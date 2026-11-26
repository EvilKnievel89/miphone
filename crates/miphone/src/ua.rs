//! SIP user agent: one TLS connection to the server, registration, hotdesk subscription
//! and a single call at a time. Modelled on the message flows of the Mitel MiCollab client.
//!
//! The transport is reliable, so there are no retransmission timers; requests are matched
//! to responses by their Via branch.

use std::collections::HashMap;
use std::net::SocketAddr;

use anyhow::{anyhow, Context, Result};
use misip::digest::{Challenge, Session};
use misip::message::{display_name_of, escape_user, param, tag_of, uri_of, user_of_uri, Framer, Message};
use misip::random_hex;
use misip::sdp::{AudioSdp, Codec, Direction};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{sleep_until, timeout, Duration, Instant};

use crate::config::SipConfig;
use crate::media::{AudioCodec, AudioSettings, Media, MediaConfig, OPUS_FMTP};

/// Reports a line of text to the user (console or user interface).
macro_rules! say {
    ($ua:expr, $($arg:tt)*) => { $ua.say(format!($($arg)*)) };
}

/// What the user agent tells its front end.
#[derive(Debug, Clone)]
pub enum Event {
    /// A message for the user.
    Log(String),
    /// The state changed.
    State(Snapshot),
}

/// Current state, as much as a front end needs to draw itself.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub registered: bool,
    pub call: Option<CallSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallSnapshot {
    pub peer: String,
    pub incoming: bool,
    pub phase: CallPhase,
    pub muted: bool,
    /// Negotiated audio codec, once known.
    pub codec: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallPhase {
    /// Ringing here, waiting to be answered.
    Incoming,
    /// Our call is being set up or rings at the other end.
    Dialing,
    Active,
    /// Held by us.
    Held,
}

const ALLOW: &str = "INVITE, ACK, CANCEL, OPTIONS, BYE, NOTIFY, INFO, UPDATE, PRACK";

#[derive(Debug)]
pub enum Command {
    Call(String),
    Answer,
    Hangup,
    Dtmf(String),
    Mute(bool),
    Hold,
    Resume,
    Transfer(String),
    Quit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CallState {
    /// Incoming call is ringing here, or our INVITE is waiting for a final response.
    Ringing,
    /// We sent CANCEL and wait for the final response to the INVITE.
    Cancelling,
    Established,
}

struct Call {
    call_id: String,
    incoming: bool,
    state: CallState,
    /// Our From/To header value including tag.
    local: String,
    /// The peer's From/To header value (tag is added once known).
    remote: String,
    local_tag: String,
    /// Request-URI for requests inside the dialog.
    target: String,
    routes: Vec<String>,
    /// Incoming: the peer's INVITE. Outgoing: our most recent INVITE.
    invite: Message,
    media: Option<Media>,
    sdp_id: u64,
    sdp_version: u64,
    peer: String,
    ringing_reported: bool,
    /// Our last SDP, the basis for offers we make inside the dialog.
    local_sdp: Option<AudioSdp>,
    /// The peer's last SDP and the negotiated codec, to (re)configure the audio path.
    remote_sdp: Option<AudioSdp>,
    codec: Option<Codec>,
    dtmf_pt: Option<u8>,
    /// Our re-INVITE that is waiting for its final response.
    reinvite: Option<Message>,
    /// Hold as requested by the user, and as confirmed by the peer.
    held: bool,
    held_confirmed: bool,
    muted: bool,
    /// Number to transfer to once the hold is confirmed.
    transfer_to: Option<String>,
    session: Option<SessionTimer>,
}

impl Call {
    fn new(call_id: String, incoming: bool, local: String, remote: String, local_tag: String, target: String, invite: Message, peer: String) -> Call {
        let sdp_id = rand::random::<u64>() >> 1;
        Call {
            call_id,
            incoming,
            state: CallState::Ringing,
            local,
            remote,
            local_tag,
            target,
            routes: Vec::new(),
            invite,
            media: None,
            sdp_id,
            sdp_version: sdp_id,
            peer,
            ringing_reported: incoming,
            local_sdp: None,
            remote_sdp: None,
            codec: None,
            dtmf_pt: None,
            reinvite: None,
            held: false,
            held_confirmed: false,
            muted: false,
            transfer_to: None,
            session: None,
        }
    }
}

/// Session timer (RFC 4028): the call must be refreshed within `interval` seconds,
/// otherwise both sides consider it dead.
struct SessionTimer {
    interval: u32,
    we_refresh: bool,
    /// When we have to act: refresh, or give up if the peer did not refresh.
    due: Instant,
}

impl SessionTimer {
    fn new(interval: u32, we_refresh: bool) -> Self {
        let secs = if we_refresh { interval / 2 } else { interval - (interval / 3).min(32) };
        SessionTimer { interval, we_refresh, due: Instant::now() + Duration::from_secs(secs.max(1) as u64) }
    }
}

struct Pending {
    msg: Message,
    retried: bool,
}

struct Subscription {
    call_id: String,
    tag: String,
    to_tag: Option<String>,
}

impl Subscription {
    fn new() -> Self {
        Subscription { call_id: random_hex(16), tag: random_hex(10), to_tag: None }
    }
}

struct Ua<'a, S> {
    cfg: &'a SipConfig,
    password: &'a str,
    verbose: bool,
    wr: WriteHalf<S>,
    local: SocketAddr,
    /// Sound devices for calls; `None` opens none (tests).
    audio: Option<AudioSettings>,
    events: mpsc::UnboundedSender<Event>,
    published: Snapshot,
    cseq: u32,
    /// Digest session and the header it goes into (Authorization or Proxy-Authorization).
    auth: Option<(Session, &'static str)>,
    pending: HashMap<String, Pending>,
    reg_call_id: String,
    reg_tag: String,
    registered: bool,
    unregistering: bool,
    unregistered: bool,
    next_register: Instant,
    sub: Subscription,
    hotdesk_confirmed: bool,
    /// The server refused the hotdesk subscription; do not ask again on this connection.
    hotdesk_refused: bool,
    /// Set when the server withdrew the hotdesk login; the softphone then signs off.
    evicted: bool,
    call: Option<Call>,
}

/// Runs one connection until the user quits (`Ok`) or the connection fails (`Err`).
pub async fn run(
    cfg: &SipConfig,
    password: &str,
    verbose: bool,
    audio: Option<AudioSettings>,
    events: &mpsc::UnboundedSender<Event>,
    cmds: &mut mpsc::Receiver<Command>,
) -> Result<()> {
    let (host, port) = cfg.connect_to();
    // A PBX address that is only reachable inside the company network would otherwise keep
    // the attempt (and a pending change to the other account) waiting for the system's timeout.
    let tcp = tokio::time::timeout(std::time::Duration::from_secs(8), TcpStream::connect((host, port)))
        .await
        .map_err(|_| anyhow::anyhow!("Zeitueberschreitung"))
        .and_then(|r| r.map_err(Into::into))
        .with_context(|| format!("Verbindung zu {host}:{port}"))?;
    tcp.set_nodelay(true).ok();
    let local = tcp.local_addr()?;
    let mut builder = native_tls::TlsConnector::builder();
    if cfg.tls_insecure {
        builder.danger_accept_invalid_certs(true);
        builder.danger_accept_invalid_hostnames(true);
    }
    let mut pinned = 0;
    for pem in cfg.ca_certificates() {
        match native_tls::Certificate::from_pem(pem.as_bytes()) {
            Ok(cert) => {
                builder.add_root_certificate(cert);
                pinned += 1;
            }
            Err(e) => eprintln!("Zertifikat aus dem Profil nicht lesbar: {e}"),
        }
    }
    if pinned > 0 {
        // The profile names the authority that issued this server's certificate. Such servers
        // are addressed by IP address, which their certificate does not contain, so the name
        // is not compared; the certificate still has to be issued by a trusted authority.
        builder.danger_accept_invalid_hostnames(true);
    }
    let connector = tokio_native_tls::TlsConnector::from(builder.build()?);
    let tls = connector.connect(host, tcp).await.with_context(|| format!("TLS-Handshake mit {host}:{port}"))?;
    run_stream(tls, local, cfg, password, verbose, audio, events, cmds).await
}

/// Runs the user agent on an established, reliable byte stream. `local` is the address put into Via and Contact.
pub async fn run_stream<S>(
    stream: S,
    local: SocketAddr,
    cfg: &SipConfig,
    password: &str,
    verbose: bool,
    audio: Option<AudioSettings>,
    events: &mpsc::UnboundedSender<Event>,
    cmds: &mut mpsc::Receiver<Command>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (mut rd, wr) = tokio::io::split(stream);

    let (net_tx, mut net_rx) = mpsc::channel::<Message>(64);
    tokio::spawn(async move {
        let mut framer = Framer::new();
        let mut buf = [0u8; 8192];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    framer.push(&buf[..n]);
                    while let Some(m) = framer.next_message() {
                        match m {
                            Ok(m) => {
                                if net_tx.send(m).await.is_err() {
                                    return;
                                }
                            }
                            Err(e) => {
                                eprintln!("{e}");
                                return;
                            }
                        }
                    }
                }
            }
        }
    });

    let mut ua = Ua {
        cfg,
        password,
        verbose,
        wr,
        local,
        audio,
        events: events.clone(),
        published: Snapshot::default(),
        cseq: rand::random::<u32>() >> 2,
        auth: None,
        pending: HashMap::new(),
        reg_call_id: random_hex(16),
        reg_tag: random_hex(10),
        registered: false,
        unregistering: false,
        unregistered: false,
        next_register: Instant::now(),
        sub: Subscription::new(),
        hotdesk_confirmed: false,
        hotdesk_refused: false,
        evicted: false,
        call: None,
    };
    say!(ua, "Verbunden mit {}:{} (lokal {})", cfg.server, cfg.port(), local);

    loop {
        tokio::select! {
            m = net_rx.recv() => match m {
                Some(m) => {
                    ua.on_message(m).await?;
                    if ua.evicted {
                        say!(ua, "Das Softphone wird abgemeldet.");
                        ua.shutdown(&mut net_rx).await;
                        ua.registered = false;
                        ua.publish();
                        return Ok(());
                    }
                }
                None => return Err(anyhow!("Server hat die Verbindung geschlossen")),
            },
            c = cmds.recv() => match c {
                Some(Command::Quit) | None => {
                    ua.shutdown(&mut net_rx).await;
                    ua.registered = false;
                    ua.publish();
                    return Ok(());
                }
                Some(c) => ua.on_command(c).await?,
            },
            _ = sleep_until(ua.next_register) => ua.send_register(ua.cfg.expires).await?,
            _ = sleep_until(ua.session_due()) => ua.on_session_timer().await?,
        }
        ua.publish();
    }
}

impl<S: AsyncRead + AsyncWrite> Ua<'_, S> {
    fn say(&self, text: String) {
        let _ = self.events.send(Event::Log(text));
    }

    fn snapshot(&self) -> Snapshot {
        let call = self.call.as_ref().map(|c| CallSnapshot {
            peer: c.peer.clone(),
            incoming: c.incoming,
            phase: match (c.state, c.incoming) {
                (CallState::Established, _) if c.held => CallPhase::Held,
                (CallState::Established, _) => CallPhase::Active,
                (_, true) => CallPhase::Incoming,
                (_, false) => CallPhase::Dialing,
            },
            muted: c.muted,
            codec: c.codec.as_ref().filter(|_| c.state == CallState::Established).map(|k| k.name.clone()),
        });
        Snapshot { registered: self.registered, call }
    }

    /// Tells the front end about a changed state.
    fn publish(&mut self) {
        let now = self.snapshot();
        if now != self.published {
            self.published = now.clone();
            let _ = self.events.send(Event::State(now));
        }
    }

    // ----- identities -------------------------------------------------------------------

    fn user_escaped(&self) -> String {
        escape_user(&self.cfg.user)
    }

    fn registrar(&self) -> String {
        format!("sips:{}:{};transport=tls", self.cfg.server, self.cfg.port())
    }

    /// Address of record as a name-addr.
    fn aor(&self) -> String {
        format!("\"{}\" <sips:{}@{}:{};transport=tls>", self.cfg.user, self.user_escaped(), self.cfg.server, self.cfg.port())
    }

    fn contact_uri(&self) -> String {
        format!("sips:{}@{};transport=tls", self.user_escaped(), self.local)
    }

    fn contact(&self) -> String {
        format!("\"{}\" <{}>", self.cfg.user, self.contact_uri())
    }

    fn via(&self) -> String {
        format!("SIP/2.0/TLS {};branch=z9hG4bK{}", self.local, random_hex(17))
    }

    /// Names of the audio codecs we accept, in our order of preference.
    fn supported_codecs(&self) -> Vec<&str> {
        self.cfg.codecs.iter().map(String::as_str).collect()
    }

    /// The codecs we put into an offer, with the payload types the Mitel client uses.
    fn offer_codecs(&self) -> Vec<Codec> {
        self.cfg
            .codecs
            .iter()
            .filter_map(|name| match AudioCodec::from_name(name)? {
                AudioCodec::Opus => Some(Codec::opus(124, OPUS_FMTP)),
                AudioCodec::G711(misip::g711::Law::A) => Some(Codec::new(8, "PCMA", 8000)),
                AudioCodec::G711(misip::g711::Law::Mu) => Some(Codec::new(0, "PCMU", 8000)),
            })
            .collect()
    }

    // ----- sending ----------------------------------------------------------------------

    async fn send(&mut self, m: &Message) -> Result<()> {
        if self.verbose {
            dump(">>>", m);
        }
        self.wr.write_all(&m.to_bytes()).await?;
        self.wr.flush().await?;
        Ok(())
    }

    fn base_request(&mut self, method: &str, uri: &str, from: &str, to: &str, call_id: &str) -> Message {
        self.cseq += 1;
        let mut m = Message::request(method, uri);
        m.add("Via", self.via());
        m.add("Max-Forwards", "70");
        m.add("From", from);
        m.add("To", to);
        m.add("Call-ID", call_id);
        m.add("CSeq", format!("{} {}", self.cseq, method));
        m
    }

    /// Adds credentials and the identifying headers every request carries.
    fn decorate(&mut self, m: &mut Message) {
        m.remove("Authorization");
        m.remove("Proxy-Authorization");
        if let Some((session, header)) = &mut self.auth {
            let value = session.authorize(m.method().unwrap_or(""), m.uri().unwrap_or(""), &m.body);
            m.add(header, value);
        }
        m.set("User-Agent", self.cfg.user_agent());
        if let Some(id) = self.cfg.aastra_id() {
            m.set("X-Aastra-Id", id);
        }
    }

    /// Sends a request and remembers it, so that it can be repeated with credentials after a 401/407.
    async fn send_request(&mut self, mut m: Message) -> Result<()> {
        self.decorate(&mut m);
        if let Some(branch) = m.branch() {
            self.pending.insert(branch.to_string(), Pending { msg: m.clone(), retried: false });
        }
        self.send(&m).await
    }

    fn reply(&self, req: &Message, code: u16, reason: &str, to_tag: Option<&str>) -> Message {
        let mut rsp = Message::response_to(req, code, reason, to_tag);
        rsp.add("Server", self.cfg.user_agent());
        rsp
    }

    fn dialog_request(&mut self, call: &Call, method: &str) -> Message {
        let mut m = self.base_request(method, &call.target, &call.local, &call.remote, &call.call_id);
        for r in &call.routes {
            m.add("Route", r.clone());
        }
        m
    }

    /// ACK for a non-2xx final response: same branch as the INVITE (RFC 3261, 17.1.1.3).
    async fn ack_failure(&mut self, invite: &Message, rsp: &Message) -> Result<()> {
        let mut ack = Message::request("ACK", invite.uri().unwrap_or(""));
        ack.add("Via", invite.header("Via").unwrap_or(""));
        ack.add("Max-Forwards", "70");
        ack.add("From", invite.header("From").unwrap_or(""));
        ack.add("To", rsp.header("To").unwrap_or(""));
        ack.add("Call-ID", invite.call_id());
        ack.add("CSeq", format!("{} ACK", invite.cseq().map(|c| c.0).unwrap_or(0)));
        ack.add("User-Agent", self.cfg.user_agent());
        self.send(&ack).await
    }

    // ----- registration -----------------------------------------------------------------

    async fn send_register(&mut self, expires: u32) -> Result<()> {
        let (uri, aor, call_id) = (self.registrar(), self.aor(), self.reg_call_id.clone());
        let from = format!("{aor};tag={}", self.reg_tag);
        let mut m = self.base_request("REGISTER", &uri, &from, &aor, &call_id);
        m.add("Allow", ALLOW);
        m.add("Contact", format!("{};expires={}", self.contact(), expires));
        // Fallback in case no answer arrives; a 200 replaces this with the real refresh time.
        self.next_register = Instant::now() + Duration::from_secs(30);
        self.send_request(m).await
    }

    /// Subscribes to (or with `expires` 0 unsubscribes from) the hotdesk state of the account.
    async fn send_subscribe(&mut self, expires: u32) -> Result<()> {
        let (uri, aor, call_id) = (self.registrar(), self.aor(), self.sub.call_id.clone());
        let from = format!("{aor};tag={}", self.sub.tag);
        let to = match &self.sub.to_tag {
            Some(t) => format!("{aor};tag={t}"),
            None => aor,
        };
        let mut m = self.base_request("SUBSCRIBE", &uri, &from, &to, &call_id);
        m.add("Accept", "application/mihotdesk");
        m.add("Contact", self.contact());
        m.add("Event", "mihotdesk");
        m.add("Expires", expires.to_string());
        self.send_request(m).await
    }

    async fn on_register_response(&mut self, rsp: &Message, code: u16) -> Result<()> {
        if self.unregistering {
            self.unregistered = true;
            return Ok(());
        }
        if !(200..300).contains(&code) {
            self.registered = false;
            self.next_register = Instant::now() + Duration::from_secs(60);
            let hint = if code == 401 || code == 403 { " (Benutzername/Passwort pruefen)" } else { "" };
            say!(self, "Registrierung fehlgeschlagen: {code} {}{hint}. Neuer Versuch in 60 s.", reason(rsp));
            return Ok(());
        }
        let ours = self.contact_uri();
        let expires = rsp
            .headers_all("Contact")
            .find(|c| uri_of(c).eq_ignore_ascii_case(&ours))
            .and_then(|c| param(c, "expires"))
            .or(rsp.header("Expires"))
            .and_then(|e| e.parse::<u32>().ok())
            .unwrap_or(self.cfg.expires);
        // Refresh at half the granted lifetime, like the original client.
        self.next_register = Instant::now() + Duration::from_secs((expires / 2).max(15) as u64);
        if !self.registered {
            self.registered = true;
            say!(self, "Registriert als {} (Gueltigkeit {expires} s)", self.cfg.user);
        }
        // Only hotdesk accounts have a hotdesk state to watch; the server marks them in its
        // answer. For other accounts the subscription would be refused every time.
        let hotdesk = rsp.header("P-Login").is_some_and(|v| v.to_ascii_lowercase().contains("mihotdesk"));
        if self.cfg.hotdesk_subscribe && hotdesk && !self.hotdesk_refused {
            self.send_subscribe(1800).await?;
        }
        Ok(())
    }

    // ----- incoming messages ------------------------------------------------------------

    async fn on_message(&mut self, m: Message) -> Result<()> {
        if self.verbose {
            dump("<<<", &m);
        }
        if m.is_request() {
            self.on_request(m).await
        } else {
            self.on_response(m).await
        }
    }

    async fn on_response(&mut self, rsp: Message) -> Result<()> {
        let code = rsp.status().unwrap_or(0);
        let Some((_, method)) = rsp.cseq() else { return Ok(()) };
        let method = method.to_string();
        let branch = rsp.branch().unwrap_or("").to_string();

        if code == 401 || code == 407 {
            let challenge = rsp
                .header("WWW-Authenticate")
                .map(|v| (v, "Authorization"))
                .or(rsp.header("Proxy-Authenticate").map(|v| (v, "Proxy-Authorization")))
                .and_then(|(v, h)| Challenge::parse(v).map(|c| (c, h)));
            if let (Some(p), Some((challenge, header))) = (self.pending.remove(&branch), challenge) {
                // Retry once; a stale nonce after a successful login may be retried again.
                if !p.retried || challenge.stale {
                    if method == "INVITE" {
                        self.ack_failure(&p.msg, &rsp).await?;
                    }
                    let user = self.cfg.auth_user.as_deref().unwrap_or(&self.cfg.user);
                    self.auth = Some((Session::new(user, self.password, challenge), header));
                    let mut m = p.msg;
                    self.cseq += 1;
                    m.set("CSeq", format!("{} {}", self.cseq, method));
                    m.set("Via", self.via());
                    self.decorate(&mut m);
                    if let Some(b) = m.branch() {
                        self.pending.insert(b.to_string(), Pending { msg: m.clone(), retried: true });
                    }
                    if method == "INVITE" {
                        if let Some(call) = self.call.as_mut().filter(|c| c.call_id == m.call_id()) {
                            if call.reinvite.is_some() {
                                call.reinvite = Some(m.clone());
                            } else {
                                call.invite = m.clone();
                            }
                        }
                    }
                    return self.send(&m).await;
                }
            }
        }
        if code >= 200 {
            self.pending.remove(&branch);
        }

        match method.as_str() {
            "REGISTER" if code >= 200 => self.on_register_response(&rsp, code).await?,
            "SUBSCRIBE" if (200..300).contains(&code) => {
                self.sub.to_tag = rsp.header("To").and_then(tag_of).map(str::to_string);
            }
            "SUBSCRIBE" if code >= 300 => {
                if self.verbose {
                    eprintln!("Hotdesk-Subscription abgelehnt: {code} {}", reason(&rsp));
                }
                self.sub = Subscription::new();
                self.hotdesk_refused = true;
            }
            "INVITE" => self.on_invite_response(&rsp, code).await?,
            "REFER" if (200..300).contains(&code) => say!(self, "Vermittlung vom Server angenommen ..."),
            "REFER" if code >= 300 => {
                say!(self, "Vermittlung abgelehnt: {code} {}. Mit 'resume' zurueck zum Gespraech.", reason(&rsp));
            }
            _ => {}
        }
        Ok(())
    }

    async fn on_invite_response(&mut self, rsp: &Message, code: u16) -> Result<()> {
        let Some(mut call) = self.call.take() else { return Ok(()) };
        let cseq = rsp.cseq().map(|c| c.0);
        if call.call_id == rsp.call_id() && cseq.is_some() && call.reinvite.as_ref().and_then(|m| m.cseq()).map(|c| c.0) == cseq {
            return self.on_reinvite_response(call, rsp, code).await;
        }
        if call.incoming || call.call_id != rsp.call_id() || code <= 100 || call.state == CallState::Established {
            self.call = Some(call);
            return Ok(());
        }
        if code >= 300 {
            self.ack_failure(&call.invite, rsp).await?;
            if call.state == CallState::Cancelling || code == 487 {
                say!(self, "Anruf abgebrochen.");
            } else {
                say!(self, "Anruf fehlgeschlagen: {code} {}", reason(rsp));
            }
            return Ok(()); // call (and its media) is dropped
        }

        // 1xx with tag or 2xx: learn the dialog.
        if let Some(to) = rsp.header("To") {
            call.remote = to.to_string();
        }
        if let Some(c) = rsp.header("Contact") {
            call.target = uri_of(c).to_string();
        }
        let mut routes: Vec<String> = rsp.headers_all("Record-Route").map(str::to_string).collect();
        routes.reverse();
        call.routes = routes;
        if let Some(name) = rsp.header("P-Asserted-Identity").and_then(display_name_of) {
            call.peer = format!("{name} ({})", call.peer.split(" (").last().unwrap_or(&call.peer).trim_end_matches(')'));
        }
        let invite_cseq = call.invite.cseq().map(|c| c.0).unwrap_or(0);

        if code < 200 {
            if rsp.has_token("Require", "100rel") {
                if let Some(rseq) = rsp.header("RSeq") {
                    let mut prack = self.dialog_request(&call, "PRACK");
                    prack.add("RAck", format!("{rseq} {invite_cseq} INVITE"));
                    self.send_request(prack).await?;
                }
            }
            if let Some(sdp) = sdp_of(rsp) {
                apply_remote_answer(&mut call, sdp);
            }
            if !call.ringing_reported && code == 180 {
                call.ringing_reported = true;
                say!(self, "Es klingelt bei {}.", call.peer);
            }
            self.call = Some(call);
            return Ok(());
        }

        self.send_ack(&call, invite_cseq).await?;
        if call.state == CallState::Cancelling {
            // The answer crossed our CANCEL: the call exists, so end it properly.
            let bye = self.dialog_request(&call, "BYE");
            self.send_request(bye).await?;
            say!(self, "Anruf abgebrochen.");
            return Ok(());
        }
        call.state = CallState::Established;
        call.session = session_from_response(rsp);
        say!(self, "Verbunden mit {}.", call.peer);
        // The answer may already have arrived in a provisional response; then the 200 has no SDP.
        if let Some(sdp) = sdp_of(rsp) {
            apply_remote_answer(&mut call, sdp);
        }
        self.call = Some(call);
        Ok(())
    }

    /// ACK for a 2xx: a new transaction, but with the INVITE's CSeq number.
    async fn send_ack(&mut self, call: &Call, cseq: u32) -> Result<()> {
        let mut ack = Message::request("ACK", &call.target);
        ack.add("Via", self.via());
        ack.add("Max-Forwards", "70");
        ack.add("From", call.local.clone());
        ack.add("To", call.remote.clone());
        ack.add("Call-ID", call.call_id.clone());
        ack.add("CSeq", format!("{cseq} ACK"));
        for r in &call.routes {
            ack.add("Route", r.clone());
        }
        self.decorate(&mut ack);
        self.send(&ack).await
    }

    /// Final response to an offer we made inside the dialog (hold, resume, refresh).
    async fn on_reinvite_response(&mut self, mut call: Call, rsp: &Message, code: u16) -> Result<()> {
        if code < 200 {
            self.call = Some(call);
            return Ok(());
        }
        let Some(req) = call.reinvite.take() else {
            self.call = Some(call);
            return Ok(());
        };
        if code >= 300 {
            self.ack_failure(&req, rsp).await?;
            if code == 481 || code == 408 {
                say!(self, "Das Gespraech mit {} besteht nicht mehr.", call.peer);
                return Ok(());
            }
            if call.held != call.held_confirmed {
                say!(self, "{} abgelehnt: {code} {}", if call.held { "Halten" } else { "Fortsetzen" }, reason(rsp));
                call.held = call.held_confirmed;
            }
            call.transfer_to = None;
            refresh_media(&call);
            self.call = Some(call);
            return Ok(());
        }
        self.send_ack(&call, req.cseq().map(|c| c.0).unwrap_or(0)).await?;
        if let Some(t) = session_from_response(rsp) {
            call.session = Some(t);
        }
        if let Some(sdp) = sdp_of(rsp) {
            apply_remote_answer(&mut call, sdp);
        }
        if call.held != call.held_confirmed {
            call.held_confirmed = call.held;
            say!(self, "{}", if call.held { "Gespraech wird gehalten." } else { "Gespraech fortgesetzt." });
        }
        if call.held {
            if let Some(number) = call.transfer_to.take() {
                self.send_refer(&call, &number).await?;
            }
        }
        self.call = Some(call);
        Ok(())
    }

    /// Sends a new offer inside the dialog: hold, resume or a session refresh.
    async fn send_reinvite(&mut self, call: &mut Call) -> Result<()> {
        let Some(mut sdp) = call.local_sdp.clone() else { return Ok(()) };
        call.sdp_version += 1;
        sdp.session_version = call.sdp_version;
        sdp.direction = if call.held { Direction::SendOnly } else { Direction::SendRecv };
        let mut m = self.dialog_request(call, "INVITE");
        m.add("Allow", ALLOW);
        m.add("Contact", self.contact());
        m.add("Supported", "timer");
        m.add("Session-Expires", format!("{};refresher=uac", call.session.as_ref().map(|s| s.interval).unwrap_or(1800)));
        m.add("Min-SE", "90");
        m.set_body("application/sdp", sdp.build());
        call.local_sdp = Some(sdp);
        self.decorate(&mut m);
        if let Some(b) = m.branch() {
            self.pending.insert(b.to_string(), Pending { msg: m.clone(), retried: false });
        }
        self.send(&m).await?;
        call.reinvite = Some(m);
        Ok(())
    }

    /// Blind transfer: asks the peer's side to call `number` instead of us.
    async fn send_refer(&mut self, call: &Call, number: &str) -> Result<()> {
        let mut refer = self.dialog_request(call, "REFER");
        refer.add("Refer-To", format!("<sips:{}@{}:{}>", number, self.cfg.server, self.cfg.port()));
        refer.add("Referred-By", format!("<{}>", uri_of(&self.aor())));
        refer.add("Contact", self.contact());
        self.send_request(refer).await
    }

    fn session_due(&self) -> Instant {
        self.call
            .as_ref()
            .and_then(|c| c.session.as_ref())
            .map(|s| s.due)
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(86400))
    }

    async fn on_session_timer(&mut self) -> Result<()> {
        let Some(mut call) = self.call.take() else { return Ok(()) };
        let Some((interval, we_refresh)) = call.session.as_ref().map(|s| (s.interval, s.we_refresh)) else {
            self.call = Some(call);
            return Ok(());
        };
        if !we_refresh {
            say!(self, "Die Gegenstelle hat das Gespraech nicht aufgefrischt; es wird beendet.");
            let bye = self.dialog_request(&call, "BYE");
            return self.send_request(bye).await;
        }
        if call.reinvite.is_some() || call.state != CallState::Established {
            // Something else is being negotiated; try again shortly.
            call.session = Some(SessionTimer { interval, we_refresh, due: Instant::now() + Duration::from_secs(5) });
        } else {
            // Re-armed here in case the answer never comes; a 200 sets the real next time.
            call.session = Some(SessionTimer::new(interval, true));
            self.send_reinvite(&mut call).await?;
        }
        self.call = Some(call);
        Ok(())
    }

    async fn on_request(&mut self, req: Message) -> Result<()> {
        let method = req.method().unwrap_or("").to_string();
        let in_call = self.call.as_ref().is_some_and(|c| c.call_id == req.call_id());
        match method.as_str() {
            "INVITE" => self.on_invite(req, in_call).await,
            "UPDATE" if in_call && !req.body.is_empty() => self.on_reinvite(req).await,
            "ACK" => {
                // Answer to an offer we made in a 200 (INVITE without SDP).
                if let (true, Some(call), Some(sdp)) = (in_call, self.call.as_mut(), sdp_of(&req)) {
                    apply_remote_answer(call, sdp);
                }
                Ok(())
            }
            "BYE" => {
                let rsp = self.reply(&req, 200, "OK", None);
                self.send(&rsp).await?;
                if in_call {
                    if let Some(call) = self.call.take() {
                        say!(self, "{} hat aufgelegt.", call.peer);
                    }
                }
                Ok(())
            }
            "CANCEL" => {
                let tag = self.call.as_ref().filter(|_| in_call).map(|c| c.local_tag.clone());
                let rsp = self.reply(&req, 200, "OK", tag.as_deref());
                self.send(&rsp).await?;
                if in_call && self.call.as_ref().is_some_and(|c| c.incoming && c.state == CallState::Ringing) {
                    let call = self.call.take().unwrap();
                    let rsp = self.reply(&call.invite, 487, "Request Terminated", Some(&call.local_tag));
                    self.send(&rsp).await?;
                    say!(self, "Anruf von {} verpasst.", call.peer);
                }
                Ok(())
            }
            "NOTIFY" => {
                let rsp = self.reply(&req, 200, "OK", None);
                self.send(&rsp).await?;
                let event = req.header("Event").unwrap_or("").trim().to_ascii_lowercase();
                if event == "mihotdesk" {
                    self.on_hotdesk_notify(&req);
                } else if event.starts_with("refer") && in_call {
                    return self.on_transfer_progress(&req).await;
                }
                Ok(())
            }
            "OPTIONS" => {
                let mut rsp = self.reply(&req, 200, "OK", Some(&random_hex(10)));
                rsp.add("Allow", ALLOW);
                self.send(&rsp).await
            }
            "UPDATE" if in_call => {
                // Session refresh without a new offer.
                let mut rsp = self.reply(&req, 200, "OK", None);
                rsp.add("Contact", self.contact());
                let timer = accept_session_timer(&req, &mut rsp);
                if let (Some(call), Some(t)) = (self.call.as_mut(), timer) {
                    call.session = Some(t);
                }
                self.send(&rsp).await
            }
            "PRACK" | "INFO" if in_call => {
                let rsp = self.reply(&req, 200, "OK", None);
                self.send(&rsp).await
            }
            _ => {
                let mut rsp = self.reply(&req, 405, "Method Not Allowed", Some(&random_hex(10)));
                rsp.add("Allow", ALLOW);
                self.send(&rsp).await
            }
        }
    }

    /// Hotdesk state of the account, sent by the server after each (re)subscription and when
    /// the state changes. The Mitel client treats the causes -2, -1, 0 and 105 as "all fine",
    /// 103 as an error without consequences, and every other cause (the account was taken
    /// over or logged out) as the order to switch the softphone off.
    fn on_hotdesk_notify(&mut self, req: &Message) {
        let body = req.body_str();
        let attr = |name: &str| {
            let start = body.find(&format!("{name}=\""))? + name.len() + 2;
            let len = body[start..].find('"')?;
            Some(&body[start..start + len])
        };
        let terminated = req.header("Subscription-State").is_some_and(|s| s.trim_start().starts_with("terminated"));
        if terminated {
            // A later refresh of the registration subscribes again.
            self.sub = Subscription::new();
        }
        if self.unregistering {
            return; // the server's farewell to our own sign-off
        }
        let cause = attr("cause").unwrap_or("");
        let text = attr("display").map(|d| format!(" \"{d}\"")).unwrap_or_default();
        match cause {
            "0" | "-1" | "-2" | "105" => {
                if !self.hotdesk_confirmed {
                    self.hotdesk_confirmed = true;
                    say!(self, "Hotdesk-Anmeldung vom Server bestaetigt.");
                }
            }
            "103" => say!(self, "Hotdesk-Fehlermeldung vom Server (cause=103{text}); das Softphone bleibt angemeldet."),
            "" => {
                if self.verbose {
                    eprintln!("Hotdesk-Meldung ohne cause-Angabe ignoriert.");
                }
            }
            other => {
                say!(self, "Der Server hat die Hotdesk-Anmeldung dieses Softphones beendet (cause={other}{text}).");
                self.evicted = true;
            }
        }
    }
    async fn on_invite(&mut self, req: Message, in_call: bool) -> Result<()> {
        let has_to_tag = req.header("To").and_then(tag_of).is_some();
        if in_call && has_to_tag {
            return self.on_reinvite(req).await;
        }
        if has_to_tag {
            let rsp = self.reply(&req, 481, "Call/Transaction Does Not Exist", None);
            return self.send(&rsp).await;
        }
        if self.call.is_some() {
            let rsp = self.reply(&req, 486, "Busy Here", Some(&random_hex(10)));
            return self.send(&rsp).await;
        }

        let local_tag = random_hex(10);
        let from = req.header("From").unwrap_or("").to_string();
        let identity = req.header("P-Asserted-Identity").unwrap_or(&from);
        let number = user_of_uri(uri_of(identity)).unwrap_or("unbekannt");
        let peer = match display_name_of(identity) {
            Some(name) => format!("{name} ({number})"),
            None => number.to_string(),
        };
        let trying = self.reply(&req, 100, "Trying", None);
        self.send(&trying).await?;
        let mut ringing = self.reply(&req, 180, "Ringing", Some(&local_tag));
        ringing.add("Contact", self.contact());
        if req.has_token("Supported", "100rel") || req.has_token("Require", "100rel") {
            ringing.add("Require", "100rel");
            ringing.add("RSeq", "1");
        }
        self.send(&ringing).await?;

        let mut call = Call::new(
            req.call_id().to_string(),
            true,
            format!("{};tag={local_tag}", req.header("To").unwrap_or("")),
            from,
            local_tag,
            req.header("Contact").map(uri_of).unwrap_or("").to_string(),
            req.clone(),
            peer.clone(),
        );
        call.routes = req.headers_all("Record-Route").map(str::to_string).collect();
        self.call = Some(call);
        say!(self, "\x07Eingehender Anruf von {peer}. Mit 'answer' annehmen, mit 'hangup' abweisen.");
        Ok(())
    }

    /// Progress of a transfer, reported by the peer as the status line of the new call.
    async fn on_transfer_progress(&mut self, req: &Message) -> Result<()> {
        let line = req.body_str().lines().next().unwrap_or("").trim().to_string();
        let code: u16 = line.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
        if (200..300).contains(&code) {
            if let Some(call) = self.call.take() {
                let bye = self.dialog_request(&call, "BYE");
                self.send_request(bye).await?;
                say!(self, "Vermittelt.");
            }
        } else if code >= 300 {
            say!(self, "Vermittlung fehlgeschlagen ({line}). Mit 'resume' zurueck zum Gespraech.");
        }
        Ok(())
    }

    /// New offer inside the dialog (re-INVITE or UPDATE): codec change, hold, resume, refresh.
    async fn on_reinvite(&mut self, req: Message) -> Result<()> {
        let Some(mut call) = self.call.take() else { return Ok(()) };
        let ip = self.local.ip().to_string();
        let port = call.media.as_ref().map(|m| m.port());
        let rsp = match (port, AudioSdp::parse(req.body_str())) {
            // Our own offer is still open; the peer has to try again (RFC 3261, 14.2).
            _ if call.reinvite.is_some() => self.reply(&req, 491, "Request Pending", None),
            // INVITE without SDP: the peer asks us for a fresh offer and answers it in its ACK.
            // The PBX does this when it retrieves a call it had put on hold.
            (Some(port), _) if req.body.is_empty() => {
                call.sdp_version += 1;
                let codecs = self.offer_codecs();
                let mut offer = AudioSdp::offer(&ip, port, call.sdp_id, &codecs);
                offer.session_version = call.sdp_version;
                if call.held {
                    offer.direction = Direction::SendOnly;
                }
                let mut rsp = self.reply(&req, 200, "OK", None);
                rsp.add("Contact", self.contact());
                rsp.add("Allow", ALLOW);
                if let Some(t) = accept_session_timer(&req, &mut rsp) {
                    call.session = Some(t);
                }
                rsp.set_body("application/sdp", offer.build());
                call.local_sdp = Some(offer);
                rsp
            }
            (Some(port), Ok(offer)) => {
                call.sdp_version += 1;
                match AudioSdp::answer(&offer, &ip, port, call.sdp_id, call.sdp_version, &self.supported_codecs()) {
                    Some(mut answer) => {
                        if call.held {
                            // While we hold the call we do not accept audio from the peer.
                            answer.direction = if answer.direction.can_send() { Direction::SendOnly } else { Direction::Inactive };
                        }
                        let mut rsp = self.reply(&req, 200, "OK", None);
                        rsp.add("Contact", self.contact());
                        rsp.add("Allow", ALLOW);
                        if let Some(t) = accept_session_timer(&req, &mut rsp) {
                            call.session = Some(t);
                        }
                        rsp.set_body("application/sdp", answer.build());
                        update_media(&mut call, offer, &answer);
                        rsp
                    }
                    None => self.reply(&req, 488, "Not Acceptable Here", None),
                }
            }
            // Not answered yet or no usable SDP: we cannot renegotiate now.
            _ => self.reply(&req, 491, "Request Pending", None),
        };
        self.call = Some(call);
        self.send(&rsp).await
    }

    // ----- user commands ----------------------------------------------------------------

    async fn on_command(&mut self, cmd: Command) -> Result<()> {
        match cmd {
            Command::Call(number) => self.start_call(&number).await,
            Command::Answer => self.answer().await,
            Command::Hangup => self.hangup().await,
            Command::Hold => self.set_hold(true, None).await,
            Command::Resume => self.set_hold(false, None).await,
            Command::Transfer(number) => {
                let number = dialable(&number);
                if number.is_empty() {
                    say!(self, "Keine gueltige Nummer.");
                    return Ok(());
                }
                self.set_hold(true, Some(number)).await
            }
            Command::Dtmf(digits) => {
                match self.call.as_ref().filter(|c| c.state == CallState::Established).and_then(|c| c.media.as_ref()) {
                    Some(media) if media.send_dtmf(&digits) => {}
                    Some(_) => say!(self, "Die Gegenstelle akzeptiert keine Tonwahl per RTP."),
                    None => say!(self, "Kein aktives Gespraech."),
                }
                Ok(())
            }
            Command::Mute(on) => {
                match self.call.as_mut().and_then(|c| c.media.as_ref().map(|m| (m, &mut c.muted))) {
                    Some((media, muted)) => {
                        media.set_muted(on);
                        *muted = on;
                        say!(self, "Mikrofon {}.", if on { "stumm" } else { "aktiv" });
                    }
                    None => say!(self, "Kein aktives Gespraech."),
                }
                Ok(())
            }
            Command::Quit => Ok(()),
        }
    }

    /// Holds or resumes the call. With `transfer_to` the call is transferred as soon as it is
    /// on hold, the way the Mitel client does a blind transfer.
    async fn set_hold(&mut self, hold: bool, transfer_to: Option<String>) -> Result<()> {
        let Some(mut call) = self.call.take().filter(|c| c.state == CallState::Established) else {
            say!(self, "Kein aktives Gespraech.");
            return Ok(());
        };
        if call.reinvite.is_some() {
            say!(self, "Bitte kurz warten, eine Aenderung am Gespraech laeuft noch.");
        } else if let (true, true, Some(number)) = (call.held, call.held_confirmed, &transfer_to) {
            say!(self, "Vermittle an {number} ...");
            self.send_refer(&call, number).await?;
        } else if call.held == hold && transfer_to.is_none() {
            say!(self, "{}", if hold { "Das Gespraech wird bereits gehalten." } else { "Das Gespraech wird nicht gehalten." });
        } else {
            if let Some(number) = &transfer_to {
                say!(self, "Vermittle an {number} ...");
            }
            call.held = hold;
            call.transfer_to = transfer_to;
            refresh_media(&call); // stop or restart audio right away
            self.send_reinvite(&mut call).await?;
        }
        self.call = Some(call);
        Ok(())
    }

    async fn start_call(&mut self, number: &str) -> Result<()> {
        if self.call.is_some() {
            say!(self, "Es besteht bereits ein Anruf.");
            return Ok(());
        }
        if !self.registered {
            say!(self, "Noch nicht registriert.");
            return Ok(());
        }
        let number = dialable(number);
        if number.is_empty() {
            say!(self, "Keine gueltige Nummer.");
            return Ok(());
        }
        let media = Media::start(self.audio.as_ref()).context("RTP-Socket")?;
        let uri = format!("sips:{}@{}:{}", number, self.cfg.server, self.cfg.port());
        let local_tag = random_hex(10);
        let local = format!("{};tag={local_tag}", self.aor());
        let remote = format!("<{uri}>");
        let call_id = random_hex(16);
        let mut call = Call::new(call_id.clone(), false, local.clone(), remote.clone(), local_tag, uri.clone(), Message::request("INVITE", &uri), number.clone());
        let codecs = self.offer_codecs();
        let offer = AudioSdp::offer(&self.local.ip().to_string(), media.port(), call.sdp_id, &codecs);

        let mut invite = self.base_request("INVITE", &uri, &local, &remote, &call_id);
        invite.add("Allow", ALLOW);
        invite.add("Contact", self.contact());
        invite.add("Min-SE", "90");
        invite.add("Session-Expires", "1800");
        invite.add("Supported", "100rel, timer");
        invite.set_body("application/sdp", offer.build());
        self.decorate(&mut invite);
        if let Some(b) = invite.branch() {
            self.pending.insert(b.to_string(), Pending { msg: invite.clone(), retried: false });
        }
        self.send(&invite).await?;
        say!(self, "Rufe {number} an ...");
        call.invite = invite;
        call.media = Some(media);
        call.local_sdp = Some(offer);
        self.call = Some(call);
        Ok(())
    }

    async fn answer(&mut self) -> Result<()> {
        let Some(mut call) = self.call.take().filter(|c| c.incoming && c.state == CallState::Ringing) else {
            say!(self, "Kein eingehender Anruf.");
            return Ok(());
        };
        let media = Media::start(self.audio.as_ref()).context("RTP-Socket")?;
        let port = media.port();
        call.media = Some(media);
        let ip = self.local.ip().to_string();
        let body = if call.invite.body.is_empty() {
            // INVITE without offer: we offer, the peer answers in its ACK.
            let codecs = self.offer_codecs();
            let offer = AudioSdp::offer(&ip, port, call.sdp_id, &codecs);
            let body = offer.build();
            call.local_sdp = Some(offer);
            body
        } else {
            let answer = AudioSdp::parse(call.invite.body_str())
                .ok()
                .and_then(|offer| AudioSdp::answer(&offer, &ip, port, call.sdp_id, call.sdp_version, &self.supported_codecs()).map(|a| (offer, a)));
            match answer {
                Some((offer, answer)) => {
                    update_media(&mut call, offer, &answer);
                    answer.build()
                }
                None => {
                    let rsp = self.reply(&call.invite, 488, "Not Acceptable Here", Some(&call.local_tag));
                    say!(self, "Kein gemeinsamer Codec, Anruf abgewiesen.");
                    return self.send(&rsp).await;
                }
            }
        };
        let mut rsp = self.reply(&call.invite, 200, "OK", Some(&call.local_tag));
        rsp.add("Contact", self.contact());
        rsp.add("Allow", ALLOW);
        call.session = accept_session_timer(&call.invite, &mut rsp);
        rsp.set_body("application/sdp", body);
        call.state = CallState::Established;
        say!(self, "Verbunden mit {}.", call.peer);
        self.call = Some(call);
        self.send(&rsp).await
    }

    async fn hangup(&mut self) -> Result<()> {
        let Some(mut call) = self.call.take() else {
            say!(self, "Kein Anruf.");
            return Ok(());
        };
        match (call.state, call.incoming) {
            (CallState::Established, _) => {
                let bye = self.dialog_request(&call, "BYE");
                self.send_request(bye).await?;
                say!(self, "Aufgelegt.");
            }
            (CallState::Ringing, true) => {
                let rsp = self.reply(&call.invite, 603, "Decline", Some(&call.local_tag));
                self.send(&rsp).await?;
                say!(self, "Anruf abgewiesen.");
            }
            (CallState::Ringing, false) => {
                // CANCEL shares branch, Request-URI, From, To and CSeq number with the INVITE.
                let inv = &call.invite;
                let mut cancel = Message::request("CANCEL", inv.uri().unwrap_or(""));
                cancel.add("Via", inv.header("Via").unwrap_or(""));
                cancel.add("Max-Forwards", "70");
                cancel.add("From", inv.header("From").unwrap_or(""));
                cancel.add("To", inv.header("To").unwrap_or(""));
                cancel.add("Call-ID", inv.call_id());
                cancel.add("CSeq", format!("{} CANCEL", inv.cseq().map(|c| c.0).unwrap_or(0)));
                cancel.add("User-Agent", self.cfg.user_agent());
                self.send(&cancel).await?;
                call.state = CallState::Cancelling;
                call.media = None;
                self.call = Some(call); // kept until the INVITE gets its final response
            }
            (CallState::Cancelling, _) => self.call = Some(call),
        }
        Ok(())
    }

    /// Ends a running call and removes the registration, waiting briefly for the server's answer.
    async fn shutdown(&mut self, net_rx: &mut mpsc::Receiver<Message>) {
        if self.call.is_some() {
            let _ = self.hangup().await;
        }
        if !self.registered {
            return;
        }
        self.unregistering = true;
        // Like the original: end the hotdesk subscription first, then remove the registration.
        if self.cfg.hotdesk_subscribe && self.sub.to_tag.is_some() && self.send_subscribe(0).await.is_err() {
            return;
        }
        if self.send_register(0).await.is_err() {
            return;
        }
        let wait = async {
            while !self.unregistered {
                match net_rx.recv().await {
                    Some(m) => {
                        if self.on_message(m).await.is_err() {
                            return;
                        }
                    }
                    None => return,
                }
            }
        };
        if timeout(Duration::from_secs(3), wait).await.is_ok() && self.unregistered {
            say!(self, "Abgemeldet.");
        }
    }
}

fn reason(rsp: &Message) -> &str {
    match &rsp.start {
        misip::message::StartLine::Response { reason, .. } => reason,
        _ => "",
    }
}

/// The SDP body of a message, if it has one. Other bodies and empty ones are not session descriptions.
fn sdp_of(m: &Message) -> Option<&str> {
    let is_sdp = m.header("Content-Type").is_some_and(|c| c.trim().to_ascii_lowercase().starts_with("application/sdp"));
    (is_sdp && !m.body.is_empty()).then(|| m.body_str())
}

/// Characters of a number that can be dialled.
fn dialable(number: &str) -> String {
    number.chars().filter(|c| c.is_ascii_digit() || "+*#".contains(*c)).collect()
}

/// `Session-Expires` of a message: interval in seconds and the refresher role, if named.
fn session_expires(m: &Message) -> Option<(u32, Option<String>)> {
    let v = m.header("Session-Expires").or_else(|| m.header("x"))?;
    let secs = v.split(';').next()?.trim().parse().ok()?;
    Some((secs, param(v, "refresher").map(str::to_ascii_lowercase)))
}

/// As the called side of a request: accepts the session timer it asks for (capped at 30 minutes
/// like the Mitel client), writes the headers into our 200 and returns the timer to run.
fn accept_session_timer(req: &Message, rsp: &mut Message) -> Option<SessionTimer> {
    let (secs, refresher) = session_expires(req)?;
    let interval = secs.min(1800);
    let refresher = refresher.filter(|r| r == "uac").unwrap_or_else(|| "uas".to_string());
    rsp.add("Session-Expires", format!("{interval};refresher={refresher}"));
    rsp.add("Supported", "timer");
    Some(SessionTimer::new(interval, refresher == "uas"))
}

/// As the calling side: the timer the peer's 2xx established. Without a named refresher it is us.
fn session_from_response(rsp: &Message) -> Option<SessionTimer> {
    let (secs, refresher) = session_expires(rsp)?;
    Some(SessionTimer::new(secs, refresher.as_deref() != Some("uas")))
}

/// Applies the peer's SDP answer to our offer.
fn apply_remote_answer(call: &mut Call, sdp: &str) {
    match AudioSdp::parse(sdp) {
        Ok(remote) => {
            call.codec = remote.audio_codec().cloned();
            call.dtmf_pt = remote.dtmf_pt();
            call.remote_sdp = Some(remote);
            refresh_media(call);
        }
        Err(e) => eprintln!("SDP der Gegenstelle nicht verwertbar: {e}\n{sdp}"),
    }
}

/// Applies the peer's offer and our answer to it.
fn update_media(call: &mut Call, remote: AudioSdp, local: &AudioSdp) {
    call.codec = local.audio_codec().cloned();
    call.dtmf_pt = local.dtmf_pt();
    call.remote_sdp = Some(remote);
    call.local_sdp = Some(local.clone());
    refresh_media(call);
}

/// Points the audio path at the peer according to the last negotiation and our hold state.
fn refresh_media(call: &Call) {
    let (Some(media), Some(remote), Some(codec)) = (&call.media, &call.remote_sdp, &call.codec) else { return };
    let Some(audio) = AudioCodec::from_name(&codec.name) else {
        eprintln!("Codec {} wird nicht unterstuetzt, kein Audio.", codec.name);
        return;
    };
    let addr = format!("{}:{}", remote.addr, remote.port)
        .parse::<SocketAddr>()
        .ok()
        .filter(|a| a.port() != 0 && !a.ip().is_unspecified());
    media.configure(MediaConfig {
        remote: addr,
        codec: audio,
        payload_type: codec.pt,
        dtmf_payload_type: call.dtmf_pt,
        // Directions are from the peer's point of view; a call we hold is silent both ways.
        send: !call.held && remote.direction.can_recv(),
        recv: !call.held && remote.direction.can_send(),
    });
}
/// Prints a message for `--verbose`, hiding credentials.
fn dump(prefix: &str, m: &Message) {
    let text = String::from_utf8_lossy(&m.to_bytes()).into_owned();
    eprintln!("{prefix}");
    for line in text.trim_end().lines() {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("authorization:") || lower.starts_with("proxy-authorization:") {
            eprintln!("    {} <ausgeblendet>", line.split(' ').next().unwrap_or(""));
        } else {
            eprintln!("    {line}");
        }
    }
}

#[cfg(test)]
mod tests {
    //! Drives the user agent against a scripted server over an in-memory stream.
    //! The flows mirror what the Mitel client and the MBG exchange.

    use super::*;
    use tokio::io::DuplexStream;
    use tokio::task::JoinHandle;

    const PASSWORD: &str = "secret";

    struct Server {
        stream: DuplexStream,
        framer: Framer,
    }

    impl Server {
        async fn recv(&mut self) -> Message {
            loop {
                if let Some(m) = self.framer.next_message() {
                    return m.unwrap();
                }
                let mut buf = [0u8; 4096];
                let n = timeout(Duration::from_secs(5), self.stream.read(&mut buf)).await.expect("no message from UA").unwrap();
                assert!(n > 0, "UA closed the stream");
                self.framer.push(&buf[..n]);
            }
        }

        async fn send(&mut self, m: &Message) {
            self.stream.write_all(&m.to_bytes()).await.unwrap();
        }

        async fn reply(&mut self, req: &Message, code: u16, tag: Option<&str>) {
            self.send(&Message::response_to(req, code, "Test", tag)).await;
        }
    }

    fn config(codecs: &str) -> SipConfig {
        let text = format!("[sip]\nserver = \"pbx.example.org\"\nuser = \"alice@example.org-1000\"\npassword = \"secret\"\ncodecs = {codecs}\n\
aastra_id = 'type=\"32\" model=\"02\" version=\"10.3.8.0\" mac=\"001122334455\"'\n");
        toml::from_str::<crate::config::Config>(&text).unwrap().sip
    }

    fn start() -> (Server, mpsc::Sender<Command>, JoinHandle<Result<()>>) {
        start_with("[\"PCMA\", \"PCMU\"]")
    }

    fn start_with(codecs: &'static str) -> (Server, mpsc::Sender<Command>, JoinHandle<Result<()>>) {
        let (client, server) = tokio::io::duplex(65536);
        let (tx, mut rx) = mpsc::channel(8);
        let handle = tokio::spawn(async move {
            let cfg = config(codecs);
            let local: SocketAddr = "10.0.0.5:50000".parse().unwrap();
            let (events, _log) = mpsc::unbounded_channel();
            run_stream(client, local, &cfg, PASSWORD, false, None, &events, &mut rx).await
        });
        (Server { stream: server, framer: Framer::new() }, tx, handle)
    }

    /// Checks the digest response of a request against the expected credentials.
    fn assert_authorized(req: &Message, nonce: &str) {
        let auth = req.header("Authorization").expect("request without credentials");
        let field = |name: &str| {
            let start = auth.find(&format!("{name}=")).unwrap_or_else(|| panic!("{name} missing in {auth}")) + name.len() + 1;
            auth[start..].split(',').next().unwrap().trim_matches('"').to_string()
        };
        assert_eq!(field("nonce"), nonce);
        assert_eq!(field("uri"), req.uri().unwrap());
        assert_eq!(field("qop"), "auth-int");
        let nc = u32::from_str_radix(&field("nc"), 16).unwrap();
        let expected = misip::digest::response(
            "alice@example.org-1000",
            "mbg",
            PASSWORD,
            req.method().unwrap(),
            req.uri().unwrap(),
            nonce,
            Some("auth-int"),
            nc,
            &field("cnonce"),
            &req.body,
        );
        assert_eq!(field("response"), expected);
    }

    const AOR_URI: &str = "sips:alice%40example.org-1000@pbx.example.org:5061;transport=tls";
    const CONTACT_URI: &str = "sips:alice%40example.org-1000@10.0.0.5:50000;transport=tls";

    /// REGISTER, challenge, REGISTER with credentials, hotdesk SUBSCRIBE.
    async fn register(server: &mut Server) -> Message {
        let first = server.recv().await;
        assert_eq!(first.method(), Some("REGISTER"));
        assert_eq!(first.uri(), Some("sips:pbx.example.org:5061;transport=tls"));
        assert!(first.header("Authorization").is_none());
        assert_eq!(uri_of(first.header("To").unwrap()), AOR_URI);
        assert_eq!(first.header("Contact").unwrap(), format!("\"alice@example.org-1000\" <{CONTACT_URI}>;expires=1800"));
        assert_eq!(first.header("X-Aastra-Id").unwrap(), "type=\"32\" model=\"02\" version=\"10.3.8.0\" mac=\"001122334455\"");
        assert!(first.header("Via").unwrap().starts_with("SIP/2.0/TLS 10.0.0.5:50000;branch=z9hG4bK"));

        let mut challenge = Message::response_to(&first, 401, "Unauthorized", Some("srv1"));
        challenge.add("WWW-Authenticate", "Digest nonce=\"n1\",algorithm=MD5,realm=\"mbg\",qop=\"auth,auth-int\"");
        server.send(&challenge).await;

        let second = server.recv().await;
        assert_eq!(second.method(), Some("REGISTER"));
        assert_eq!(second.call_id(), first.call_id());
        assert_eq!(second.cseq().unwrap().0, first.cseq().unwrap().0 + 1);
        assert_ne!(second.branch(), first.branch());
        assert_authorized(&second, "n1");

        let mut ok = Message::response_to(&second, 200, "OK", Some("srv2"));
        // The server echoes the binding with a shorter lifetime and different case.
        ok.add("Contact", "\"alice@example.org-1000\"<sips:alice%40example.org-1000@10.0.0.5:50000;transport=TLS>;expires=240");
        ok.add("Expires", "240");
        ok.add("P-Login", "mihotdesk");
        server.send(&ok).await;

        let sub = server.recv().await;
        assert_eq!(sub.method(), Some("SUBSCRIBE"));
        assert_eq!(sub.header("Event"), Some("mihotdesk"));
        assert_eq!(sub.header("Accept"), Some("application/mihotdesk"));
        assert_authorized(&sub, "n1");
        assert_eq!(sub.header("Expires"), Some("1800"));
        server.reply(&sub, 200, Some("sub1")).await;
        // The server confirms the hotdesk login. Waiting for our answer also makes sure the
        // subscription is established before a test goes on.
        server.send(&hotdesk_notify(&sub, "0", false)).await;
        assert_eq!(server.recv().await.cseq(), Some((7, "NOTIFY")));
        sub
    }

    async fn quit(server: &mut Server, tx: mpsc::Sender<Command>, handle: JoinHandle<Result<()>>) {
        tx.send(Command::Quit).await.unwrap();
        sign_off(server).await;
        timeout(Duration::from_secs(5), handle).await.expect("UA did not stop").unwrap().unwrap();
    }

    /// SUBSCRIBE with Expires 0 inside the existing subscription, then REGISTER with expires=0.
    async fn sign_off(server: &mut Server) {
        let unsub = server.recv().await;
        assert_eq!(unsub.method(), Some("SUBSCRIBE"));
        assert_eq!(unsub.header("Expires"), Some("0"));
        assert_eq!(tag_of(unsub.header("To").unwrap()), Some("sub1"));
        server.reply(&unsub, 200, None).await;
        // The server confirms the end of the subscription; this must not be reported as an eviction.
        server.send(&hotdesk_notify(&unsub, "6", true)).await;
        let unreg = server.recv().await;
        assert_eq!(unreg.method(), Some("REGISTER"));
        assert!(unreg.header("Contact").unwrap().ends_with(";expires=0"));
        server.reply(&unreg, 200, Some("srv3")).await;
        assert_eq!(server.recv().await.cseq().map(|c| c.1.to_string()), Some("NOTIFY".to_string()));
    }

    /// A hotdesk NOTIFY inside the subscription created by `subscribe`.
    fn hotdesk_notify(subscribe: &Message, cause: &str, terminated: bool) -> Message {
        let mut n = Message::request("NOTIFY", CONTACT_URI);
        n.add("Via", format!("SIP/2.0/TLS 10.0.0.1;branch=z9hG4bK-n{}", random_hex(6)));
        n.add("From", format!("{};tag=sub1", subscribe.header("To").unwrap().split(";tag=").next().unwrap()));
        n.add("To", subscribe.header("From").unwrap());
        n.add("Call-ID", subscribe.call_id());
        n.add("CSeq", "7 NOTIFY");
        n.add("Event", "mihotdesk");
        n.add("Subscription-State", if terminated { "terminated;reason=deactivated" } else { "active;expires=1800" });
        n.set_body("application/mihotdesk", format!("<mihotdesk cause=\"{cause}\" display=\"Test\">\r\n</mihotdesk>\r\n"));
        n
    }

    #[tokio::test]
    async fn signs_off_when_server_ends_hotdesk_login() {
        let (mut server, _tx, handle) = start();
        let sub = register(&mut server).await;
        // Normal confirmations and the harmless error code change nothing.
        for cause in ["0", "105", "103"] {
            server.send(&hotdesk_notify(&sub, cause, false)).await;
            assert_eq!(server.recv().await.status(), Some(200));
        }
        // Another device took the account over.
        server.send(&hotdesk_notify(&sub, "4", false)).await;
        assert_eq!(server.recv().await.status(), Some(200));
        sign_off(&mut server).await;
        timeout(Duration::from_secs(5), handle).await.expect("UA did not stop").unwrap().unwrap();
    }

    #[tokio::test]
    async fn forgets_subscription_terminated_by_server() {
        let (mut server, tx, handle) = start();
        let sub = register(&mut server).await;
        server.send(&hotdesk_notify(&sub, "0", true)).await;
        assert_eq!(server.recv().await.status(), Some(200));
        // No subscription exists any more, so signing off only removes the registration.
        tx.send(Command::Quit).await.unwrap();
        let unreg = server.recv().await;
        assert_eq!(unreg.method(), Some("REGISTER"));
        assert!(unreg.header("Contact").unwrap().ends_with(";expires=0"));
        server.reply(&unreg, 200, None).await;
        timeout(Duration::from_secs(5), handle).await.expect("UA did not stop").unwrap().unwrap();
    }

    #[tokio::test]
    async fn registers_and_unregisters() {
        let (mut server, tx, handle) = start();
        register(&mut server).await;
        quit(&mut server, tx, handle).await;
    }

    #[tokio::test]
    async fn answers_incoming_call_and_follows_reinvite() {
        let (mut server, tx, handle) = start();
        register(&mut server).await;

        let mut invite = Message::request("INVITE", CONTACT_URI);
        invite.add("Via", "SIP/2.0/TLS 10.0.0.1;branch=z9hG4bK-inv1;rport");
        invite.add("Max-Forwards", "25");
        invite.add("Contact", "<sip:2000@10.0.0.1:5061;transport=TLS>");
        invite.add("To", format!("<{CONTACT_URI}>"));
        invite.add("From", "\"Bob\"<sip:2000@10.0.0.1>;tag=peer1");
        invite.add("Call-ID", "call-in-1");
        invite.add("CSeq", "1 INVITE");
        invite.add("Supported", "100rel, timer, from-change");
        invite.add("P-Asserted-Identity", "\"Bob\"<sip:2000@10.0.0.1:5061;transport=TLS>");
        invite.set_body(
            "application/sdp",
            "v=0\r\no=- 2913 2913 IN IP4 10.0.0.1\r\ns=NSTREAMING\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\nm=audio 20184 RTP/AVP 8 0 101\r\n\
a=rtpmap:8 PCMA/8000\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-15\r\na=ptime:20\r\na=inactive\r\n",
        );
        server.send(&invite).await;

        let trying = server.recv().await;
        assert_eq!(trying.status(), Some(100));
        let ringing = server.recv().await;
        assert_eq!(ringing.status(), Some(180));
        assert_eq!(ringing.header("Require"), Some("100rel"));
        assert_eq!(ringing.header("RSeq"), Some("1"));
        assert_eq!(ringing.branch(), Some("z9hG4bK-inv1"));
        let our_to = ringing.header("To").unwrap().to_string();
        let our_tag = tag_of(&our_to).expect("180 without To tag").to_string();

        let mut prack = Message::request("PRACK", CONTACT_URI);
        prack.add("Via", "SIP/2.0/TLS 10.0.0.1;branch=z9hG4bK-prack");
        prack.add("To", our_to.clone());
        prack.add("From", "\"Bob\"<sip:2000@10.0.0.1>;tag=peer1");
        prack.add("Call-ID", "call-in-1");
        prack.add("CSeq", "2 PRACK");
        prack.add("RAck", "1 1 INVITE");
        server.send(&prack).await;
        assert_eq!(server.recv().await.cseq(), Some((2, "PRACK")));

        tx.send(Command::Answer).await.unwrap();
        let ok = server.recv().await;
        assert_eq!((ok.status(), ok.cseq()), (Some(200), Some((1, "INVITE"))));
        assert_eq!(tag_of(ok.header("To").unwrap()), Some(our_tag.as_str()));
        assert_eq!(uri_of(ok.header("Contact").unwrap()), CONTACT_URI);
        let answer = AudioSdp::parse(ok.body_str()).unwrap();
        assert_eq!(answer.codecs.iter().map(|c| c.pt).collect::<Vec<_>>(), vec![8, 101]);
        assert_eq!(answer.direction, misip::sdp::Direction::Inactive);
        assert_eq!(answer.addr, "10.0.0.5");
        assert_ne!(answer.port, 0);

        // The server now switches the stream on and offers a codec we do not have first.
        let mut reinvite = invite.clone();
        reinvite.set("Via", "SIP/2.0/TLS 10.0.0.1;branch=z9hG4bK-inv2;rport");
        reinvite.set("To", our_to.clone());
        reinvite.set("CSeq", "3 INVITE");
        reinvite.set_body(
            "application/sdp",
            "v=0\r\no=- 2913 2914 IN IP4 10.0.0.1\r\ns=NSTREAMING\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\nm=audio 20184 RTP/AVP 124 8 0 101\r\n\
a=rtpmap:124 opus/48000/2\r\na=rtpmap:8 PCMA/8000\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\na=ptime:20\r\n",
        );
        server.send(&reinvite).await;
        let ok2 = server.recv().await;
        assert_eq!((ok2.status(), ok2.cseq()), (Some(200), Some((3, "INVITE"))));
        let answer2 = AudioSdp::parse(ok2.body_str()).unwrap();
        assert_eq!(answer2.codecs.iter().map(|c| c.pt).collect::<Vec<_>>(), vec![8, 101]);
        assert_eq!(answer2.direction, misip::sdp::Direction::SendRecv);
        assert_eq!(answer2.port, answer.port);
        assert_eq!(answer2.session_id, answer.session_id);
        assert_eq!(answer2.session_version, answer.session_version + 1);

        tx.send(Command::Hangup).await.unwrap();
        let bye = server.recv().await;
        assert_eq!(bye.method(), Some("BYE"));
        assert_eq!(bye.uri(), Some("sip:2000@10.0.0.1:5061;transport=TLS"));
        assert_eq!(tag_of(bye.header("From").unwrap()), Some(our_tag.as_str()));
        assert_eq!(tag_of(bye.header("To").unwrap()), Some("peer1"));
        assert_eq!(bye.call_id(), "call-in-1");
        assert_authorized(&bye, "n1");
        server.reply(&bye, 200, None).await;

        quit(&mut server, tx, handle).await;
    }

    #[tokio::test]
    async fn places_call_with_challenge_and_prack() {
        let (mut server, tx, handle) = start();
        register(&mut server).await;

        tx.send(Command::Call("2000".into())).await.unwrap();
        let first = server.recv().await;
        assert_eq!(first.method(), Some("INVITE"));
        assert_eq!(first.uri(), Some("sips:2000@pbx.example.org:5061"));
        assert_eq!(first.header("To"), Some("<sips:2000@pbx.example.org:5061>"));
        let offer = AudioSdp::parse(first.body_str()).unwrap();
        assert_eq!(offer.codecs.iter().map(|c| c.pt).collect::<Vec<_>>(), vec![8, 0, 101]);

        // The server asks for fresh credentials for the call.
        let mut challenge = Message::response_to(&first, 401, "Unauthorized", Some("x1"));
        challenge.add("WWW-Authenticate", "Digest nonce=\"n2\",algorithm=MD5,realm=\"mbg\",qop=\"auth,auth-int\"");
        server.send(&challenge).await;
        let ack = server.recv().await;
        assert_eq!(ack.method(), Some("ACK"));
        assert_eq!(ack.branch(), first.branch());
        assert_eq!(tag_of(ack.header("To").unwrap()), Some("x1"));

        let invite = server.recv().await;
        assert_eq!(invite.method(), Some("INVITE"));
        assert_eq!(invite.call_id(), first.call_id());
        assert_eq!(invite.header("From"), first.header("From"));
        assert_eq!(invite.body, first.body);
        let invite_cseq = invite.cseq().unwrap().0;
        assert_eq!(invite_cseq, first.cseq().unwrap().0 + 1);
        assert_authorized(&invite, "n2");

        server.reply(&invite, 100, None).await;
        let mut ringing = Message::response_to(&invite, 180, "Ringing", Some("peer2"));
        ringing.add("Require", "100rel");
        ringing.add("RSeq", "688332707");
        ringing.add("Contact", "<sip:2000@10.0.0.1:5061;transport=TLS>");
        server.send(&ringing).await;

        let prack = server.recv().await;
        assert_eq!(prack.method(), Some("PRACK"));
        assert_eq!(prack.uri(), Some("sip:2000@10.0.0.1:5061;transport=TLS"));
        assert_eq!(prack.header("RAck").unwrap(), format!("688332707 {invite_cseq} INVITE"));
        assert_eq!(tag_of(prack.header("To").unwrap()), Some("peer2"));
        assert_authorized(&prack, "n2");
        server.reply(&prack, 200, None).await;

        let mut ok = Message::response_to(&invite, 200, "OK", Some("peer2"));
        ok.add("Contact", "<sip:2000@10.0.0.1:5061;transport=TLS>");
        ok.set_body(
            "application/sdp",
            "v=0\r\no=- 2832 2832 IN IP4 127.0.0.1\r\ns=NSTREAMING\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 20114 RTP/AVP 0 101\r\n\
a=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\na=sendrecv\r\n",
        );
        server.send(&ok).await;
        let ack = server.recv().await;
        assert_eq!(ack.method(), Some("ACK"));
        assert_eq!(ack.uri(), Some("sip:2000@10.0.0.1:5061;transport=TLS"));
        assert_eq!(ack.cseq(), Some((invite_cseq, "ACK")));
        assert_ne!(ack.branch(), invite.branch());

        // The peer hangs up.
        let mut bye = Message::request("BYE", CONTACT_URI);
        bye.add("Via", "SIP/2.0/TLS 10.0.0.1;branch=z9hG4bK-bye");
        bye.add("From", ok.header("To").unwrap());
        bye.add("To", ok.header("From").unwrap());
        bye.add("Call-ID", invite.call_id());
        bye.add("CSeq", "1 BYE");
        server.send(&bye).await;
        assert_eq!(server.recv().await.cseq(), Some((1, "BYE")));

        quit(&mut server, tx, handle).await;
    }

    #[tokio::test]
    async fn cancels_unanswered_call_and_rejects_second_call() {
        let (mut server, tx, handle) = start();
        register(&mut server).await;

        tx.send(Command::Call("2000".into())).await.unwrap();
        let invite = server.recv().await;
        server.reply(&invite, 100, None).await;

        // A call arriving meanwhile is refused as busy.
        let mut other = Message::request("INVITE", CONTACT_URI);
        other.add("Via", "SIP/2.0/TLS 10.0.0.1;branch=z9hG4bK-other");
        other.add("From", "<sip:3000@10.0.0.1>;tag=p3");
        other.add("To", format!("<{CONTACT_URI}>"));
        other.add("Call-ID", "call-in-2");
        other.add("CSeq", "1 INVITE");
        server.send(&other).await;
        assert_eq!(server.recv().await.status(), Some(486));

        tx.send(Command::Hangup).await.unwrap();
        let cancel = server.recv().await;
        assert_eq!(cancel.method(), Some("CANCEL"));
        assert_eq!(cancel.branch(), invite.branch());
        assert_eq!(cancel.uri(), invite.uri());
        assert_eq!(cancel.cseq(), Some((invite.cseq().unwrap().0, "CANCEL")));
        server.reply(&cancel, 200, None).await;
        server.reply(&invite, 487, Some("x9")).await;
        let ack = server.recv().await;
        assert_eq!(ack.method(), Some("ACK"));
        assert_eq!(ack.branch(), invite.branch());

        quit(&mut server, tx, handle).await;
    }

    const PEER_SDP: &str = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=NSTREAMING\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 20184 RTP/AVP 8 101\r\n\
a=rtpmap:8 PCMA/8000\r\na=rtpmap:101 telephone-event/8000\r\na=ptime:20\r\n";

    /// Brings up an answered incoming call. Returns the peer's INVITE and our 200.
    async fn incoming_call(server: &mut Server, tx: &mpsc::Sender<Command>, session_expires: Option<&str>) -> (Message, Message) {
        let mut invite = Message::request("INVITE", CONTACT_URI);
        invite.add("Via", "SIP/2.0/TLS 10.0.0.1;branch=z9hG4bK-c1");
        invite.add("Contact", "<sip:2000@10.0.0.1:5061;transport=TLS>");
        invite.add("To", format!("<{CONTACT_URI}>"));
        invite.add("From", "\"Bob\"<sip:2000@10.0.0.1>;tag=peer1");
        invite.add("Call-ID", "call-x");
        invite.add("CSeq", "1 INVITE");
        invite.add("Supported", "timer");
        if let Some(se) = session_expires {
            invite.add("Session-Expires", se);
        }
        invite.set_body("application/sdp", format!("{PEER_SDP}a=sendrecv\r\n"));
        server.send(&invite).await;
        assert_eq!(server.recv().await.status(), Some(100));
        assert_eq!(server.recv().await.status(), Some(180));
        tx.send(Command::Answer).await.unwrap();
        let ok = server.recv().await;
        assert_eq!(ok.status(), Some(200));
        let mut ack = Message::request("ACK", CONTACT_URI);
        ack.add("Via", "SIP/2.0/TLS 10.0.0.1;branch=z9hG4bK-a1");
        ack.add("To", ok.header("To").unwrap());
        ack.add("From", ok.header("From").unwrap());
        ack.add("Call-ID", "call-x");
        ack.add("CSeq", "1 ACK");
        server.send(&ack).await;
        (invite, ok)
    }

    /// Answers the UA's re-INVITE with 200 and the given stream direction, and takes the ACK.
    async fn accept_reinvite(server: &mut Server, re: &Message, direction: &str, session_expires: Option<&str>) {
        let mut ok = Message::response_to(re, 200, "OK", None);
        ok.add("Contact", "<sip:2000@10.0.0.1:5061;transport=TLS>");
        if let Some(se) = session_expires {
            ok.add("Session-Expires", se);
        }
        ok.set_body("application/sdp", format!("{PEER_SDP}a={direction}\r\n"));
        server.send(&ok).await;
        let ack = server.recv().await;
        assert_eq!(ack.method(), Some("ACK"));
        assert_eq!(ack.cseq(), Some((re.cseq().unwrap().0, "ACK")));
        assert_eq!(ack.uri(), Some("sip:2000@10.0.0.1:5061;transport=TLS"));
    }

    fn direction_of(m: &Message) -> misip::sdp::Direction {
        AudioSdp::parse(m.body_str()).unwrap().direction
    }

    #[tokio::test]
    async fn holds_resumes_and_transfers() {
        let (mut server, tx, handle) = start();
        register(&mut server).await;
        let (invite, ok) = incoming_call(&mut server, &tx, None).await;
        let answer = AudioSdp::parse(ok.body_str()).unwrap();
        assert!(ok.header("Session-Expires").is_none(), "no timer was asked for");

        tx.send(Command::Hold).await.unwrap();
        let hold = server.recv().await;
        assert_eq!(hold.method(), Some("INVITE"));
        assert_eq!(hold.uri(), Some("sip:2000@10.0.0.1:5061;transport=TLS"));
        assert_eq!(hold.call_id(), "call-x");
        assert_eq!(hold.header("From"), ok.header("To"));
        assert_eq!(hold.header("To"), ok.header("From"));
        let offer = AudioSdp::parse(hold.body_str()).unwrap();
        assert_eq!(offer.direction, Direction::SendOnly);
        assert_eq!((offer.port, offer.session_id, offer.session_version), (answer.port, answer.session_id, answer.session_version + 1));
        assert_eq!(offer.codecs, answer.codecs);
        assert_authorized(&hold, "n1");
        accept_reinvite(&mut server, &hold, "recvonly", None).await;

        // While we hold, an offer from the peer is answered without accepting audio.
        let mut peer_offer = invite.clone();
        peer_offer.set("Via", "SIP/2.0/TLS 10.0.0.1;branch=z9hG4bK-c2");
        peer_offer.set("To", ok.header("To").unwrap());
        peer_offer.set("CSeq", "2 INVITE");
        server.send(&peer_offer).await;
        let held_answer = server.recv().await;
        assert_eq!((held_answer.status(), direction_of(&held_answer)), (Some(200), Direction::SendOnly));

        // The peer refuses to resume: the call stays on hold.
        tx.send(Command::Resume).await.unwrap();
        let resume = server.recv().await;
        assert_eq!(direction_of(&resume), Direction::SendRecv);
        server.reply(&resume, 500, None).await;
        let ack = server.recv().await;
        assert_eq!((ack.method(), ack.branch()), (Some("ACK"), resume.branch()));

        // Already on hold, so the transfer request goes out at once.
        tx.send(Command::Transfer("30 00".into())).await.unwrap();
        let refer = server.recv().await;
        assert_eq!(refer.method(), Some("REFER"));
        assert_eq!(refer.header("Refer-To"), Some("<sips:3000@pbx.example.org:5061>"));
        assert_eq!(refer.header("Referred-By").unwrap(), format!("<{AOR_URI}>"));
        assert_eq!(refer.uri(), Some("sip:2000@10.0.0.1:5061;transport=TLS"));
        server.reply(&refer, 202, None).await;

        let mut progress = Message::request("NOTIFY", CONTACT_URI);
        progress.add("Via", "SIP/2.0/TLS 10.0.0.1;branch=z9hG4bK-n1");
        progress.add("From", ok.header("From").unwrap());
        progress.add("To", ok.header("To").unwrap());
        progress.add("Call-ID", "call-x");
        progress.add("CSeq", "3 NOTIFY");
        progress.add("Event", "refer");
        progress.add("Subscription-State", "active");
        progress.set_body("message/sipfrag", "SIP/2.0 180 Ringing\r\n");
        server.send(&progress).await;
        assert_eq!(server.recv().await.cseq(), Some((3, "NOTIFY")));
        progress.set("CSeq", "4 NOTIFY");
        progress.set_body("message/sipfrag", "SIP/2.0 200 OK\r\n");
        server.send(&progress).await;
        assert_eq!(server.recv().await.cseq(), Some((4, "NOTIFY")));
        let bye = server.recv().await;
        assert_eq!(bye.method(), Some("BYE"));
        server.reply(&bye, 200, None).await;

        quit(&mut server, tx, handle).await;
    }

    #[tokio::test]
    async fn transfer_holds_first() {
        let (mut server, tx, handle) = start();
        register(&mut server).await;
        incoming_call(&mut server, &tx, None).await;
        tx.send(Command::Transfer("3000".into())).await.unwrap();
        let hold = server.recv().await;
        assert_eq!((hold.method(), direction_of(&hold)), (Some("INVITE"), Direction::SendOnly));
        accept_reinvite(&mut server, &hold, "recvonly", None).await;
        let refer = server.recv().await;
        assert_eq!(refer.method(), Some("REFER"));
        assert_eq!(refer.header("Refer-To"), Some("<sips:3000@pbx.example.org:5061>"));
        // The transfer target is busy; the held call stays and can be resumed.
        server.reply(&refer, 603, None).await;
        tx.send(Command::Resume).await.unwrap();
        let resume = server.recv().await;
        assert_eq!(direction_of(&resume), Direction::SendRecv);
        accept_reinvite(&mut server, &resume, "sendrecv", None).await;
        tx.send(Command::Hangup).await.unwrap();
        let bye = server.recv().await;
        assert_eq!(bye.method(), Some("BYE"));
        server.reply(&bye, 200, None).await;
        quit(&mut server, tx, handle).await;
    }

    #[tokio::test]
    async fn refreshes_session_and_ends_call_nobody_refreshes() {
        let (mut server, tx, handle) = start();
        register(&mut server).await;
        // The caller wants the called side (us) to refresh every 4 seconds.
        let (_, ok) = incoming_call(&mut server, &tx, Some("4;Refresher=uas")).await;
        assert_eq!(ok.header("Session-Expires"), Some("4;refresher=uas"));
        assert!(ok.has_token("Supported", "timer"));

        let started = std::time::Instant::now();
        let refresh = server.recv().await;
        let waited = started.elapsed();
        assert!(waited >= Duration::from_millis(1500) && waited < Duration::from_millis(3500), "refresh after {waited:?}");
        assert_eq!(refresh.method(), Some("INVITE"));
        assert_eq!(refresh.header("Session-Expires"), Some("4;refresher=uac"));
        assert_eq!(direction_of(&refresh), Direction::SendRecv);
        // From now on the peer promises to refresh, but never does.
        accept_reinvite(&mut server, &refresh, "sendrecv", Some("4;refresher=uas")).await;
        let bye = server.recv().await;
        assert_eq!(bye.method(), Some("BYE"));
        assert!(started.elapsed() >= Duration::from_millis(4000));
        server.reply(&bye, 200, None).await;
        quit(&mut server, tx, handle).await;
    }

    #[tokio::test]
    async fn outgoing_call_announces_and_runs_session_timer() {
        let (mut server, tx, handle) = start();
        register(&mut server).await;
        tx.send(Command::Call("2000".into())).await.unwrap();
        let invite = server.recv().await;
        assert_eq!(invite.header("Session-Expires"), Some("1800"));
        assert_eq!(invite.header("Min-SE"), Some("90"));
        assert!(invite.has_token("Supported", "timer") && invite.has_token("Supported", "100rel"));
        let mut ok = Message::response_to(&invite, 200, "OK", Some("peer9"));
        ok.add("Contact", "<sip:2000@10.0.0.1:5061;transport=TLS>");
        ok.add("Require", "timer");
        ok.add("Session-Expires", "2;refresher=uac");
        ok.set_body("application/sdp", format!("{PEER_SDP}a=sendrecv\r\n"));
        server.send(&ok).await;
        assert_eq!(server.recv().await.method(), Some("ACK"));
        // We are the refresher: a new offer after half the interval.
        let refresh = server.recv().await;
        assert_eq!(refresh.method(), Some("INVITE"));
        assert_eq!(refresh.header("Session-Expires"), Some("2;refresher=uac"));
        assert_eq!(tag_of(refresh.header("To").unwrap()), Some("peer9"));
        // A refresh by UPDATE from the peer is accepted as well.
        accept_reinvite(&mut server, &refresh, "sendrecv", Some("1800;refresher=uac")).await;
        let mut update = Message::request("UPDATE", CONTACT_URI);
        update.add("Via", "SIP/2.0/TLS 10.0.0.1;branch=z9hG4bK-u1");
        update.add("From", ok.header("To").unwrap());
        update.add("To", ok.header("From").unwrap());
        update.add("Call-ID", invite.call_id());
        update.add("CSeq", "1 UPDATE");
        update.add("Session-Expires", "600;refresher=uac");
        server.send(&update).await;
        let rsp = server.recv().await;
        assert_eq!((rsp.status(), rsp.header("Session-Expires")), (Some(200), Some("600;refresher=uac")));
        tx.send(Command::Hangup).await.unwrap();
        let bye = server.recv().await;
        assert_eq!(bye.method(), Some("BYE"));
        server.reply(&bye, 200, None).await;
        quit(&mut server, tx, handle).await;
    }

    /// Hold and retrieve as the PBX does them when the user holds via the server (CTI):
    /// an offer with `inactive`, later an INVITE without SDP that we answer with an offer.
    #[tokio::test]
    async fn follows_hold_and_retrieve_by_pbx() {
        let (mut server, tx, handle) = start();
        register(&mut server).await;
        let (invite, ok) = incoming_call(&mut server, &tx, None).await;
        let first = AudioSdp::parse(ok.body_str()).unwrap();

        let mut hold = invite.clone();
        hold.set("Via", "SIP/2.0/TLS 10.0.0.1;branch=z9hG4bK-h1");
        hold.set("To", ok.header("To").unwrap());
        hold.set("CSeq", "2 INVITE");
        hold.add("Session-Expires", "1800;Refresher=uas");
        hold.set_body("application/sdp", format!("{PEER_SDP}a=inactive\r\n"));
        server.send(&hold).await;
        let rsp = server.recv().await;
        assert_eq!((rsp.status(), direction_of(&rsp)), (Some(200), Direction::Inactive));
        assert_eq!(rsp.header("Session-Expires"), Some("1800;refresher=uas"));

        let mut retrieve = Message::request("INVITE", CONTACT_URI);
        retrieve.add("Via", "SIP/2.0/TLS 10.0.0.1;branch=z9hG4bK-h2");
        retrieve.add("Contact", "<sip:2000@10.0.0.1:5061;transport=TLS>");
        retrieve.add("From", ok.header("From").unwrap());
        retrieve.add("To", ok.header("To").unwrap());
        retrieve.add("Call-ID", "call-x");
        retrieve.add("CSeq", "3 INVITE");
        retrieve.add("Session-Expires", "1800;Refresher=uas");
        server.send(&retrieve).await;
        let rsp = server.recv().await;
        assert_eq!((rsp.status(), rsp.cseq()), (Some(200), Some((3, "INVITE"))));
        let offer = AudioSdp::parse(rsp.body_str()).unwrap();
        assert_eq!(offer.direction, Direction::SendRecv);
        assert_eq!(offer.codecs.iter().map(|c| c.pt).collect::<Vec<_>>(), vec![8, 0, 101]);
        assert_eq!((offer.port, offer.session_id), (first.port, first.session_id));
        assert_eq!(offer.session_version, first.session_version + 2);

        // The answer arrives in the ACK; afterwards the call works as before.
        let mut ack = Message::request("ACK", CONTACT_URI);
        ack.add("Via", "SIP/2.0/TLS 10.0.0.1;branch=z9hG4bK-h3");
        ack.add("From", ok.header("From").unwrap());
        ack.add("To", ok.header("To").unwrap());
        ack.add("Call-ID", "call-x");
        ack.add("CSeq", "3 ACK");
        ack.set_body("application/sdp", format!("{PEER_SDP}a=sendrecv\r\n"));
        server.send(&ack).await;
        tx.send(Command::Hold).await.unwrap();
        let our_hold = server.recv().await;
        assert_eq!((our_hold.method(), direction_of(&our_hold)), (Some("INVITE"), Direction::SendOnly));
        assert_eq!(AudioSdp::parse(our_hold.body_str()).unwrap().session_version, first.session_version + 3);
        accept_reinvite(&mut server, &our_hold, "recvonly", None).await;
        tx.send(Command::Hangup).await.unwrap();
        let bye = server.recv().await;
        assert_eq!(bye.method(), Some("BYE"));
        server.reply(&bye, 200, None).await;
        quit(&mut server, tx, handle).await;
    }

    /// With the default codec list Opus is offered first and taken when the peer offers it,
    /// and a later offer without Opus switches the call back to G.711.
    #[tokio::test]
    async fn negotiates_opus() {
        const OPUS_OFFER: &str = "v=0\r\no=- 5 5 IN IP4 127.0.0.1\r\ns=NSTREAMING\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 20184 RTP/AVP 124 8 0 101\r\n\
b=AS:128\r\na=rtpmap:124 opus/48000/2\r\na=fmtp:124 maxaveragebitrate=16000;maxplaybackrate=16000;stereo=0;useinbandfec=1\r\n\
a=rtpmap:8 PCMA/8000\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-15\r\na=ptime:20\r\na=sendrecv\r\n";
        let (mut server, tx, handle) = start_with("[\"opus\", \"PCMA\", \"PCMU\"]");
        register(&mut server).await;

        tx.send(Command::Call("2000".into())).await.unwrap();
        let invite = server.recv().await;
        let offer = AudioSdp::parse(invite.body_str()).unwrap();
        assert_eq!(offer.codecs.iter().map(|c| c.pt).collect::<Vec<_>>(), vec![124, 8, 0, 101]);
        assert_eq!(offer.codecs[0], Codec::opus(124, OPUS_FMTP));
        let mut ok = Message::response_to(&invite, 200, "OK", Some("peer5"));
        ok.add("Contact", "<sip:2000@10.0.0.1:5061;transport=TLS>");
        ok.set_body("application/sdp", OPUS_OFFER.replace(" 124 8 0 101", " 124 101"));
        server.send(&ok).await;
        assert_eq!(server.recv().await.method(), Some("ACK"));

        // The peer renegotiates and offers Opus among others: Opus stays.
        let mut re = Message::request("INVITE", CONTACT_URI);
        re.add("Via", "SIP/2.0/TLS 10.0.0.1;branch=z9hG4bK-o1");
        re.add("Contact", "<sip:2000@10.0.0.1:5061;transport=TLS>");
        re.add("From", ok.header("To").unwrap());
        re.add("To", ok.header("From").unwrap());
        re.add("Call-ID", invite.call_id());
        re.add("CSeq", "1 INVITE");
        re.set_body("application/sdp", OPUS_OFFER);
        server.send(&re).await;
        let rsp = server.recv().await;
        let answer = AudioSdp::parse(rsp.body_str()).unwrap();
        assert_eq!(answer.codecs.iter().map(|c| c.pt).collect::<Vec<_>>(), vec![124, 101]);
        assert_eq!(answer.codecs[0].fmtp.as_deref(), Some("maxaveragebitrate=16000;maxplaybackrate=16000;stereo=0;useinbandfec=1"));
        assert_eq!((answer.codecs[0].rate, answer.codecs[0].channels), (48000, 2));

        // An offer without Opus (e.g. after a transfer to a plain phone) falls back to G.711.
        re.set("Via", "SIP/2.0/TLS 10.0.0.1;branch=z9hG4bK-o2");
        re.set("CSeq", "2 INVITE");
        re.set_body("application/sdp", format!("{PEER_SDP}a=sendrecv\r\n"));
        server.send(&re).await;
        let rsp = server.recv().await;
        assert_eq!(AudioSdp::parse(rsp.body_str()).unwrap().codecs.iter().map(|c| c.pt).collect::<Vec<_>>(), vec![8, 101]);

        tx.send(Command::Hangup).await.unwrap();
        let bye = server.recv().await;
        assert_eq!(bye.method(), Some("BYE"));
        server.reply(&bye, 200, None).await;
        quit(&mut server, tx, handle).await;
    }

    /// An account that is not a hotdesk account: no hotdesk subscription, neither after
    /// registering nor when signing off.
    #[tokio::test]
    async fn skips_hotdesk_for_ordinary_accounts() {
        let (mut server, tx, handle) = start();
        let first = server.recv().await;
        let mut challenge = Message::response_to(&first, 401, "Unauthorized", Some("srv1"));
        challenge.add("WWW-Authenticate", "Digest nonce=\"n1\",algorithm=MD5,realm=\"mbg\",qop=\"auth,auth-int\"");
        server.send(&challenge).await;
        let second = server.recv().await;
        let mut ok = Message::response_to(&second, 200, "OK", Some("srv2"));
        ok.add("Contact", format!("<{CONTACT_URI}>;expires=240"));
        server.send(&ok).await;
        // Messages are handled in order, so the answer to this OPTIONS shows that the
        // registration has been processed - and that no SUBSCRIBE came in between.
        let mut ping = Message::request("OPTIONS", CONTACT_URI);
        ping.add("Via", "SIP/2.0/TLS 10.0.0.1;branch=z9hG4bK-opt");
        ping.add("From", "<sip:pbx@10.0.0.1>;tag=o1");
        ping.add("To", format!("<{CONTACT_URI}>"));
        ping.add("Call-ID", "options-1");
        ping.add("CSeq", "1 OPTIONS");
        server.send(&ping).await;
        assert_eq!(server.recv().await.cseq(), Some((1, "OPTIONS")));

        // The next thing the UA sends is the call, not a SUBSCRIBE.
        tx.send(Command::Call("2000".into())).await.unwrap();
        let invite = server.recv().await;
        assert_eq!(invite.method(), Some("INVITE"));
        tx.send(Command::Hangup).await.unwrap();
        let cancel = server.recv().await;
        assert_eq!(cancel.method(), Some("CANCEL"));
        server.reply(&cancel, 200, None).await;
        server.reply(&invite, 487, Some("x")).await;
        assert_eq!(server.recv().await.method(), Some("ACK"));

        tx.send(Command::Quit).await.unwrap();
        let unreg = server.recv().await;
        assert_eq!(unreg.method(), Some("REGISTER"));
        assert!(unreg.header("Contact").unwrap().ends_with(";expires=0"));
        server.reply(&unreg, 200, None).await;
        timeout(Duration::from_secs(5), handle).await.expect("UA did not stop").unwrap().unwrap();
    }
}