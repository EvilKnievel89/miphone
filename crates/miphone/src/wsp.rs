//! The MiCollab server's event channel ("WSP"): a WebSocket on port 36008 over which the
//! server pushes notifications, e.g. that the user's presence status changed.
//!
//! Every frame is one JSON object. After connecting, the server sends a greeting, the client
//! attaches with the user's login and then registers for notifications. Frames from the server
//! carry a sequence number (`wspSeq`) that the client acknowledges, so the server can replay
//! what was missed after a reconnect.

use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tokio::time::{sleep_until, Instant};
use tokio_tungstenite::tungstenite::Message;

use crate::micollab::Account;
use crate::provision::percent_decode;

/// Client type the MiCollab client for Windows reports; the server knows its clients by this.
const CLIENT_TYPE: &str = "UCA_Win10/10.3.8";
const PORT: u16 = 36008;
const HEARTBEAT: Duration = Duration::from_secs(180);
const ACK_DELAY: Duration = Duration::from_secs(1);

/// Notification codes (`command`) of frames with `source: "notif"`.
const NOTIFY_REGISTER: u64 = 2000;
const NOTIFY_HEARTBEAT: u64 = 1000;
const NOTIFY_STATUS_CHANGED: u64 = 2006;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerEvent {
    /// Attached and registered for notifications.
    Connected,
    /// The user's status (or its text) changed; the new one has to be fetched.
    StatusChanged,
    /// The server's view of the user's own presence.
    Presence(Presence),
    /// Presence of a watched contact; `id` is the contact's presence identity.
    ContactPresence { id: String, presence: Presence },
}

/// Presence identities of the contacts to watch besides ourselves. The front end changes
/// the list and signals the running connection.
pub type Watchlist = std::sync::Arc<std::sync::Mutex<Vec<String>>>;

/// The server limits the number of presence subscriptions per client.
const MAX_WATCHED: usize = 250;

/// Presence of a user as the server reports it; the status dot is drawn from this.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Presence {
    /// `Idle`, `Ringing`, `In A Call`, `OffHook`, `DND`, `OffLine`.
    pub telephony_state: String,
    /// `Default`, `Away`, `Busy`.
    pub external_presence: String,
    /// Chat state: `Idle`, `Away`, `Offline`.
    pub im_state: String,
    pub status_name: String,
    pub status_id: Value,
    pub available_for_calls: bool,
    pub available_for_chat: bool,
}

/// What the status dot shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Indicator {
    Available,
    Away,
    Busy,
    /// Busy and blinking: a call is ringing.
    Ringing,
    DoNotDisturb,
    Offline,
    Unknown,
}

impl Presence {
    fn parse(notification: &Value) -> Presence {
        let text = |key: &str| notification.get(key).and_then(Value::as_str).unwrap_or("").to_string();
        let has = |what: &str| match notification.pointer("/availabilities/availability") {
            Some(Value::Array(items)) => items.iter().any(|a| a.as_str() == Some(what)),
            Some(Value::String(one)) => one == what,
            _ => false,
        };
        Presence {
            telephony_state: text("telephonyState"),
            external_presence: text("externalPresence"),
            im_state: text("imState"),
            status_name: text("statusName"),
            status_id: notification.get("statusId").cloned().unwrap_or(Value::Null),
            available_for_calls: has("AvailableCall"),
            available_for_chat: has("AvailableIM"),
        }
    }

    /// The rules of the MiCollab client for turning a presence into its status icon
    /// (calendar hints left out).
    pub fn indicator(&self) -> Indicator {
        let external = self.external_presence.to_ascii_lowercase();
        let telephony = self.telephony_state.to_ascii_lowercase();
        if external == "away" {
            return Indicator::Away;
        }
        // "Do not disturb" on the phone is shown even when the status itself says busy.
        let dnd = telephony == "dnd" && (external == "busy" || external == "default");
        if external == "busy" && !dnd {
            return Indicator::Busy;
        }
        // The phone state only counts if calls are possible in this status at all.
        let phone = if dnd || self.available_for_calls { telephony.as_str() } else { "offline" };
        let chat_away = self.available_for_chat && self.im_state.eq_ignore_ascii_case("away");
        match phone {
            "idle" if chat_away => Indicator::Away,
            "idle" => Indicator::Available,
            "ringing" => Indicator::Ringing,
            "offhook" | "in a call" => Indicator::Busy,
            "dnd" => Indicator::DoNotDisturb,
            "offline" => Indicator::Offline,
            _ => Indicator::Unknown,
        }
    }
}

pub struct Login<'a> {
    pub server: &'a str,
    pub user: &'a str,
    pub password: &'a str,
    pub tls_insecure: bool,
    /// Identifies this client's session on the server across reconnects; 32 hex digits.
    pub session_key: &'a str,
}

/// Protocol state of one connection, separate from the socket so it can be tested.
struct Session<'a> {
    login: &'a Login<'a>,
    account: &'a Account,
    attached: bool,
    /// Our own presence id as the account names it; `<login>@<server>` if it does not.
    own_id: String,
    watchlist: &'a Watchlist,
    /// Highest sequence number received; sent with every frame and in acknowledgements.
    highest_seq: u64,
    ack_pending: bool,
}

impl Session<'_> {
    /// Handles one frame from the server. Returns the frames to send and the events to report.
    fn on_frame(&mut self, text: &str) -> Result<(Vec<Value>, Vec<ServerEvent>)> {
        let frame: Value = match serde_json::from_str(text) {
            Ok(v) => v,
            // Frames may arrive URL-encoded.
            Err(_) => serde_json::from_str(&percent_decode(text)).map_err(|_| anyhow!("Ereigniskanal: unlesbare Nachricht"))?,
        };
        let mut send = Vec::new();
        let mut events = Vec::new();
        if let Some(seq) = frame.get("wspSeq").and_then(Value::as_u64) {
            self.highest_seq = self.highest_seq.max(seq);
            self.ack_pending = true;
        }
        match frame.get("source").and_then(Value::as_str) {
            Some("wsp") if frame.get("nonce").is_some() => {
                send.push(json!({
                    "dest": "proxy",
                    "user": self.login.user,
                    "passwd": self.login.password,
                    "clientType": CLIENT_TYPE,
                    "WspCommand": "attach",
                    "capabilities": "reliable",
                    "wspSeq": self.highest_seq,
                }));
            }
            Some("wsp") if frame.get("service").is_some() => {
                let code = frame.pointer("/message/code").and_then(Value::as_str).unwrap_or("");
                if code != "SUCCESS" && code != "PASSWORD_CHANGED" {
                    bail!("Ereigniskanal: Anmeldung abgelehnt ({code})");
                }
                if frame.get("WspCommand").and_then(Value::as_str) != Some("attached") {
                    // A new session on the server side: its numbering starts over.
                    self.highest_seq = 0;
                }
                self.attached = true;
                send.push(self.stamped(json!({
                    "dest": "notif",
                    "command": NOTIFY_REGISTER,
                    "tenant": self.account.tenant,
                    "message": { "addressUuid": self.account.contact_id },
                })));
                // Watch our own presence, like the MiCollab client does right after logging in.
                send.push(self.stamped(json!({ "dest": "pres", "service": "setDynamicPresenceLimit", "message": { "limit": 300 } })));
                send.push(self.subscriptions());
                events.push(ServerEvent::Connected);
            }
            Some("pres") => {
                if let (Some(id), Some(notification)) = (frame.get("id").and_then(Value::as_str), frame.get("notification")) {
                    let presence = Presence::parse(notification);
                    if id.eq_ignore_ascii_case(&self.own_id) {
                        events.push(ServerEvent::Presence(presence));
                    } else {
                        events.push(ServerEvent::ContactPresence { id: id.to_ascii_lowercase(), presence });
                    }
                }
            }
            Some("notif") if frame.get("command").and_then(Value::as_u64) == Some(NOTIFY_STATUS_CHANGED) => {
                events.push(ServerEvent::StatusChanged);
            }
            _ => {}
        }
        Ok((send, events))
    }

    /// The complete list of presence subscriptions: ourselves (with details) and the watched
    /// contacts. Sent as a replacement of whatever the server had before.
    fn subscriptions(&self) -> Value {
        let mut list = vec![json!({ "id": self.own_id, "context": "", "details": true })];
        let watched = self.watchlist.lock().unwrap();
        list.extend(
            watched.iter().filter(|id| !id.eq_ignore_ascii_case(&self.own_id)).take(MAX_WATCHED).map(|id| json!({ "id": id, "context": "", "details": false })),
        );
        self.stamped(json!({
            "dest": "pres",
            "service": "setupDynamicPresence",
            "message": {
                "watcher": self.own_id,
                "increment": false,
                "addSubscriptions": { "subscriptions": list },
                "removeSubscriptions": { "subscriptions": [] },
            },
        }))
    }

    /// Adds the sequence number every frame to the server carries.
    fn stamped(&self, mut frame: Value) -> Value {
        frame["wspSeq"] = json!(self.highest_seq);
        frame
    }

    fn ack(&mut self) -> Value {
        self.ack_pending = false;
        json!({ "dest": "proxy", "wspSeq": self.highest_seq, "WspCommand": "ping" })
    }

    /// The server only expects heartbeats from accounts that belong to a tenant.
    fn heartbeat(&self) -> Option<Value> {
        let has_tenant = !self.account.tenant.is_null() && self.account.tenant.as_str() != Some("");
        (self.attached && has_tenant).then(|| self.stamped(json!({ "dest": "notif", "command": NOTIFY_HEARTBEAT, "message": {}, "tenant": self.account.tenant })))
    }
}

/// Runs one connection. Returns `Ok` when `stop` fires or its sender is dropped (the session
/// is then ended on the server), and `Err` when the connection fails; the caller reconnects.
/// `watch_changed` signals that the `watchlist` was modified and has to be sent again.
pub async fn run(
    login: &Login<'_>,
    account: &Account,
    watchlist: &Watchlist,
    watch_changed: &mut mpsc::UnboundedReceiver<()>,
    events: &mpsc::UnboundedSender<ServerEvent>,
    stop: &mut mpsc::Receiver<()>,
) -> Result<()> {
    let url = format!("wss://{}:{PORT}/?S_VER=2&S_KEY={}", login.server, login.session_key);
    let connector = if login.tls_insecure {
        let tls = native_tls::TlsConnector::builder().danger_accept_invalid_certs(true).danger_accept_invalid_hostnames(true).build()?;
        Some(tokio_tungstenite::Connector::NativeTls(tls))
    } else {
        None
    };
    let (mut ws, _) = tokio_tungstenite::connect_async_tls_with_config(url, None, true, connector)
        .await
        .with_context(|| format!("Ereigniskanal: keine Verbindung zu {}:{PORT}", login.server))?;
    let own_id = account.presence_id.clone().unwrap_or_else(|| format!("{}@{}", login.user, login.server));
    let mut session = Session { login, account, own_id, watchlist, attached: false, highest_seq: 0, ack_pending: false };
    let mut ack_at: Option<Instant> = None;
    let mut next_heartbeat = Instant::now() + HEARTBEAT;
    let idle = || Instant::now() + Duration::from_secs(86400);
    loop {
        tokio::select! {
            msg = ws.next() => {
                let text = match msg {
                    Some(Ok(Message::Text(t))) => t.to_string(),
                    Some(Ok(Message::Close(_))) | None => bail!("Ereigniskanal: vom Server geschlossen"),
                    Some(Ok(_)) => continue, // ping/pong are answered by the library
                    Some(Err(e)) => return Err(e).context("Ereigniskanal"),
                };
                let (send, reported) = session.on_frame(&text)?;
                for frame in send {
                    ws.send(Message::text(frame.to_string())).await?;
                }
                for event in reported {
                    let _ = events.send(event);
                }
                if session.ack_pending && ack_at.is_none() {
                    ack_at = Some(Instant::now() + ACK_DELAY);
                }
            }
            _ = sleep_until(ack_at.unwrap_or_else(idle)) => {
                ack_at = None;
                let frame = session.ack();
                ws.send(Message::text(frame.to_string())).await?;
            }
            _ = sleep_until(next_heartbeat) => {
                next_heartbeat = Instant::now() + HEARTBEAT;
                if let Some(frame) = session.heartbeat() {
                    ws.send(Message::text(frame.to_string())).await?;
                }
            }
            Some(()) = watch_changed.recv() => {
                if session.attached {
                    let frame = session.subscriptions();
                    ws.send(Message::text(frame.to_string())).await?;
                }
            }
            _ = stop.recv() => {
                // Logging out: end the session instead of leaving it to time out.
                let _ = ws.send(Message::text(json!({ "dest": "proxy", "WspCommand": "disconnectSession" }).to_string())).await;
                let _ = ws.close(None).await;
                return Ok(());
            }
        }
    }
}

/// A fresh session key, formed like the MiCollab client's (32 hex digits).
pub fn new_session_key() -> String {
    misip::random_hex(32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login() -> Login<'static> {
        Login { server: "mc.example.org", user: "alice@example.org", password: "pw", tls_insecure: false, session_key: "00112233445566778899aabbccddeeff" }
    }

    fn account() -> Account {
        Account { tenant: json!("t1"), contact_id: "497e5b85-0000".into(), first_name: String::new(), last_name: String::new(), presence_id: None }
    }

    // Shapes as the MiCollab server sends them.
    const GREETING: &str = r#"{"S_LASTSEQ":156,"S_USE":2,"recvfrom":"/10.0.0.5:22051","source":"wsp","nonce":"abc"}"#;
    const ATTACHED: &str = r#"{"WspCommand":"attached","bridgeId":313,"configFileID":"21","service":"errorValue","source":"wsp","message":{"code":"SUCCESS"},"version":"10.3.0.21"}"#;

    #[test]
    fn attaches_and_registers() {
        let (login, account, watch) = (login(), account(), Watchlist::default());
        let mut s = Session { login: &login, account: &account, own_id: "alice@example.org@mc.example.org".into(), watchlist: &watch, attached: false, highest_seq: 0, ack_pending: false };
        let (send, events) = s.on_frame(GREETING).unwrap();
        assert!(events.is_empty());
        assert_eq!(
            send,
            vec![json!({"dest":"proxy","user":"alice@example.org","passwd":"pw","clientType":"UCA_Win10/10.3.8","WspCommand":"attach","capabilities":"reliable","wspSeq":0})]
        );
        assert!(s.heartbeat().is_none(), "no heartbeat before the login is confirmed");

        let (send, events) = s.on_frame(ATTACHED).unwrap();
        assert_eq!(events, vec![ServerEvent::Connected]);
        assert_eq!(
            send,
            vec![
                json!({"dest":"notif","command":2000,"tenant":"t1","message":{"addressUuid":"497e5b85-0000"},"wspSeq":0}),
                json!({"dest":"pres","service":"setDynamicPresenceLimit","message":{"limit":300},"wspSeq":0}),
                json!({"dest":"pres","service":"setupDynamicPresence","message":{"watcher":"alice@example.org@mc.example.org","increment":false,
                    "addSubscriptions":{"subscriptions":[{"id":"alice@example.org@mc.example.org","context":"","details":true}]},
                    "removeSubscriptions":{"subscriptions":[]}},"wspSeq":0}),
            ]
        );
        assert_eq!(s.heartbeat().unwrap(), json!({"dest":"notif","command":1000,"message":{},"tenant":"t1","wspSeq":0}));
    }

    #[test]
    fn reports_status_changes_and_acknowledges() {
        let (login, account, watch) = (login(), account(), Watchlist::default());
        let mut s = Session { login: &login, account: &account, own_id: "alice@example.org@mc.example.org".into(), watchlist: &watch, attached: true, highest_seq: 0, ack_pending: false };
        let (send, events) = s.on_frame(r#"{"source":"notif","command":2006,"wspSeq":184,"message":{"id":12,"changeType":"account_status_id"}}"#).unwrap();
        assert!(send.is_empty());
        assert_eq!(events, vec![ServerEvent::StatusChanged]);
        assert!(s.ack_pending);
        assert_eq!(s.ack(), json!({"dest":"proxy","wspSeq":184,"WspCommand":"ping"}));
        assert!(!s.ack_pending);
        // Other notifications and an older sequence number change nothing.
        let (send, events) = s.on_frame(r#"{"source":"notif","command":2003,"wspSeq":183}"#).unwrap();
        assert!(send.is_empty() && events.is_empty());
        assert_eq!(s.highest_seq, 184);
        // URL-encoded frames are understood as well.
        let (_, events) = s.on_frame("%7B%22source%22%3A%22notif%22%2C%22command%22%3A2006%7D").unwrap();
        assert_eq!(events, vec![ServerEvent::StatusChanged]);
    }

    #[test]
    fn rejected_login_and_new_session() {
        let (login, account, watch) = (login(), account(), Watchlist::default());
        let mut s = Session { login: &login, account: &account, own_id: "alice@example.org@mc.example.org".into(), watchlist: &watch, attached: false, highest_seq: 40, ack_pending: false };
        let err = s.on_frame(r#"{"source":"wsp","service":"errorValue","message":{"code":"AUTHENTICATION_FAILED"}}"#).unwrap_err();
        assert!(err.to_string().contains("AUTHENTICATION_FAILED"));
        // Without "attached" the server started a new session, so counting starts over.
        s.on_frame(r#"{"source":"wsp","service":"x","message":{"code":"SUCCESS"}}"#).unwrap();
        assert_eq!(s.highest_seq, 0);
        assert!(s.on_frame("not json at all").is_err());
        // Accounts without tenant send no heartbeat.
        let no_tenant = Account { tenant: Value::Null, contact_id: "c".into(), first_name: String::new(), last_name: String::new(), presence_id: None };
        let s = Session { login: &login, account: &no_tenant, own_id: String::new(), watchlist: &watch, attached: true, highest_seq: 0, ack_pending: false };
        assert!(s.heartbeat().is_none());
    }

    fn presence(telephony: &str, external: &str, im: &str, availabilities: &[&str]) -> Presence {
        let frame = json!({"notification":{"telephonyState":telephony,"activity":"x","availabilities":{"availability":availabilities},
            "externalPresence":external,"calendarAdv":"","statusId":1267,"statusName":"Available","imState":im},
            "service":"statusSnapShot","context":"","source":"pres","id":"Alice@example.org@mc.example.org"});
        let (login, account, watch) = (login(), account(), Watchlist::default());
        let mut s = Session { login: &login, account: &account, own_id: "alice@example.org@mc.example.org".into(), watchlist: &watch, attached: true, highest_seq: 0, ack_pending: false };
        match s.on_frame(&frame.to_string()).unwrap().1.pop() {
            Some(ServerEvent::Presence(p)) => p,
            other => panic!("no presence event: {other:?}"),
        }
    }

    /// The combinations the server really sends, with the icon the MiCollab client shows.
    #[test]
    fn maps_presence_to_indicator() {
        let both = ["AvailableIM", "AvailableCall"];
        let p = presence("Idle", "Default", "Idle", &both);
        assert_eq!((p.status_name.as_str(), p.status_id.clone(), p.available_for_calls), ("Available", json!(1267), true));
        assert_eq!(p.indicator(), Indicator::Available);
        assert_eq!(presence("Idle", "Away", "Idle", &both).indicator(), Indicator::Away);
        assert_eq!(presence("Ringing", "Away", "Idle", &both).indicator(), Indicator::Away);
        assert_eq!(presence("Idle", "Busy", "Idle", &both).indicator(), Indicator::Busy);
        assert_eq!(presence("In A Call", "Default", "Idle", &both).indicator(), Indicator::Busy);
        assert_eq!(presence("OffHook", "Default", "Idle", &both).indicator(), Indicator::Busy);
        assert_eq!(presence("Ringing", "Default", "Idle", &both).indicator(), Indicator::Ringing);
        assert_eq!(presence("DND", "Default", "Idle", &both).indicator(), Indicator::DoNotDisturb);
        assert_eq!(presence("DND", "Busy", "Idle", &both).indicator(), Indicator::DoNotDisturb);
        assert_eq!(presence("DND", "Default", "Idle", &["AvailableIM"]).indicator(), Indicator::DoNotDisturb);
        assert_eq!(presence("OffLine", "Default", "Idle", &both).indicator(), Indicator::Offline);
        assert_eq!(presence("Idle", "Default", "Away", &both).indicator(), Indicator::Away);
        // Without call availability the phone state does not count.
        assert_eq!(presence("Idle", "Default", "Idle", &["AvailableIM"]).indicator(), Indicator::Offline);
        assert_eq!(presence("Weird", "Default", "Idle", &both).indicator(), Indicator::Unknown);
    }

    #[test]
    fn watches_contacts() {
        let (login, account, watch) = (login(), account(), Watchlist::default());
        let mut s = Session { login: &login, account: &account, own_id: "alice@example.org@mc.example.org".into(), watchlist: &watch, attached: true, highest_seq: 5, ack_pending: false };
        // Our own id is never listed twice, even if the front end asks for it.
        *watch.lock().unwrap() = vec!["Bob@example.org@mc.example.org".into(), "ALICE@example.org@mc.example.org".into()];
        assert_eq!(
            s.subscriptions(),
            json!({"dest":"pres","service":"setupDynamicPresence","message":{"watcher":"alice@example.org@mc.example.org","increment":false,
                "addSubscriptions":{"subscriptions":[
                    {"id":"alice@example.org@mc.example.org","context":"","details":true},
                    {"id":"Bob@example.org@mc.example.org","context":"","details":false}]},
                "removeSubscriptions":{"subscriptions":[]}},"wspSeq":5})
        );
        let (_, events) = s.on_frame(r#"{"notification":{"telephonyState":"In A Call","externalPresence":"Default","availabilities":{"availability":["AvailableCall"]}},"source":"pres","id":"Bob@example.org@mc.example.org"}"#).unwrap();
        match &events[..] {
            [ServerEvent::ContactPresence { id, presence }] => {
                assert_eq!(id, "bob@example.org@mc.example.org");
                assert_eq!(presence.indicator(), Indicator::Busy);
            }
            other => panic!("unexpected events: {other:?}"),
        }
        // The subscription list is capped.
        *watch.lock().unwrap() = (0..400).map(|i| format!("user{i}@mc.example.org")).collect();
        assert_eq!(s.subscriptions()["message"]["addSubscriptions"]["subscriptions"].as_array().unwrap().len(), MAX_WATCHED + 1);
    }

    #[test]
    fn session_keys_look_right() {
        let k = new_session_key();
        assert!(k.len() == 32 && k.chars().all(|c| c.is_ascii_hexdigit()) && k != new_session_key());
    }
}
