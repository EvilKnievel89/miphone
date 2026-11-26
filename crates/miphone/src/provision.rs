//! Provisioning: logs in to the MiCollab server with the user's own credentials and downloads
//! the deployment profile that contains the softphone's SIP account, the same way the
//! MiCollab client configures itself ("self deployment").
//!
//! 1. `GetAccountInfo` (JSON-RPC, basic auth) yields the user's contact id.
//! 2. `/mdpapi/v1/getLink/<login>/<contact id>` yields a short-lived deployment token per number.
//! 3. `/mdpapi/v1/getTokenAndUrl` exchanges it for a config token and the config server.
//! 4. `/mdpapi/v1/getconfigforuser` returns the profile.
//!
//! Steps 3 and 4 answer with an encrypted body on current servers; the key is derived from
//! values of the exchange itself (path, `Date` header, bearer token and a nonce).

use aes::cipher::{BlockCipherDecrypt, KeyInit};
use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::config::MicollabConfig;

/// Version reported to the config server; profiles can depend on the client version.
const CLIENT_VERSION: &str = "10.3.8";

/// One SIP account of the profile: the one at the PBX itself or the one at the border
/// gateway (teleworker).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    /// The registrar; also the domain of the SIP addresses.
    pub server: String,
    pub port: u16,
    /// Host and port to connect to if they differ from the registrar.
    pub outbound_proxy: Option<(String, u16)>,
    pub user: String,
    pub password: String,
    /// Certificates (PEM) the profile names as issuers of the SIP server's certificate.
    pub ca_chain: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    /// The account in use. Like the Mitel client, the choice follows `general.use_teleworker`
    /// alone; the other account is never used as a silent substitute.
    pub account: Account,
    /// True if `account` is the one of the border gateway (teleworker) rather than the PBX's.
    pub teleworker: bool,
    /// The other account, if the profile lets the user switch and it is usable.
    pub other: Option<Account>,
    pub number: Option<String>,
    /// The profile marks the account as ACD agent.
    pub acd: bool,
}

impl Profile {
    /// Changes over to the other account. False if there is none to change to.
    pub fn switch(&mut self) -> bool {
        match self.other.take() {
            Some(other) => {
                self.other = Some(std::mem::replace(&mut self.account, other));
                self.teleworker = !self.teleworker;
                true
            }
            None => false,
        }
    }
}

/// The login name as the Mitel client uses it: a trailing `@<server>` is not part of it.
pub fn login_name(server: &str, user: &str) -> String {
    let user = user.trim();
    let suffix = format!("@{}", server.trim().to_lowercase());
    match user.len().checked_sub(suffix.len()) {
        Some(at) if at > 0 && user.is_char_boundary(at) && user[at..].to_lowercase() == suffix => user[..at].to_string(),
        _ => user.to_string(),
    }
}

/// One of several extensions an account can be set up for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Choice {
    pub number: String,
    /// Name of the device as the server calls it; empty if unknown.
    pub label: String,
    /// True if the server lists this extension as a softphone.
    pub softphone: bool,
}

/// The account has several extensions; the user has to pick one (`MicollabConfig::number`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultipleDeployments(pub Vec<Choice>);

impl std::fmt::Display for MultipleDeployments {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let numbers: Vec<&str> = self.0.iter().map(|c| c.number.as_str()).collect();
        write!(f, "Mehrere Bereitstellungen vorhanden ({}). Bitte micollab.number in der Konfiguration setzen.", numbers.join(", "))
    }
}

impl std::error::Error for MultipleDeployments {}

/// Describes the extensions on offer using the account's device list (`GetDestinations`).
fn label_choices(numbers: &[String], destinations: &Value) -> Vec<Choice> {
    let list: Vec<&Value> = match find_key(destinations, "destination") {
        Some(Value::Array(items)) => items.iter().collect(),
        Some(one) if one.is_object() => vec![one],
        _ => Vec::new(),
    };
    let text = |d: &Value, key: &str| d.get(key).and_then(Value::as_str).unwrap_or("").to_string();
    numbers
        .iter()
        .map(|number| {
            let device = list.iter().find(|d| text(d, "number") == *number || text(d, "prgDN") == *number);
            let kinds: Vec<String> = match device.and_then(|d| d.get("destTypes")).map(|t| t.get("attribute").unwrap_or(t)) {
                Some(Value::Array(items)) => items.iter().filter_map(Value::as_str).map(str::to_lowercase).collect(),
                Some(Value::String(one)) => vec![one.to_lowercase()],
                _ => Vec::new(),
            };
            // The softphone device is marked as such; other SIP devices of the user (type "PRG")
            // carry "sip" as well and must not be mistaken for it.
            let kind = device.map(|d| text(d, "type")).unwrap_or_default();
            Choice {
                number: number.clone(),
                label: device.map(|d| Some(text(d, "label")).filter(|l| !l.is_empty()).unwrap_or_else(|| kind.clone())).unwrap_or_default(),
                softphone: kinds.iter().any(|k| k == "softphone") || kind.eq_ignore_ascii_case("softphone"),
            }
        })
        .collect()
}

struct Http<'a> {
    client: reqwest::Client,
    verbose: bool,
    cfg: &'a MicollabConfig,
}

/// A JSON answer together with the `Date` header, which is part of the decryption key.
struct Answer {
    /// `Null` if the body was not JSON; `error_text` then holds the readable start of the body.
    json: Value,
    error_text: Option<String>,
    date: String,
    status: u16,
}

impl Answer {
    fn require_json(self, what: &str) -> Result<Answer> {
        match &self.error_text {
            Some(text) => bail!("{what}: Antwort (Status {}) ist kein JSON. Text der Antwort: {text}", self.status),
            None => Ok(self),
        }
    }
}

impl Http<'_> {
    async fn get(&self, url: &str, auth: Auth<'_>) -> Result<Answer> {
        if self.verbose {
            eprintln!("GET {url}");
        }
        let req = self.client.get(url);
        let req = match auth {
            Auth::Basic(user, password) => req.basic_auth(user, Some(password)),
            Auth::Bearer(token) => req.bearer_auth(token),
        };
        let rsp = req.send().await.with_context(|| format!("Anfrage an {url}"))?;
        let status = rsp.status().as_u16();
        let date = rsp.headers().get("date").and_then(|d| d.to_str().ok()).unwrap_or("").to_string();
        let text = rsp.text().await?;
        if status == 401 {
            bail!("Anmeldung am MiCollab-Server abgelehnt (401). Benutzername und Kennwort pruefen.");
        }
        if self.verbose {
            eprintln!("  -> Status {status}");
        }
        match serde_json::from_str(&text) {
            Ok(json) => Ok(Answer { json, error_text: None, date, status }),
            Err(_) => Ok(Answer { json: Value::Null, error_text: Some(excerpt(&text)), date, status }),
        }
    }
}

enum Auth<'a> {
    Basic(&'a str, &'a str),
    Bearer(&'a str),
}

pub async fn fetch(cfg: &MicollabConfig, password: &str, verbose: bool) -> Result<Profile> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(cfg.tls_insecure)
        .timeout(std::time::Duration::from_secs(20))
        .user_agent(cfg.user_agent.clone().unwrap_or_else(|| format!("miphone/{}", env!("CARGO_PKG_VERSION"))))
        .build()?;
    let http = Http { client, verbose, cfg };
    let login = login_name(&cfg.server, &cfg.user);
    let user = login.to_lowercase();

    // 1. contact id
    let url = format!("https://{}/ucs/json/JsonServlet", cfg.server);
    if verbose {
        eprintln!("POST {url} (GetAccountInfo)");
    }
    let rsp = http
        .client
        .post(&url)
        .basic_auth(&login, Some(password))
        .header("Content-type", "application/json")
        .body(r#"{"class":"com.mitel.ucs.ws.model.GetAccountInfo","method":"getAccountInfo","req":{}}"#)
        .send()
        .await
        .with_context(|| format!("Verbindung zum MiCollab-Server {}", cfg.server))?;
    if rsp.status().as_u16() == 401 {
        bail!("Anmeldung am MiCollab-Server abgelehnt (401). Benutzername und Kennwort pruefen.");
    }
    let status = rsp.status();
    let text = rsp.text().await?;
    // Some servers answer URL-encoded.
    let text = if text.starts_with('%') { percent_decode(&text) } else { text };
    let account: Value = serde_json::from_str(&text).with_context(|| format!("GetAccountInfo (Status {status}) lieferte kein JSON"))?;
    if let Some(err) = find_key(&account, "apperror").or_else(|| find_key(&account, "servererror")) {
        bail!("MiCollab-Server meldet einen Fehler: {err}");
    }
    if find_key(&account, "status").and_then(Value::as_str) == Some("Login failed") {
        bail!("Anmeldung am MiCollab-Server fehlgeschlagen. Benutzername und Kennwort pruefen.");
    }
    if verbose {
        eprintln!("Konto-Felder: {}", key_paths(&account).join(", "));
    }
    let contact_id = find_key(&account, "contactID")
        .map(scalar)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("GetAccountInfo enthaelt keine contactID (Felder: {})", key_paths(&account).join(", ")))?;

    // 2. deployment token. The login name in the path must be the one the server knows the
    // account by, which is not necessarily what the user typed; try the known spellings.
    let mut logins = vec![("micollab.user", user.clone())];
    for field in ["primaryEmail", "domainLogin"] {
        if let Some(v) = find_key(&account, field).map(scalar).map(|v| v.to_lowercase()).filter(|v| !v.is_empty()) {
            if !logins.iter().any(|(_, l)| *l == v) {
                logins.push((field, v));
            }
        }
    }
    if verbose {
        let flags = find_key(&account, "enableSelfDeploymentFlags").map(scalar).unwrap_or_else(|| "(fehlt)".into());
        eprintln!("Selbstbereitstellung laut Konto (enableSelfDeploymentFlags): {flags}");
    }
    let mut links = Value::Null;
    let mut failure = String::new();
    for (source, login) in &logins {
        if verbose {
            eprintln!("Anmeldename aus {source}");
        }
        let url = format!("https://{}/mdpapi/v1/getLink/{}/{}", cfg.server, url_encode(login), url_encode(&contact_id));
        let answer = http.get(&url, Auth::Basic(login, password)).await?;
        match answer.error_text {
            None => {
                links = answer.json;
                break;
            }
            Some(text) => failure = format!("Status {}: {text}", answer.status),
        }
    }
    if links.is_null() {
        bail!("Der Server liefert keinen Bereitstellungslink ({} Anmeldenamen versucht). Letzte Antwort: {failure}", logins.len());
    }
    if let Some(e) = links.get("error") {
        bail!("Der Server stellt keine Bereitstellungsdaten aus: {e}");
    }
    let links = links.as_array().filter(|a| !a.is_empty()).ok_or_else(|| anyhow!("Keine Bereitstellung fuer dieses Konto vorhanden"))?;
    let dn_of = |l: &Value| l.get("dn").map(scalar).unwrap_or_default();
    let link = match &http.cfg.number {
        Some(n) => links.iter().find(|l| &dn_of(l) == n).ok_or_else(|| {
            anyhow!("Keine Bereitstellung fuer Nummer {n}; vorhanden: {}", links.iter().map(dn_of).collect::<Vec<_>>().join(", "))
        })?,
        None if links.len() == 1 => &links[0],
        None => {
            // Several extensions: which one is right differs from system to system, so the
            // user decides. The device list only serves to describe the choices.
            let numbers: Vec<String> = links.iter().map(dn_of).collect();
            let destinations = http
                .client
                .post(format!("https://{}/ucs/json/JsonServlet", cfg.server))
                .basic_auth(&login, Some(password))
                .header("Content-type", "application/json")
                .body(r#"{"class":"com.mitel.ucs.ws.model.GetDestinations","method":"getDestinations","req":{}}"#)
                .send()
                .await;
            let destinations = match destinations {
                Ok(rsp) => rsp.text().await.ok().and_then(|t| serde_json::from_str(&if t.starts_with('%') { percent_decode(&t) } else { t }).ok()),
                Err(_) => None,
            };
            let choices = label_choices(&numbers, &destinations.unwrap_or(Value::Null));
            if verbose {
                for c in &choices {
                    eprintln!("Bereitstellung {} ({}){}", c.number, c.label, if c.softphone { " - Softphone" } else { "" });
                }
            }
            return Err(anyhow::Error::new(MultipleDeployments(choices)));
        }
    };
    let number = Some(dn_of(link)).filter(|d| !d.is_empty());
    let link_url = link.get("link").and_then(Value::as_str).unwrap_or("");
    let (deploy_host, token) = parse_deploy_link(link_url).ok_or_else(|| anyhow!("Unerwartetes Format des Bereitstellungslinks"))?;

    // 3. config token and config server
    let base = format!("https://{deploy_host}/mdpapi/v1/getTokenAndUrl");
    let mut answer = http.get(&base, Auth::Bearer(&token)).await?;
    if answer.error_text.is_some() {
        // Not an encrypted answer at all; fall through to the old API below.
        answer.json = Value::Null;
    }
    let mut info = open(&answer, "tokenAndUrl", "v1/getTokenAndUrl", &token);
    if info.as_ref().is_none_or(|i| i.get("configtoken").is_none()) {
        // Servers before 9.2 take the token in the path and answer in plain JSON.
        answer = http.get(&format!("{base}/{token}"), Auth::Bearer(&token)).await?.require_json("getTokenAndUrl")?;
        info = Some(answer.json.clone());
    }
    let info = info.unwrap_or(Value::Null);
    let config_token = info.get("configtoken").and_then(Value::as_str);
    let config_url = info.get("url").and_then(Value::as_str);
    let (Some(config_token), Some(config_url)) = (config_token, config_url) else {
        bail!("Kein Konfigurations-Token erhalten (Status {}, Felder: {})", answer.status, key_paths(&info).join(", "));
    };
    let config_host = config_url.split("://").last().unwrap_or(config_url).split('/').next().unwrap_or("");

    // 4. profile
    let base = format!("https://{config_host}/mdpapi/v1/getconfigforuser");
    let query = format!("?version={CLIENT_VERSION}");
    let answer = http.get(&format!("{base}{query}"), Auth::Bearer(config_token)).await?;
    let mut profile = open(&answer, "config", "v1/getconfigforuser", config_token);
    if profile.as_ref().is_none_or(|p| p.get("error").is_some()) {
        let old = http.get(&format!("{base}/{config_token}{query}"), Auth::Bearer(config_token)).await?.require_json("getconfigforuser")?;
        profile = Some(old.json);
    }
    let profile = profile.unwrap_or(Value::Null);
    if let Some(e) = profile.get("error") {
        bail!("Der Konfigurationsserver lehnt ab: {e}");
    }
    if verbose {
        eprintln!("Profil-Felder: {}", key_paths(&profile).join(", "));
    }
    let mut p = extract(&profile, cfg.teleworker)?;
    p.number = number;
    Ok(p)
}

/// Returns the usable JSON of an answer: decrypted if it carries `field` and a nonce, as is otherwise.
fn open(answer: &Answer, field: &str, path: &str, token: &str) -> Option<Value> {
    match (answer.json.get(field).and_then(Value::as_str), answer.json.get("nonce").map(scalar)) {
        (Some(payload), Some(nonce)) => decrypt(payload, path, &answer.date, token, &nonce),
        _ => Some(answer.json.clone()),
    }
}

/// Decrypts a response body: AES-256-CBC, IV in the first 16 bytes, key = SHA-256 over
/// path, the `Date` header with seconds set to zero, bearer token and nonce.
/// The server may have computed the key a minute earlier, so that is tried as well.
fn decrypt(payload_b64: &str, path: &str, date: &str, token: &str, nonce: &str) -> Option<Value> {
    if date.len() != 29 {
        return None;
    }
    let raw = base64::engine::general_purpose::STANDARD.decode(payload_b64.trim()).ok()?;
    if raw.len() < 32 || raw.len() % 16 != 0 {
        return None;
    }
    let earlier = httpdate::parse_http_date(date)
        .ok()
        .and_then(|t| t.checked_sub(std::time::Duration::from_secs(60)))
        .map(httpdate::fmt_http_date);
    for d in std::iter::once(date.to_string()).chain(earlier) {
        let key = Sha256::digest(format!("{path}{}00 GMT{token}{nonce}", &d[..23]).as_bytes());
        let plain = aes256_cbc_decrypt(&key, &raw[..16], &raw[16..]);
        // PKCS#7 padding; tolerate its absence.
        let pad = *plain.last()? as usize;
        let end = if (1..=16).contains(&pad) && pad <= plain.len() { plain.len() - pad } else { plain.len() };
        if let Ok(v) = serde_json::from_slice::<Value>(&plain[..end]) {
            return Some(v);
        }
    }
    None
}

fn aes256_cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
    let cipher = aes::Aes256::new_from_slice(key).expect("SHA-256 output is a valid AES-256 key");
    let mut out = Vec::with_capacity(data.len());
    let mut prev = iv.to_vec();
    for chunk in data.chunks_exact(16) {
        let mut block = aes::Block::default();
        block.copy_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        out.extend(block.iter().zip(&prev).map(|(b, p)| b ^ p));
        prev = chunk.to_vec();
    }
    out
}

/// `micollab://edd?deployu=<host>&token=<token>` -> (host, token)
fn parse_deploy_link(link: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = link.split(['?', '&', '=']).collect();
    if parts.len() >= 5
        && parts[0].to_ascii_lowercase().starts_with("micollab://edd")
        && parts[1].eq_ignore_ascii_case("deployu")
        && parts[3].eq_ignore_ascii_case("token")
    {
        Some((parts[2].to_string(), parts[4].to_string()))
    } else {
        None
    }
}

/// Picks the SIP account out of the profile. Key names arrive with spaces or underscores,
/// leaves either plain or wrapped as `{access, value}`, teleworker keys optionally prefixed.
///
/// Which account is used follows the Mitel client: `general.use_teleworker` decides (on if
/// the profile does not say), and the user may overrule it with `teleworker` if the
/// profile's access flags leave the setting to them.
fn extract(profile: &Value, teleworker: Option<bool>) -> Result<Profile> {
    let mut flat = Vec::new();
    flatten(profile, String::new(), &mut flat);
    let get = |section: &str, key: &str| -> Option<String> {
        flat.iter()
            .find(|(path, _)| {
                let mut segs = path.rsplit('.');
                let last = segs.next().unwrap_or("");
                (last == key || last.strip_prefix(&format!("{section}_")) == Some(key)) && segs.any(|s| s == section)
            })
            .map(|(_, v)| v.clone())
            .filter(|v| !v.is_empty())
    };
    let truthy = |v: Option<String>| v.is_some_and(|v| v.eq_ignore_ascii_case("true") || v == "1");
    let softphone = get("general", "use_softphone");
    if softphone.is_some() && !truthy(softphone) {
        bail!("Im Profil ist das Softphone nicht aktiviert (general.use_softphone).");
    }
    let account = |section: &str| -> Result<Account> {
        let what = if section == "teleworker" { "Teleworker-Konto (MBG)" } else { "Konto an der Telefonanlage" };
        let (Some(server), Some(user), Some(password)) =
            (get(section, "sip_proxy_ip"), get(section, "sip_user_name"), get(section, "sip_password"))
        else {
            let names: Vec<&str> = flat.iter().map(|(p, _)| p.as_str()).filter(|p| p.split('.').any(|s| s == section)).collect();
            bail!("Das {what} ist im Profil nicht vollstaendig (vorhandene Felder: {})", names.join(", "));
        };
        let transport = get(section, "sip_transport_protocol").unwrap_or_else(|| "TLS".into());
        if !transport.eq_ignore_ascii_case("tls") {
            bail!("Das {what} verlangt den Transport {transport}; unterstuetzt wird nur TLS.");
        }
        if get(section, "sip_srtp_mode").is_some_and(|m| m.eq_ignore_ascii_case("mandatory")) {
            bail!("Das {what} verlangt SRTP; das wird noch nicht unterstuetzt.");
        }
        // No port means 5060 to the Mitel client; port 0 means "look the server up via DNS SRV".
        let port_of = |key: &str| -> Result<u16> {
            match get(section, key) {
                None => Ok(5060),
                Some(p) => match p.trim().parse::<u16>() {
                    Ok(0) => bail!("Das {what} verlangt die Suche des Servers ueber DNS (SRV, Port 0); das wird noch nicht unterstuetzt."),
                    Ok(port) => Ok(port),
                    Err(_) => bail!("Das {what} nennt einen ungueltigen Port ({key})."),
                },
            }
        };
        let outbound_proxy = match get(section, "sip_outbound_proxy") {
            // With a proxy only its port matters; the registrar is not looked up.
            Some(host) => Some((host, port_of("sip_outbound_proxy_port")?)),
            None => None,
        };
        let port = if outbound_proxy.is_some() { get(section, "sip_proxy_port").and_then(|p| p.trim().parse().ok()).filter(|p| *p != 0).unwrap_or(5060) } else { port_of("sip_proxy_port")? };
        Ok(Account { server, port, outbound_proxy, user, password, ca_chain: get(section, "sip_tls_ca_chain") })
    };
    let by_profile = get("general", "use_teleworker").map(|v| truthy(Some(v))).unwrap_or(true);
    // Bits 2 and 8 of the access flags leave a setting to the user; without flags it is theirs.
    let selectable = access_of(profile, "general", "use_teleworker").is_none_or(|flags| flags & 10 != 0);
    let use_teleworker = teleworker.filter(|_| selectable).unwrap_or(by_profile);
    let (chosen, alternative) = if use_teleworker { ("teleworker", "pbx") } else { ("pbx", "teleworker") };
    let other = if selectable { account(alternative).ok() } else { None };
    let account = account(chosen).map_err(|e| match &other {
        Some(_) => e.context(format!(
            "Das Profil sieht {} vor. Das andere Konto ist vorhanden: \"Teleworker verwenden\" umschalten (micollab.teleworker).",
            if use_teleworker { "die Anmeldung als Teleworker" } else { "die Anmeldung direkt an der Telefonanlage" }
        )),
        None => e,
    })?;
    Ok(Profile { account, teleworker: use_teleworker, other, number: None, acd: truthy(get("general", "is_acd")) })
}

/// Access flags of a profile setting, if the profile carries them (`{access, value}`).
fn access_of(profile: &Value, section: &str, key: &str) -> Option<u32> {
    let find = |v: &Value, name: &str| v.as_object().and_then(|map| map.iter().find(|(k, _)| normalise(k) == name).map(|(_, child)| child.clone()));
    let access = find(&find(profile, section)?, key)?.get("access")?.clone();
    access.as_u64().map(|a| a as u32).or_else(|| access.as_str()?.trim().parse().ok())
}

fn normalise(key: &str) -> String {
    key.trim().to_ascii_lowercase().replace(' ', "_")
}

fn flatten(v: &Value, path: String, out: &mut Vec<(String, String)>) {
    match v {
        Value::Object(map) => {
            if let Some(inner) = map.get("value").filter(|i| !i.is_object() && !i.is_array()) {
                out.push((path, scalar(inner)));
                return;
            }
            for (k, child) in map {
                let p = if path.is_empty() { normalise(k) } else { format!("{path}.{}", normalise(k)) };
                flatten(child, p, out);
            }
        }
        Value::Array(_) | Value::Null => {}
        other => out.push((path, scalar(other))),
    }
}

/// Field names of a JSON document without their values, for diagnostics.
fn key_paths(v: &Value) -> Vec<String> {
    let mut flat = Vec::new();
    flatten(v, String::new(), &mut flat);
    flat.into_iter().map(|(p, _)| p).collect()
}

fn scalar(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

pub(crate) fn find_key<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    match v {
        Value::Object(map) => map.get(key).or_else(|| map.values().find_map(|c| find_key(c, key))),
        Value::Array(items) => items.iter().find_map(|c| find_key(c, key)),
        _ => None,
    }
}

/// Readable start of a non-JSON answer (usually an HTML error page): tags removed, whitespace collapsed.
fn excerpt(text: &str) -> String {
    let mut plain = String::new();
    let mut in_tag = false;
    for c in text.chars() {
        match c {
            '<' => in_tag = true,
            '>' => {
                in_tag = false;
                plain.push(' ');
            }
            c if !in_tag => plain.push(c),
            _ => {}
        }
    }
    let words: Vec<&str> = plain.split_whitespace().collect();
    let joined = words.join(" ");
    if joined.is_empty() {
        return "(leer)".to_string();
    }
    joined.chars().take(400).collect()
}

fn url_encode(s: &str) -> String {
    s.bytes()
        .map(|b| if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") })
        .collect()
}

pub(crate) fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = bytes.get(i + 1..i + 3).and_then(|h| std::str::from_utf8(h).ok());
                match hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    Some(b) => {
                        out.push(b);
                        i += 3;
                    }
                    None => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::BlockCipherEncrypt;

    fn encrypt(plain: &[u8], path: &str, date: &str, token: &str, nonce: &str) -> String {
        let key = Sha256::digest(format!("{path}{}00 GMT{token}{nonce}", &date[..23]).as_bytes());
        let cipher = aes::Aes256::new_from_slice(&key).unwrap();
        let pad = 16 - plain.len() % 16;
        let mut data = plain.to_vec();
        data.extend(std::iter::repeat(pad as u8).take(pad));
        let iv = [7u8; 16];
        let mut out = iv.to_vec();
        let mut prev = iv.to_vec();
        for chunk in data.chunks(16) {
            let mut block = aes::Block::default();
            for (i, b) in chunk.iter().enumerate() {
                block[i] = b ^ prev[i];
            }
            cipher.encrypt_block(&mut block);
            prev = block.to_vec();
            out.extend_from_slice(&block);
        }
        base64::engine::general_purpose::STANDARD.encode(out)
    }

    #[test]
    fn decrypts_with_current_and_previous_minute() {
        let json = br#"{"configtoken":"abc","url":"https://cfg.example.org/x"}"#;
        let payload = encrypt(json, "v1/getTokenAndUrl", "Thu, 26 Nov 2026 10:24:26 GMT", "tok", "42");
        let v = decrypt(&payload, "v1/getTokenAndUrl", "Thu, 26 Nov 2026 10:24:59 GMT", "tok", "42").unwrap();
        assert_eq!(v["configtoken"], "abc");
        // Key computed by the server just before the minute changed.
        let v = decrypt(&payload, "v1/getTokenAndUrl", "Thu, 26 Nov 2026 10:25:01 GMT", "tok", "42").unwrap();
        assert_eq!(v["url"], "https://cfg.example.org/x");
        assert!(decrypt(&payload, "v1/getTokenAndUrl", "Thu, 26 Nov 2026 10:27:01 GMT", "tok", "42").is_none());
        assert!(decrypt(&payload, "v1/getconfigforuser", "Thu, 26 Nov 2026 10:24:26 GMT", "tok", "42").is_none());
        assert!(decrypt("not base64!", "p", "Thu, 26 Nov 2026 10:24:26 GMT", "t", "n").is_none());
    }

    #[test]
    fn labels_deployments_from_device_list() {
        let destinations: Value = serde_json::from_str(
            r#"{"result":{"destination":[
                {"id":1,"number":"81002","label":"Tischtelefon","type":"DeskPhone","destTypes":{"attribute":["deskphone","prg","mdug","hotdesk"]}},
                {"id":2,"number":"8*1002","label":"Softphone","type":"SoftPhone","destTypes":{"attribute":["softphone","prg","mdug","sip"]}},
                {"id":3,"number":"0170","label":"","type":"PRG","prgDN":"8#1002","destTypes":{"attribute":["prg","mdug","sip"]}}
            ]}}"#,
        )
        .unwrap();
        let numbers = ["8*1002".to_string(), "81002".into(), "8#1002".into(), "999".into()];
        let choices = label_choices(&numbers, &destinations);
        assert_eq!(choices[0], Choice { number: "8*1002".into(), label: "Softphone".into(), softphone: true });
        assert_eq!(choices[1], Choice { number: "81002".into(), label: "Tischtelefon".into(), softphone: false });
        assert_eq!((choices[2].label.as_str(), choices[2].softphone), ("PRG", false), "matched by its PRG number; a SIP device, but not the softphone");
        assert_eq!(choices.iter().filter(|c| c.softphone).count(), 1, "only the device marked as softphone counts as one");
        assert_eq!(choices[3], Choice { number: "999".into(), label: String::new(), softphone: false });
        // Without a device list the numbers are offered as they are.
        assert!(label_choices(&numbers, &Value::Null).iter().all(|c| c.label.is_empty() && !c.softphone));
        let message = MultipleDeployments(choices).to_string();
        assert!(message.contains("8*1002, 81002"), "{message}");
    }

    #[test]
    fn parses_deploy_link() {
        assert_eq!(
            parse_deploy_link("micollab://edd?deployu=pbx.example.org&token=abc123"),
            Some(("pbx.example.org".to_string(), "abc123".to_string()))
        );
        assert_eq!(parse_deploy_link("https://example.org/?deployu=a&token=b"), None);
    }

    const PROFILE: &str = r#"{
      "general": {"use softphone": "true", "use teleworker": "true"},
      "accounts": {"name of account": {
        "pbx": {"type": "MCD", "sip user name": "1000", "sip password": "pbxpw", "sip proxy ip": "pbx.local", "sip proxy port": "0", "sip transport protocol": "TLS"},
        "teleworker": {"teleworker type": "MBG", "teleworker sip user name": "alice@example.org-1000", "teleworker sip password": "twpw",
                       "teleworker sip proxy ip": "mbg.example.org", "teleworker sip proxy port": "5061", "teleworker sip transport protocol": "TLS", "teleworker sip srtp mode": "OFF"}
      }}
    }"#;

    fn account(server: &str, port: u16, user: &str, password: &str) -> Account {
        Account { server: server.into(), port, outbound_proxy: None, user: user.into(), password: password.into(), ca_chain: None }
    }

    #[test]
    fn extracts_teleworker_account() {
        let p = extract(&serde_json::from_str(PROFILE).unwrap(), None).unwrap();
        // The PBX account needs DNS SRV (port 0), so there is nothing to switch to.
        assert_eq!(p, Profile { account: account("mbg.example.org", 5061, "alice@example.org-1000", "twpw"), teleworker: true, other: None, number: None, acd: false });
        // Asking for the PBX account does not silently fall back to the gateway.
        let e = format!("{:#}", extract(&serde_json::from_str(PROFILE).unwrap(), Some(false)).unwrap_err());
        assert!(e.contains("DNS") && e.contains("Telefonanlage"), "{e}");
    }

    #[test]
    fn extracts_wrapped_values_and_honours_pbx_preference() {
        let text = r#"{"general": {"use_teleworker": {"access": ACCESS, "value": false}},
                "accounts": {"name_of_account": {
                  "pbx": {"sip_user_name": {"access": 1, "value": "1000"}, "sip_password": {"value": "pw"}, "sip_proxy_ip": {"value": "pbx.local"}, "sip_proxy_port": {"value": 5061}},
                  "teleworker": {"sip_user_name": {"value": "t"}, "sip_password": {"value": "tp"}, "sip_proxy_ip": {"value": "mbg"}, "sip_proxy_port": {"value": "5061"}}}}}"#;
        // Access flags without the user bits: the profile's choice stands, whatever the user wants.
        let fixed: Value = serde_json::from_str(&text.replace("ACCESS", "\"20\"")).unwrap();
        for wish in [None, Some(true)] {
            let p = extract(&fixed, wish).unwrap();
            assert_eq!((p.account.server.as_str(), p.account.user.as_str(), p.teleworker, &p.other), ("pbx.local", "1000", false, &None));
        }
        // With them (15, as the server sends it) the user may switch, in both directions.
        let open: Value = serde_json::from_str(&text.replace("ACCESS", "15")).unwrap();
        let mut p = extract(&open, None).unwrap();
        assert_eq!((p.account.server.as_str(), p.teleworker), ("pbx.local", false));
        assert_eq!(p.other, Some(account("mbg", 5061, "t", "tp")));
        assert_eq!(extract(&open, Some(true)).unwrap().account, account("mbg", 5061, "t", "tp"));
        assert!(p.switch());
        assert_eq!((p.account.server.as_str(), p.teleworker, p.other.as_ref().map(|o| o.server.as_str())), ("mbg", true, Some("pbx.local")));
        assert!(p.switch() && !p.teleworker);
        p.other = None;
        assert!(!p.switch() && !p.teleworker);
    }

    #[test]
    fn extracts_pbx_account_with_its_certificate_chain() {
        // An office account as the server delivers it: registered directly at the PBX by IP address.
        let v: Value = serde_json::from_str(
            r#"{"general": {"use softphone": true, "is acd": false, "use teleworker": false},
                "accounts": {"name of account": {
                  "pbx": {"sip user name": "8*1001", "sip password": "pw", "sip proxy ip": "10.0.0.9", "sip proxy port": "5061",
                          "sip transport protocol": "TLS", "sip tls check enabled": "1", "sip tls ca chain": "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"},
                  "teleworker": {"teleworker sip user name": "a@b-8*1001", "teleworker sip password": "tp", "teleworker sip proxy ip": "mbg.example.org", "teleworker sip proxy port": "5061"}}}}"#,
        )
        .unwrap();
        let p = extract(&v, None).unwrap();
        assert_eq!((p.account.server.as_str(), p.account.port, p.account.user.as_str(), p.teleworker, p.acd), ("10.0.0.9", 5061, "8*1001", false, false));
        assert!(p.account.ca_chain.unwrap().contains("BEGIN CERTIFICATE"));
        assert_eq!(p.other, Some(account("mbg.example.org", 5061, "a@b-8*1001", "tp")));
    }

    #[test]
    fn agent_and_office_profiles_pick_their_own_server() {
        // Both kinds of account carry both sections; only `use teleworker` tells them apart.
        let profile = |acd: bool, teleworker: bool| -> Value {
            let text = r#"{"general": {"use softphone": {"access": "15", "value": true}, "is acd": {"access": "16", "value": ACD}, "use teleworker": {"access": "15", "value": TELEWORKER}},
                "accounts": {"name of account": {
                  "pbx": {"type": "MCD", "sip user name": "8*1", "sip password": "p", "sip proxy ip": "10.0.0.9", "sip proxy port": "5061"},
                  "teleworker": {"teleworker type": "MBG", "teleworker sip user name": "a@b-8*1", "teleworker sip password": "t", "teleworker sip proxy ip": "mbg.example.org", "teleworker sip proxy port": "5061"}}}}"#;
            serde_json::from_str(&text.replace("ACD", &acd.to_string()).replace("TELEWORKER", &teleworker.to_string())).unwrap()
        };
        let agent = extract(&profile(true, true), None).unwrap();
        assert_eq!((agent.account.server.as_str(), agent.account.user.as_str(), agent.teleworker, agent.acd), ("mbg.example.org", "a@b-8*1", true, true));
        let office = extract(&profile(false, false), None).unwrap();
        assert_eq!((office.account.server.as_str(), office.account.user.as_str(), office.teleworker, office.acd), ("10.0.0.9", "8*1", false, false));
        // The user's own choice wins over the profile's, for either kind.
        let office_at_home = extract(&profile(false, false), Some(true)).unwrap();
        assert_eq!((office_at_home.account.server.as_str(), office_at_home.teleworker, office_at_home.acd), ("mbg.example.org", true, false));
        let agent_in_office = extract(&profile(true, true), Some(false)).unwrap();
        assert_eq!((agent_in_office.account.server.as_str(), agent_in_office.teleworker, agent_in_office.acd), ("10.0.0.9", false, true));
    }

    #[test]
    fn never_substitutes_the_other_account() {
        // The profile asks for the PBX, whose account is missing: an error, not the gateway.
        let text = r#"{"general": {"use teleworker": {"access": ACCESS, "value": false}},
                "accounts": {"x": {"pbx": {"sip password": "geheim"},
                  "teleworker": {"sip user name": "t", "sip password": "tp", "sip proxy ip": "mbg", "sip proxy port": "5061"}}}}"#;
        let v: Value = serde_json::from_str(&text.replace("ACCESS", "20")).unwrap();
        let e = format!("{:#}", extract(&v, None).unwrap_err());
        assert!(e.contains("accounts.x.pbx.sip_password") && !e.contains("geheim") && !e.contains("umschalten"), "{e}");
        // If the user may switch, the message says so.
        let v: Value = serde_json::from_str(&text.replace("ACCESS", "15")).unwrap();
        let e = format!("{:#}", extract(&v, None).unwrap_err());
        assert!(e.contains("umschalten") && !e.contains("geheim"), "{e}");
        assert_eq!(extract(&v, Some(true)).unwrap().account.server, "mbg");
        let v: Value = serde_json::from_str(r#"{"general": {"use softphone": "false"}}"#).unwrap();
        assert!(extract(&v, None).is_err());
    }

    #[test]
    fn connects_through_outbound_proxy_and_defaults_port() {
        let v: Value = serde_json::from_str(
            r#"{"general": {"use teleworker": false},
                "accounts": {"x": {"pbx": {"sip user name": "1", "sip password": "p", "sip proxy ip": "pbx.local", "sip proxy port": "0",
                                           "sip outbound proxy": "edge.example.org", "sip outbound proxy port": "5071"},
                  "teleworker": {"sip user name": "t", "sip password": "tp", "sip proxy ip": "mbg"}}}}"#,
        )
        .unwrap();
        let p = extract(&v, None).unwrap();
        assert_eq!((p.account.server.as_str(), p.account.outbound_proxy.clone()), ("pbx.local", Some(("edge.example.org".to_string(), 5071))));
        assert_eq!(p.other.unwrap().port, 5060, "no port given");
    }

    #[test]
    fn strips_server_from_login_name() {
        assert_eq!(login_name("mc.example.org", " alice@MC.example.org "), "alice");
        assert_eq!(login_name("mc.example.org", "alice@example.org"), "alice@example.org");
        assert_eq!(login_name("mc.example.org", "@mc.example.org"), "@mc.example.org");
        assert_eq!(login_name("mc.example.org", "alice"), "alice");
    }

    #[test]
    fn excerpts_error_pages() {
        assert_eq!(excerpt("<html>\n<body><h1>500  Internal</h1>\n<p>oops</p></body></html>"), "500 Internal oops");
        assert_eq!(excerpt("\n\n"), "(leer)");
        assert_eq!(excerpt(&"x".repeat(1000)).len(), 400);
    }

    #[test]
    fn encodes_and_decodes() {
        assert_eq!(url_encode("alice@example.org"), "alice%40example.org");
        assert_eq!(percent_decode("%7B%22a%22%3A+1%7D"), "{\"a\": 1}");
        assert_eq!(percent_decode("100%"), "100%");
    }
}
