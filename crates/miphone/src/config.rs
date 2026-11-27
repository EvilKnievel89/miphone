use anyhow::{bail, Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// MiCollab server login; the SIP account is then downloaded from the server.
    pub micollab: Option<MicollabConfig>,
    /// SIP settings. Server, user and password may be left out when `[micollab]` is given.
    #[serde(default)]
    pub sip: SipConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MicollabConfig {
    /// Host name of the MiCollab server.
    pub server: String,
    /// Login name as used in the MiCollab client.
    pub user: String,
    /// Value of the HTTP User-Agent header for requests to the MiCollab server.
    pub user_agent: Option<String>,
    /// Extension to use if the account has several deployments.
    pub number: Option<String>,
    /// Register through the border gateway (true) or directly at the PBX (false) instead of
    /// what the profile suggests. Only honoured if the profile leaves the choice to the user.
    pub teleworker: Option<bool>,
    /// Accept invalid TLS certificates. Only for testing.
    #[serde(default)]
    pub tls_insecure: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SipConfig {
    /// SIP server (MBG or PBX) host name; also used for TLS certificate validation.
    #[serde(default)]
    pub server: String,
    /// Port 0 looks the servers up via DNS (SRV records `_sips._tcp.<server>`).
    #[serde(default)]
    pub port: Option<u16>,
    /// Host to connect to if it is not the SIP server itself.
    pub outbound_proxy: Option<String>,
    pub outbound_proxy_port: Option<u16>,
    /// SIP user name, e.g. `user@example.org-1234`.
    #[serde(default)]
    pub user: String,
    /// User name for digest authentication if it differs from `user`.
    pub auth_user: Option<String>,
    /// SIP password. Alternatively set the environment variable `MIPHONE_SIP_PASSWORD`.
    pub password: Option<String>,
    /// Value of the User-Agent header. Default: the device name of a Mitel UC endpoint.
    pub user_agent: Option<String>,
    /// Full value of the `X-Aastra-Id` header. Default: the device type of the MiCollab
    /// softphone; an empty string leaves the header out.
    pub aastra_id: Option<String>,
    /// The account is an ACD agent; the Mitel client then presents itself as single-line device.
    #[serde(default)]
    pub acd: bool,
    /// Audio codecs to use, in the order we offer them: "opus", "PCMA", "PCMU".
    #[serde(default = "default_codecs")]
    pub codecs: Vec<String>,
    /// Requested registration lifetime in seconds.
    #[serde(default = "default_expires")]
    pub expires: u32,
    /// Subscribe to the `mihotdesk` event after registering, as the Mitel client does.
    #[serde(default = "default_true")]
    pub hotdesk_subscribe: bool,
    /// Accept invalid TLS certificates (self-signed, wrong name). Only for testing.
    #[serde(default)]
    pub tls_insecure: bool,
    /// Certificates in PEM format to trust as issuers of the SIP server's certificate, in
    /// addition to those Windows trusts. The provisioning profile supplies them for PBXs
    /// with a private certificate authority.
    pub tls_ca_chain: Option<String>,
}

impl Default for SipConfig {
    fn default() -> Self {
        SipConfig {
            server: String::new(),
            port: None,
            outbound_proxy: None,
            outbound_proxy_port: None,
            user: String::new(),
            auth_user: None,
            password: None,
            user_agent: None,
            aastra_id: None,
            acd: false,
            codecs: default_codecs(),
            expires: default_expires(),
            hotdesk_subscribe: true,
            tls_insecure: false,
            tls_ca_chain: None,
        }
    }
}

fn default_codecs() -> Vec<String> {
    ["opus", "PCMA", "PCMU"].map(String::from).to_vec()
}
fn default_expires() -> u32 {
    1800
}
fn default_true() -> bool {
    true
}

impl Config {
    pub fn load(path: &str) -> Result<Config> {
        let text = std::fs::read_to_string(path).with_context(|| format!("Konfigurationsdatei {path} nicht lesbar"))?;
        Self::parse(&text).with_context(|| format!("Konfigurationsdatei {path} fehlerhaft"))
    }

    fn parse(text: &str) -> Result<Config> {
        let cfg: Config = toml::from_str(text)?;
        if let Some(m) = &cfg.micollab {
            if m.server.is_empty() || m.user.is_empty() {
                bail!("micollab.server und micollab.user muessen gesetzt sein");
            }
        } else if cfg.sip.server.is_empty() || cfg.sip.user.is_empty() {
            bail!("Entweder [micollab] angeben oder sip.server und sip.user setzen");
        }
        if let Some(bad) = cfg.sip.codecs.iter().find(|c| crate::media::AudioCodec::from_name(c).is_none()) {
            bail!("Unbekannter Codec \"{bad}\" in sip.codecs; moeglich sind opus, PCMA, PCMU");
        }
        if cfg.sip.codecs.is_empty() {
            bail!("sip.codecs darf nicht leer sein");
        }
        Ok(cfg)
    }
}

impl SipConfig {
    pub fn port(&self) -> u16 {
        self.port.unwrap_or(5061)
    }

    /// The server as it stands in SIP addresses. A server found via DNS has no port there.
    pub fn host_port(&self) -> String {
        match self.port() {
            0 => self.server.clone(),
            port => format!("{}:{port}", self.server),
        }
    }

    /// Host and port the connection goes to: the outbound proxy if there is one. Port 0
    /// stands for the servers DNS names for that host.
    pub fn connect_to(&self) -> (&str, u16) {
        match self.outbound_proxy.as_deref().filter(|p| !p.is_empty()) {
            Some(proxy) => (proxy, self.outbound_proxy_port.unwrap_or(5061)),
            None => (&self.server, self.port()),
        }
    }

    /// Takes over the SIP account of a provisioning profile.
    pub fn use_account(&mut self, account: &crate::provision::Account) {
        self.server = account.server.clone();
        self.port = Some(account.port);
        (self.outbound_proxy, self.outbound_proxy_port) = match &account.outbound_proxy {
            Some((host, port)) => (Some(host.clone()), Some(*port)),
            None => (None, None),
        };
        self.user = account.user.clone();
        self.tls_ca_chain = account.ca_chain.clone();
    }

    /// The certificates of `tls_ca_chain`, one PEM block each.
    pub fn ca_certificates(&self) -> Vec<String> {
        const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
        const END: &str = "-----END CERTIFICATE-----";
        let text = self.tls_ca_chain.as_deref().unwrap_or("").replace("\\n", "\n");
        let mut blocks = Vec::new();
        let mut rest = text.as_str();
        while let Some(start) = rest.find(BEGIN) {
            let Some(len) = rest[start..].find(END) else { break };
            let end = start + len + END.len();
            blocks.push(format!("{}\n", &rest[start..end]));
            rest = &rest[end..];
        }
        blocks
    }

    /// Password from the environment or the file, if any.
    pub fn password(&self) -> Option<String> {
        std::env::var("MIPHONE_SIP_PASSWORD").ok().or_else(|| self.password.clone()).filter(|p| !p.is_empty())
    }

    /// The server only accepts registrations from device types it knows for the extension
    /// ("Incompatible device type" otherwise), so by default we present ourselves like the
    /// MiCollab softphone does: as a Mitel UC endpoint.
    pub fn user_agent(&self) -> String {
        self.user_agent.clone().unwrap_or_else(|| {
            let device = if self.acd { "Mitel-Single-Line-UC-Endpoint" } else { "Mitel-UC-Endpoint" };
            format!("{device} (UCA_Win10/10.3.8/undefined/Microsoft Windows NT 10.0)")
        })
    }

    /// Value of the `X-Aastra-Id` header (device type, model, version and a device id), if any.
    pub fn aastra_id(&self) -> Option<String> {
        match &self.aastra_id {
            Some(explicit) => Some(explicit.clone()).filter(|v| !v.trim().is_empty()),
            None => Some(format!("type=\"32\" model=\"02\" version=\"10.3.8.0\" mac=\"{}\"", self.device_id())),
        }
    }

    /// Twelve hex digits that identify this installation: stable per computer, Windows user
    /// and SIP account, without revealing any of them.
    fn device_id(&self) -> String {
        let computer = std::env::var("COMPUTERNAME").unwrap_or_default();
        let windows_user = std::env::var("USERNAME").unwrap_or_default();
        misip::digest::md5_hex(format!("miphone|{computer}|{windows_user}|{}", self.user).as_bytes())[..12].to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_micollab_only_and_sip_only() {
        let c = Config::parse("[micollab]\nserver = \"mc.example.org\"\nuser = \"alice\"\n").unwrap();
        assert!(c.sip.server.is_empty() && c.sip.hotdesk_subscribe && c.sip.expires == 1800 && c.sip.port() == 5061);
        let c = Config::parse("[sip]\nserver = \"s\"\nuser = \"u\"\nport = 5071\n").unwrap();
        assert!(c.micollab.is_none() && c.sip.port() == 5071);
        assert_eq!(c.sip.connect_to(), ("s", 5071));
        let c = Config::parse("[sip]
server = \"s\"
user = \"u\"
outbound_proxy = \"edge\"
outbound_proxy_port = 5081
").unwrap();
        assert_eq!((c.sip.connect_to(), c.sip.port()), (("edge", 5081), 5061));
        let c = Config::parse("[micollab]
server = \"m\"
user = \"u\"
teleworker = false
").unwrap();
        assert_eq!(c.micollab.unwrap().teleworker, Some(false));
    }

    #[test]
    fn identifies_as_uc_endpoint_by_default() {
        let mut c = Config::parse("[sip]\nserver = \"s\"\nuser = \"u\"\n").unwrap().sip;
        assert_eq!(c.user_agent(), "Mitel-UC-Endpoint (UCA_Win10/10.3.8/undefined/Microsoft Windows NT 10.0)");
        let id = c.aastra_id().unwrap();
        assert!(id.starts_with("type=\"32\" model=\"02\" version=\"10.3.8.0\" mac=\""), "{id}");
        let mac = id.rsplit('"').nth(1).unwrap();
        assert!(mac.len() == 12 && mac.chars().all(|ch| ch.is_ascii_hexdigit()), "{mac}");
        assert_eq!(c.aastra_id(), Some(id.clone()), "stable from call to call");
        c.acd = true;
        assert!(c.user_agent().starts_with("Mitel-Single-Line-UC-Endpoint ("));
        // Another account on the same machine gets another device id.
        c.user = "other".into();
        assert_ne!(c.aastra_id(), Some(id));
        // Explicit settings win; an empty id switches the header off.
        let c = Config::parse("[sip]\nserver = \"s\"\nuser = \"u\"\nuser_agent = \"x/1\"\naastra_id = \"\"\n").unwrap().sip;
        assert_eq!((c.user_agent().as_str(), c.aastra_id()), ("x/1", None));
    }

    #[test]
    fn splits_certificate_chain() {
        let mut c = SipConfig::default();
        assert!(c.ca_certificates().is_empty());
        // Two certificates in one text, one with escaped line breaks as JSON may deliver them.
        c.tls_ca_chain = Some("junk -----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\\nBBBB\\n-----END CERTIFICATE----- trailing".into());
        let certs = c.ca_certificates();
        assert_eq!(certs.len(), 2);
        assert_eq!(certs[0], "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n");
        assert_eq!(certs[1], "-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n");
        c.tls_ca_chain = Some("-----BEGIN CERTIFICATE-----\nno end".into());
        assert!(c.ca_certificates().is_empty());
    }

    #[test]
    fn rejects_incomplete_and_unknown() {
        assert!(Config::parse("[sip]\nserver = \"s\"\n").is_err());
        assert!(Config::parse("[micollab]\nserver = \"s\"\nuser = \"\"\n").is_err());
        assert!(Config::parse("[sip]\nserver = \"s\"\nuser = \"u\"\nfoo = 1\n").is_err());
        assert!(Config::parse("[sip]\nserver = \"s\"\nuser = \"u\"\ncodecs = [\"G729\"]\n").is_err());
        assert!(Config::parse("[sip]\nserver = \"s\"\nuser = \"u\"\ncodecs = []\n").is_err());
        let c = Config::parse("[sip]\nserver = \"s\"\nuser = \"u\"\ncodecs = [\"pcma\"]\n").unwrap();
        assert_eq!(c.sip.codecs, vec!["pcma"]);
        assert_eq!(Config::parse("[sip]\nserver = \"s\"\nuser = \"u\"\n").unwrap().sip.codecs, vec!["opus", "PCMA", "PCMU"]);
    }
}
