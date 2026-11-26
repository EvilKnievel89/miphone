//! HTTP digest authentication for SIP (RFC 2617 / RFC 3261), MD5 with qop `auth` and `auth-int`.

use md5::{Digest, Md5};

/// MD5 of `data` as lower-case hex.
pub fn md5_hex(data: &[u8]) -> String {
    Md5::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    pub realm: String,
    pub nonce: String,
    pub opaque: Option<String>,
    pub algorithm: Option<String>,
    pub qop: Vec<String>,
    pub stale: bool,
}

impl Challenge {
    /// Parses a `WWW-Authenticate` / `Proxy-Authenticate` header value.
    pub fn parse(value: &str) -> Option<Challenge> {
        let rest = value.trim();
        let rest = rest.get(..6).filter(|p| p.eq_ignore_ascii_case("digest")).map(|_| &rest[6..])?;
        let mut c = Challenge { realm: String::new(), nonce: String::new(), opaque: None, algorithm: None, qop: Vec::new(), stale: false };
        for (k, v) in split_params(rest) {
            match k.to_ascii_lowercase().as_str() {
                "realm" => c.realm = v,
                "nonce" => c.nonce = v,
                "opaque" => c.opaque = Some(v),
                "algorithm" => c.algorithm = Some(v),
                "qop" => c.qop = v.split(',').map(|s| s.trim().to_ascii_lowercase()).filter(|s| !s.is_empty()).collect(),
                "stale" => c.stale = v.eq_ignore_ascii_case("true"),
                _ => {}
            }
        }
        (!c.nonce.is_empty()).then_some(c)
    }
}

/// Splits `k=v, k="quoted, value"` lists, respecting quotes.
fn split_params(s: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for ch in s.chars().chain(std::iter::once(',')) {
        match ch {
            '"' => {
                quoted = !quoted;
                cur.push(ch);
            }
            ',' if !quoted => {
                if let Some((k, v)) = cur.split_once('=') {
                    out.push((k.trim().to_string(), v.trim().trim_matches('"').to_string()));
                }
                cur.clear();
            }
            _ => cur.push(ch),
        }
    }
    out
}

/// Computes the digest `response` value.
#[allow(clippy::too_many_arguments)]
pub fn response(
    user: &str,
    realm: &str,
    password: &str,
    method: &str,
    uri: &str,
    nonce: &str,
    qop: Option<&str>,
    nc: u32,
    cnonce: &str,
    body: &[u8],
) -> String {
    let ha1 = md5_hex(format!("{user}:{realm}:{password}").as_bytes());
    let ha2 = match qop {
        Some("auth-int") => md5_hex(format!("{method}:{uri}:{}", md5_hex(body)).as_bytes()),
        _ => md5_hex(format!("{method}:{uri}").as_bytes()),
    };
    match qop {
        Some(q) => md5_hex(format!("{ha1}:{nonce}:{nc:08x}:{cnonce}:{q}:{ha2}").as_bytes()),
        None => md5_hex(format!("{ha1}:{nonce}:{ha2}").as_bytes()),
    }
}

/// Credentials plus the server's current challenge; produces `Authorization` values
/// with an increasing nonce count, so later requests can authenticate without a new challenge.
#[derive(Debug, Clone)]
pub struct Session {
    user: String,
    password: String,
    challenge: Challenge,
    cnonce: String,
    nc: u32,
}

impl Session {
    pub fn new(user: &str, password: &str, challenge: Challenge) -> Self {
        Session { user: user.to_string(), password: password.to_string(), challenge, cnonce: crate::random_hex(8), nc: 0 }
    }

    pub fn challenge(&self) -> &Challenge {
        &self.challenge
    }

    /// `Authorization` header value for one request. Prefers `auth-int` like the Mitel client.
    pub fn authorize(&mut self, method: &str, uri: &str, body: &[u8]) -> String {
        self.nc += 1;
        let c = &self.challenge;
        let qop = if c.qop.iter().any(|q| q == "auth-int") {
            Some("auth-int")
        } else if c.qop.iter().any(|q| q == "auth") {
            Some("auth")
        } else {
            None
        };
        let resp = response(&self.user, &c.realm, &self.password, method, uri, &c.nonce, qop, self.nc, &self.cnonce, body);
        let mut v = format!(
            "Digest username=\"{}\",realm=\"{}\",nonce=\"{}\",uri=\"{}\",response=\"{}\",algorithm=MD5",
            self.user, c.realm, c.nonce, uri, resp
        );
        if let Some(q) = qop {
            v.push_str(&format!(",qop={q},cnonce=\"{}\",nc={:08x}", self.cnonce, self.nc));
        }
        if let Some(o) = &c.opaque {
            v.push_str(&format!(",opaque=\"{o}\""));
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc2617_example() {
        let r = response(
            "Mufasa",
            "testrealm@host.com",
            "Circle Of Life",
            "GET",
            "/dir/index.html",
            "dcd98b7102dd2f0e8b11d0f600bfb0c093",
            Some("auth"),
            1,
            "0a4f113b",
            b"",
        );
        assert_eq!(r, "6629fae49393a05397450978507c4ef1");
    }

    #[test]
    fn rfc3261_style_without_qop() {
        // RFC 2069 compatible form: MD5(HA1:nonce:HA2)
        let ha1 = md5_hex(b"bob:biloxi.com:zanzibar");
        let ha2 = md5_hex(b"REGISTER:sip:biloxi.com");
        let expect = md5_hex(format!("{ha1}:abc:{ha2}").as_bytes());
        assert_eq!(response("bob", "biloxi.com", "zanzibar", "REGISTER", "sip:biloxi.com", "abc", None, 1, "", b""), expect);
    }

    #[test]
    fn parses_mbg_challenge() {
        let c = Challenge::parse("Digest nonce=\"1795676903:bdd5bddef41dac99\",algorithm=MD5,realm=\"mbg\",qop=\"auth,auth-int\"").unwrap();
        assert_eq!(c.realm, "mbg");
        assert_eq!(c.nonce, "1795676903:bdd5bddef41dac99");
        assert_eq!(c.qop, vec!["auth", "auth-int"]);
        assert!(!c.stale);
        assert!(Challenge::parse("Basic realm=\"x\"").is_none());
    }

    #[test]
    fn session_counts_nonce_uses() {
        let c = Challenge::parse("Digest nonce=\"n\",realm=\"mbg\",qop=\"auth,auth-int\"").unwrap();
        let mut s = Session::new("u", "p", c);
        let a = s.authorize("REGISTER", "sips:example.org:5061;transport=tls", b"");
        let b = s.authorize("SUBSCRIBE", "sips:example.org:5061;transport=tls", b"");
        assert!(a.contains("qop=auth-int") && a.contains("nc=00000001"));
        assert!(b.contains("nc=00000002"));
        assert!(a.starts_with("Digest username=\"u\",realm=\"mbg\",nonce=\"n\",uri=\"sips:example.org:5061;transport=tls\",response=\""));
    }
}
