//! SIP message model, parser, serializer and stream framing.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartLine {
    Request { method: String, uri: String },
    Response { code: u16, reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub start: StartLine,
    /// Headers in wire order. `Content-Length` is never stored; it is derived from `body`.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError(pub String);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SIP parse error: {}", self.0)
    }
}
impl std::error::Error for ParseError {}

fn err<T>(msg: impl Into<String>) -> Result<T, ParseError> {
    Err(ParseError(msg.into()))
}

/// Maps compact header forms to their long names.
fn canonical(name: &str) -> &str {
    match name {
        "v" | "V" => "Via",
        "f" | "F" => "From",
        "t" | "T" => "To",
        "i" | "I" => "Call-ID",
        "m" | "M" => "Contact",
        "l" | "L" => "Content-Length",
        "c" | "C" => "Content-Type",
        "k" | "K" => "Supported",
        "e" | "E" => "Content-Encoding",
        "s" | "S" => "Subject",
        "o" | "O" => "Event",
        other => other,
    }
}

impl Message {
    pub fn request(method: &str, uri: &str) -> Self {
        Message {
            start: StartLine::Request { method: method.to_string(), uri: uri.to_string() },
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub fn response(code: u16, reason: &str) -> Self {
        Message {
            start: StartLine::Response { code, reason: reason.to_string() },
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// Builds a response to `req`, copying Via, From, To, Call-ID and CSeq as RFC 3261 requires.
    /// `to_tag` is appended to To when it has no tag yet.
    pub fn response_to(req: &Message, code: u16, reason: &str, to_tag: Option<&str>) -> Self {
        let mut rsp = Message::response(code, reason);
        for (n, v) in &req.headers {
            match canonical(n).to_ascii_lowercase().as_str() {
                "via" | "from" | "call-id" | "cseq" => rsp.headers.push((canonical(n).to_string(), v.clone())),
                "record-route" if (200..300).contains(&code) || code == 180 || code == 183 => {
                    rsp.headers.push((n.clone(), v.clone()))
                }
                "to" => {
                    let mut v = v.clone();
                    if let Some(tag) = to_tag {
                        if tag_of(&v).is_none() {
                            v.push_str(";tag=");
                            v.push_str(tag);
                        }
                    }
                    rsp.headers.push(("To".to_string(), v));
                }
                _ => {}
            }
        }
        rsp
    }

    pub fn is_request(&self) -> bool {
        matches!(self.start, StartLine::Request { .. })
    }

    pub fn method(&self) -> Option<&str> {
        match &self.start {
            StartLine::Request { method, .. } => Some(method),
            _ => None,
        }
    }

    pub fn uri(&self) -> Option<&str> {
        match &self.start {
            StartLine::Request { uri, .. } => Some(uri),
            _ => None,
        }
    }

    pub fn status(&self) -> Option<u16> {
        match &self.start {
            StartLine::Response { code, .. } => Some(*code),
            _ => None,
        }
    }

    /// First value of a header (case-insensitive, compact forms understood).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| canonical(n).eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn headers_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.headers
            .iter()
            .filter(move |(n, _)| canonical(n).eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn add(&mut self, name: &str, value: impl Into<String>) -> &mut Self {
        self.headers.push((name.to_string(), value.into()));
        self
    }

    /// Replaces the first header with this name or appends it.
    pub fn set(&mut self, name: &str, value: impl Into<String>) -> &mut Self {
        let value = value.into();
        match self.headers.iter_mut().find(|(n, _)| canonical(n).eq_ignore_ascii_case(name)) {
            Some(h) => h.1 = value,
            None => self.headers.push((name.to_string(), value)),
        }
        self
    }

    pub fn remove(&mut self, name: &str) {
        self.headers.retain(|(n, _)| !canonical(n).eq_ignore_ascii_case(name));
    }

    pub fn set_body(&mut self, content_type: &str, body: impl Into<Vec<u8>>) -> &mut Self {
        self.set("Content-Type", content_type);
        self.body = body.into();
        self
    }

    pub fn call_id(&self) -> &str {
        self.header("Call-ID").unwrap_or("")
    }

    /// CSeq number and method.
    pub fn cseq(&self) -> Option<(u32, &str)> {
        let v = self.header("CSeq")?;
        let mut it = v.split_whitespace();
        let n = it.next()?.parse().ok()?;
        Some((n, it.next()?))
    }

    /// Branch parameter of the topmost Via.
    pub fn branch(&self) -> Option<&str> {
        param(self.header("Via")?, "branch")
    }

    /// True if a comma separated token header (Supported, Require, ...) contains `token`.
    pub fn has_token(&self, name: &str, token: &str) -> bool {
        self.headers_all(name)
            .flat_map(|v| v.split(','))
            .any(|t| t.trim().eq_ignore_ascii_case(token))
    }

    pub fn body_str(&self) -> &str {
        std::str::from_utf8(&self.body).unwrap_or("")
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = String::new();
        match &self.start {
            StartLine::Request { method, uri } => out.push_str(&format!("{method} {uri} SIP/2.0\r\n")),
            StartLine::Response { code, reason } => out.push_str(&format!("SIP/2.0 {code} {reason}\r\n")),
        }
        for (n, v) in &self.headers {
            out.push_str(n);
            out.push_str(": ");
            out.push_str(v);
            out.push_str("\r\n");
        }
        out.push_str(&format!("Content-Length: {}\r\n\r\n", self.body.len()));
        let mut bytes = out.into_bytes();
        bytes.extend_from_slice(&self.body);
        bytes
    }

    /// Parses the head (start line and headers, without the terminating empty line).
    /// Returns the message with an empty body and the announced Content-Length.
    fn parse_head(head: &str) -> Result<(Message, usize), ParseError> {
        let mut lines = head.split("\r\n");
        let first = lines.next().unwrap_or("");
        let start = if let Some(rest) = first.strip_prefix("SIP/2.0 ") {
            let (code, reason) = rest.split_once(' ').unwrap_or((rest, ""));
            let code = code.parse().map_err(|_| ParseError(format!("bad status line: {first}")))?;
            StartLine::Response { code, reason: reason.to_string() }
        } else {
            let mut it = first.split(' ');
            match (it.next(), it.next(), it.next()) {
                (Some(m), Some(u), Some("SIP/2.0")) if !m.is_empty() => {
                    StartLine::Request { method: m.to_string(), uri: u.to_string() }
                }
                _ => return err(format!("bad start line: {first}")),
            }
        };
        let mut headers: Vec<(String, String)> = Vec::new();
        let mut content_length = 0usize;
        for line in lines {
            if line.is_empty() {
                continue;
            }
            if line.starts_with(' ') || line.starts_with('\t') {
                // folded continuation line
                if let Some(last) = headers.last_mut() {
                    last.1.push(' ');
                    last.1.push_str(line.trim());
                }
                continue;
            }
            let (name, value) = line.split_once(':').ok_or_else(|| ParseError(format!("bad header: {line}")))?;
            let (name, value) = (name.trim(), value.trim());
            if canonical(name).eq_ignore_ascii_case("Content-Length") {
                content_length = value.parse().map_err(|_| ParseError(format!("bad Content-Length: {value}")))?;
            } else {
                headers.push((name.to_string(), value.to_string()));
            }
        }
        Ok((Message { start, headers, body: Vec::new() }, content_length))
    }

    /// Parses one complete message from a buffer.
    pub fn parse(data: &[u8]) -> Result<Message, ParseError> {
        let mut framer = Framer::new();
        framer.push(data);
        match framer.next_message() {
            Some(r) => r,
            None => err("incomplete message"),
        }
    }
}

/// Splits a byte stream (TCP/TLS) into SIP messages using Content-Length.
#[derive(Default)]
pub struct Framer {
    buf: Vec<u8>,
}

impl Framer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Returns the next complete message, `None` if more data is needed.
    /// After an error the buffer is cleared, since resynchronising is not possible.
    pub fn next_message(&mut self) -> Option<Result<Message, ParseError>> {
        // Skip keep-alive CRLFs between messages.
        let skip = self.buf.iter().take_while(|b| **b == b'\r' || **b == b'\n').count();
        self.buf.drain(..skip);
        let head_end = self.buf.windows(4).position(|w| w == b"\r\n\r\n")?;
        let head = match std::str::from_utf8(&self.buf[..head_end]) {
            Ok(h) => h,
            Err(_) => {
                self.buf.clear();
                return Some(err("head is not UTF-8"));
            }
        };
        let (mut msg, len) = match Message::parse_head(head) {
            Ok(r) => r,
            Err(e) => {
                self.buf.clear();
                return Some(Err(e));
            }
        };
        let total = head_end + 4 + len;
        if self.buf.len() < total {
            return None;
        }
        msg.body = self.buf[head_end + 4..total].to_vec();
        self.buf.drain(..total);
        Some(Ok(msg))
    }
}

/// Value of a `;name=value` parameter in a header value. Parameters inside `<...>` are ignored.
pub fn param<'a>(value: &'a str, name: &str) -> Option<&'a str> {
    let tail = match value.rfind('>') {
        Some(i) => &value[i + 1..],
        None => value,
    };
    tail.split(';').skip(1).find_map(|p| {
        let (k, v) = p.split_once('=').unwrap_or((p, ""));
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim().trim_matches('"'))
    })
}

/// Tag parameter of a From/To header value.
pub fn tag_of(value: &str) -> Option<&str> {
    param(value, "tag")
}

/// URI of a name-addr or addr-spec header value (From, To, Contact, Route).
pub fn uri_of(value: &str) -> &str {
    if let (Some(a), Some(b)) = (value.find('<'), value.find('>')) {
        if a < b {
            return &value[a + 1..b];
        }
    }
    value.split(';').next().unwrap_or(value).trim()
}

/// Display name of a name-addr header value, without quotes.
pub fn display_name_of(value: &str) -> Option<&str> {
    let end = value.find('<')?;
    let name = value[..end].trim().trim_matches('"');
    (!name.is_empty()).then_some(name)
}

/// User part of a SIP URI, with `%40` style escapes left untouched.
pub fn user_of_uri(uri: &str) -> Option<&str> {
    let rest = uri.split_once(':')?.1;
    let (user, _) = rest.split_once('@')?;
    Some(user.split(':').next().unwrap_or(user))
}

/// Escapes characters of a user name that are not allowed in the user part of a SIP URI.
pub fn escape_user(user: &str) -> String {
    let mut out = String::new();
    for c in user.chars() {
        if c.is_ascii_alphanumeric() || "-_.!~*'()&=+$,;?/".contains(c) {
            out.push(c);
        } else {
            let mut buf = [0u8; 4];
            for b in c.encode_utf8(&mut buf).bytes() {
                out.push_str(&format!("%{b:02X}"));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOTIFY: &str = "NOTIFY sips:alice%40example.org-1000@10.0.0.5:53943;transport=TLS SIP/2.0\r\n\
Via: SIP/2.0/TLS 10.0.0.1;branch=z9hG4bK-524287-1---d2482e5ea39a997a;rport\r\n\
Max-Forwards: 70\r\n\
Contact: <sip:unknown@10.0.0.1:5061;transport=TLS>\r\n\
To: \"alice@example.org-1000\"<sips:alice%40example.org-1000@pbx.example.org:5061;transport=TLS>;tag=62518d6fa9\r\n\
From: \"alice@example.org-1000\"<sips:alice%40example.org-1000@pbx.example.org:5061;transport=TLS>;tag=f895825b\r\n\
Call-ID: 46560d04fc4c1ce8\r\n\
CSeq: 2079480939 NOTIFY\r\n\
Content-Type: application/mihotdesk\r\n\
Subscription-State: active;expires=1800\r\n\
Event: mihotdesk\r\n\
Content-Length: 36\r\n\
\r\n\
<mihotdesk cause=\"0\">\r\n</mihotdesk>\r\n";

    #[test]
    fn parses_request_with_body() {
        let m = Message::parse(NOTIFY.as_bytes()).unwrap();
        assert_eq!(m.method(), Some("NOTIFY"));
        assert_eq!(m.cseq(), Some((2079480939, "NOTIFY")));
        assert_eq!(m.branch(), Some("z9hG4bK-524287-1---d2482e5ea39a997a"));
        assert_eq!(m.body.len(), 36);
        assert_eq!(tag_of(m.header("from").unwrap()), Some("f895825b"));
        assert_eq!(param(m.header("Subscription-State").unwrap(), "expires"), Some("1800"));
        assert_eq!(display_name_of(m.header("To").unwrap()), Some("alice@example.org-1000"));
        assert_eq!(user_of_uri(uri_of(m.header("To").unwrap())), Some("alice%40example.org-1000"));
    }

    #[test]
    fn roundtrip_and_response() {
        let m = Message::parse(NOTIFY.as_bytes()).unwrap();
        let again = Message::parse(&m.to_bytes()).unwrap();
        assert_eq!(m, again);
        let rsp = Message::response_to(&m, 200, "OK", Some("abc"));
        assert_eq!(rsp.status(), Some(200));
        // To already has a tag, so it must be left alone.
        assert_eq!(tag_of(rsp.header("To").unwrap()), Some("62518d6fa9"));
        assert_eq!(rsp.header("Call-ID"), Some("46560d04fc4c1ce8"));
        assert!(rsp.header("Contact").is_none());
    }

    #[test]
    fn framer_handles_fragments_and_keepalives() {
        let mut data = b"\r\n\r\n".to_vec();
        data.extend_from_slice(NOTIFY.as_bytes());
        data.extend_from_slice(b"SIP/2.0 200 OK\r\nCSeq: 1 REGISTER\r\nl: 0\r\n\r\n");
        let mut f = Framer::new();
        let mut got = Vec::new();
        for chunk in data.chunks(7) {
            f.push(chunk);
            while let Some(m) = f.next_message() {
                got.push(m.unwrap());
            }
        }
        assert_eq!(got.len(), 2);
        assert_eq!(got[1].status(), Some(200));
        assert!(got[1].body.is_empty());
    }

    #[test]
    fn param_ignores_uri_parameters() {
        let v = "\"x\" <sips:x@10.0.0.5:57014;transport=tls>;expires=240";
        assert_eq!(param(v, "expires"), Some("240"));
        assert_eq!(param(v, "transport"), None);
        assert_eq!(uri_of(v), "sips:x@10.0.0.5:57014;transport=tls");
        assert_eq!(uri_of("sip:a@b;tag=1"), "sip:a@b");
    }

    #[test]
    fn escapes_user() {
        assert_eq!(escape_user("alice@example.org-1000"), "alice%40example.org-1000");
    }

    #[test]
    fn rejects_garbage() {
        assert!(Message::parse(b"hello world\r\n\r\n").is_err());
    }
}
