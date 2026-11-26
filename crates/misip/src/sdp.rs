//! Minimal SDP handling for a single audio stream (offer/answer per RFC 3264).

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Codec {
    pub pt: u8,
    /// Encoding name as on the wire, e.g. `PCMA`, `opus`, `telephone-event`.
    pub name: String,
    pub rate: u32,
    pub channels: u8,
    pub fmtp: Option<String>,
}

impl Codec {
    pub fn new(pt: u8, name: &str, rate: u32) -> Self {
        Codec { pt, name: name.to_string(), rate, channels: 1, fmtp: None }
    }

    /// Opus as it appears in SDP: always 48 kHz and two channels (RFC 7587), whatever is actually sent.
    pub fn opus(pt: u8, fmtp: &str) -> Self {
        Codec { pt, name: "opus".to_string(), rate: 48000, channels: 2, fmtp: Some(fmtp.to_string()) }
    }

    /// True if clock rate and channels are what the encoding name requires.
    fn is_well_formed(&self) -> bool {
        if self.is("opus") {
            self.rate == 48000 && self.channels == 2
        } else {
            self.rate == 8000 && self.channels == 1
        }
    }

    pub fn is(&self, name: &str) -> bool {
        self.name.eq_ignore_ascii_case(name)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    SendRecv,
    SendOnly,
    RecvOnly,
    Inactive,
}

impl Direction {
    fn as_str(self) -> &'static str {
        match self {
            Direction::SendRecv => "sendrecv",
            Direction::SendOnly => "sendonly",
            Direction::RecvOnly => "recvonly",
            Direction::Inactive => "inactive",
        }
    }

    /// The direction the answerer uses for an offer with this direction.
    pub fn reversed(self) -> Direction {
        match self {
            Direction::SendOnly => Direction::RecvOnly,
            Direction::RecvOnly => Direction::SendOnly,
            other => other,
        }
    }

    pub fn can_send(self) -> bool {
        matches!(self, Direction::SendRecv | Direction::SendOnly)
    }

    pub fn can_recv(self) -> bool {
        matches!(self, Direction::SendRecv | Direction::RecvOnly)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioSdp {
    pub session_id: u64,
    pub session_version: u64,
    pub addr: String,
    pub port: u16,
    pub codecs: Vec<Codec>,
    pub direction: Direction,
    pub ptime: Option<u32>,
    /// Further `m=` lines of an offer (media type and the rest of the line), to be rejected in the answer.
    pub other_media: Vec<String>,
}

fn static_codec(pt: u8) -> Option<Codec> {
    match pt {
        0 => Some(Codec::new(0, "PCMU", 8000)),
        8 => Some(Codec::new(8, "PCMA", 8000)),
        9 => Some(Codec::new(9, "G722", 8000)),
        18 => Some(Codec::new(18, "G729", 8000)),
        _ => None,
    }
}

impl AudioSdp {
    pub fn parse(sdp: &str) -> Result<AudioSdp, String> {
        let mut out = AudioSdp {
            session_id: 0,
            session_version: 0,
            addr: String::new(),
            port: 0,
            codecs: Vec::new(),
            direction: Direction::SendRecv,
            ptime: None,
            other_media: Vec::new(),
        };
        let mut session_addr = String::new();
        let mut session_dir = None;
        let mut pts: Vec<u8> = Vec::new();
        let mut rtpmaps: Vec<(u8, String)> = Vec::new();
        let mut fmtps: Vec<(u8, String)> = Vec::new();
        // 0 = session level, 1 = inside the audio section, 2 = inside another media section
        let mut section = 0;
        let mut seen_audio = false;
        for line in sdp.lines() {
            let line = line.trim_end();
            let Some((kind, value)) = line.split_once('=') else { continue };
            match kind {
                "o" => {
                    let f: Vec<&str> = value.split_whitespace().collect();
                    if f.len() >= 3 {
                        out.session_id = f[1].parse().unwrap_or(0);
                        out.session_version = f[2].parse().unwrap_or(0);
                    }
                }
                "c" => {
                    let a = value.split_whitespace().nth(2).unwrap_or("").to_string();
                    match section {
                        0 => session_addr = a,
                        1 => out.addr = a,
                        _ => {}
                    }
                }
                "m" => {
                    let f: Vec<&str> = value.split_whitespace().collect();
                    if f.first() == Some(&"audio") && !seen_audio {
                        if f.len() < 4 {
                            return Err(format!("bad m= line: {value}"));
                        }
                        seen_audio = true;
                        section = 1;
                        out.port = f[1].split('/').next().unwrap_or("").parse().map_err(|_| format!("bad port in: {value}"))?;
                        pts = f[3..].iter().filter_map(|p| p.parse().ok()).collect();
                    } else {
                        section = 2;
                        out.other_media.push(value.to_string());
                    }
                }
                "a" if section != 2 => {
                    let (attr, arg) = value.split_once(':').unwrap_or((value, ""));
                    let dir = match attr {
                        "sendrecv" => Some(Direction::SendRecv),
                        "sendonly" => Some(Direction::SendOnly),
                        "recvonly" => Some(Direction::RecvOnly),
                        "inactive" => Some(Direction::Inactive),
                        _ => None,
                    };
                    if let Some(d) = dir {
                        if section == 0 {
                            session_dir = Some(d);
                        } else {
                            out.direction = d;
                            session_dir = None;
                        }
                    } else if section == 1 {
                        let (pt, rest) = arg.split_once(' ').unwrap_or((arg, ""));
                        match attr {
                            "rtpmap" => {
                                if let Ok(pt) = pt.parse() {
                                    rtpmaps.push((pt, rest.trim().to_string()));
                                }
                            }
                            "fmtp" => {
                                if let Ok(pt) = pt.parse() {
                                    fmtps.push((pt, rest.trim().to_string()));
                                }
                            }
                            "ptime" => out.ptime = arg.trim().parse().ok(),
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
        if !seen_audio {
            return Err("no audio stream in SDP".into());
        }
        if let Some(d) = session_dir {
            out.direction = d;
        }
        if out.addr.is_empty() {
            out.addr = session_addr;
        }
        for pt in pts {
            let mut codec = match rtpmaps.iter().find(|(p, _)| *p == pt) {
                Some((_, map)) => {
                    let mut it = map.split('/');
                    let name = it.next().unwrap_or("").to_string();
                    let rate = it.next().and_then(|r| r.parse().ok()).unwrap_or(8000);
                    let channels = it.next().and_then(|c| c.parse().ok()).unwrap_or(1);
                    Codec { pt, name, rate, channels, fmtp: None }
                }
                None => match static_codec(pt) {
                    Some(c) => c,
                    None => continue,
                },
            };
            codec.fmtp = fmtps.iter().find(|(p, _)| *p == pt).map(|(_, f)| f.clone());
            out.codecs.push(codec);
        }
        Ok(out)
    }

    /// Serializes in the layout the Mitel client uses.
    pub fn build(&self) -> String {
        let mut s = format!(
            "v=0\r\no=- {} {} IN IP4 {}\r\ns= \r\nc=IN IP4 {}\r\nt=0 0\r\n",
            self.session_id, self.session_version, self.addr, self.addr
        );
        let pts: Vec<String> = self.codecs.iter().map(|c| c.pt.to_string()).collect();
        s.push_str(&format!("m=audio {} RTP/AVP {}\r\n", self.port, pts.join(" ")));
        for c in &self.codecs {
            if c.channels > 1 {
                s.push_str(&format!("a=rtpmap:{} {}/{}/{}\r\n", c.pt, c.name, c.rate, c.channels));
            } else {
                s.push_str(&format!("a=rtpmap:{} {}/{}\r\n", c.pt, c.name, c.rate));
            }
        }
        for c in &self.codecs {
            if let Some(f) = &c.fmtp {
                s.push_str(&format!("a=fmtp:{} {}\r\n", c.pt, f));
            }
        }
        s.push_str(&format!("a=ptime:{}\r\n", self.ptime.unwrap_or(20)));
        s.push_str(&format!("a={}\r\n", self.direction.as_str()));
        for m in &self.other_media {
            // Reject additional streams (e.g. video) by answering with port 0.
            let f: Vec<&str> = m.split_whitespace().collect();
            if f.len() >= 4 {
                s.push_str(&format!("m={} 0 {} {}\r\n", f[0], f[2], f[3..].join(" ")));
            }
        }
        s
    }

    /// Our offer: the given audio codecs plus RFC 4733 telephone events on payload type 101.
    pub fn offer(addr: &str, port: u16, session_id: u64, audio: &[Codec]) -> AudioSdp {
        let mut codecs = audio.to_vec();
        let mut dtmf = Codec::new(101, "telephone-event", 8000);
        dtmf.fmtp = Some("0-15".into());
        codecs.push(dtmf);
        AudioSdp {
            session_id,
            session_version: session_id,
            addr: addr.to_string(),
            port,
            codecs,
            direction: Direction::SendRecv,
            ptime: Some(20),
            other_media: Vec::new(),
        }
    }

    /// Builds the answer to `offer`: the first codec of the offer that we support
    /// (in the offerer's order of preference) plus telephone-event if offered.
    /// Returns `None` when there is no common audio codec.
    pub fn answer(offer: &AudioSdp, addr: &str, port: u16, session_id: u64, session_version: u64, supported: &[&str]) -> Option<AudioSdp> {
        let audio = offer.codecs.iter().find(|c| c.is_well_formed() && supported.iter().any(|s| c.is(s)))?;
        // Opus parameters are echoed like the Mitel client does; G.711 has none.
        let fmtp = audio.fmtp.clone().filter(|_| audio.is("opus"));
        let mut codecs = vec![Codec { fmtp, ..audio.clone() }];
        if let Some(d) = offer.codecs.iter().find(|c| c.is("telephone-event") && c.rate == 8000) {
            codecs.push(Codec { fmtp: Some("0-15".into()), ..d.clone() });
        }
        Some(AudioSdp {
            session_id,
            session_version,
            addr: addr.to_string(),
            port,
            codecs,
            direction: offer.direction.reversed(),
            ptime: Some(20),
            other_media: offer.other_media.clone(),
        })
    }

    /// The codec used for audio (first one that is not telephone-event).
    pub fn audio_codec(&self) -> Option<&Codec> {
        self.codecs.iter().find(|c| !c.is("telephone-event"))
    }

    pub fn dtmf_pt(&self) -> Option<u8> {
        self.codecs.iter().find(|c| c.is("telephone-event")).map(|c| c.pt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIRST_OFFER: &str = "v=0\r\no=- 2913 2913 IN IP4 10.0.0.1\r\ns=NSTREAMING\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\n\
m=audio 20184 RTP/AVP 8 0 101\r\na=rtpmap:8 PCMA/8000\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\n\
a=fmtp:101 0-15\r\na=ptime:20\r\na=inactive\r\n";

    const REINVITE: &str = "v=0\r\no=- 2913 2914 IN IP4 10.0.0.1\r\ns=NSTREAMING\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\n\
a=X-app:Android 10 10.3.8b0 ar:0.75\r\nm=audio 20184 RTP/AVP 124 8 0 101\r\nb=AS:128\r\na=rtpmap:124 opus/48000/2\r\n\
a=fmtp:124 maxaveragebitrate=16000;stereo=0\r\na=rtpmap:8 PCMA/8000\r\na=rtpmap:0 PCMU/8000\r\n\
a=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-15\r\na=ptime:20\r\n";

    const WITH_VIDEO: &str = "v=0\r\no=- 2832 2832 IN IP4 10.0.0.1\r\ns=NSTREAMING\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\n\
m=audio 20114 RTP/AVP 0 101\r\na=rtpmap:101 telephone-event/8000\r\na=sendrecv\r\n\
m=video 0 RTP/AVP 119 120\r\na=rtpmap:119 H264/90000\r\na=sendonly\r\n";

    #[test]
    fn parses_inactive_offer() {
        let o = AudioSdp::parse(FIRST_OFFER).unwrap();
        assert_eq!((o.addr.as_str(), o.port), ("10.0.0.1", 20184));
        assert_eq!(o.direction, Direction::Inactive);
        assert_eq!(o.codecs.iter().map(|c| c.pt).collect::<Vec<_>>(), vec![8, 0, 101]);
        assert_eq!(o.ptime, Some(20));
        assert_eq!((o.session_id, o.session_version), (2913, 2913));
    }

    #[test]
    fn answer_matches_mitel_layout() {
        let o = AudioSdp::parse(FIRST_OFFER).unwrap();
        let a = AudioSdp::answer(&o, "10.0.0.5", 55496, 7, 7, &["PCMA", "PCMU"]).unwrap();
        assert_eq!(
            a.build(),
            "v=0\r\no=- 7 7 IN IP4 10.0.0.5\r\ns= \r\nc=IN IP4 10.0.0.5\r\nt=0 0\r\nm=audio 55496 RTP/AVP 8 101\r\n\
a=rtpmap:8 PCMA/8000\r\na=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-15\r\na=ptime:20\r\na=inactive\r\n"
        );
    }

    #[test]
    fn skips_unsupported_codecs() {
        let o = AudioSdp::parse(REINVITE).unwrap();
        assert_eq!(o.codecs[0].name, "opus");
        assert_eq!(o.codecs[0].channels, 2);
        assert_eq!(o.direction, Direction::SendRecv);
        let a = AudioSdp::answer(&o, "10.0.0.5", 4000, 1, 2, &["PCMU", "PCMA"]).unwrap();
        assert_eq!(a.audio_codec().unwrap().name, "PCMA");
        assert_eq!(a.dtmf_pt(), Some(101));
        assert!(AudioSdp::answer(&o, "10.0.0.5", 4000, 1, 2, &["G729"]).is_none());
    }

    #[test]
    fn prefers_opus_when_supported() {
        let o = AudioSdp::parse(REINVITE).unwrap();
        let a = AudioSdp::answer(&o, "10.0.0.5", 4000, 1, 2, &["opus", "PCMA", "PCMU"]).unwrap();
        assert_eq!(
            a.build(),
            "v=0\r\no=- 1 2 IN IP4 10.0.0.5\r\ns= \r\nc=IN IP4 10.0.0.5\r\nt=0 0\r\nm=audio 4000 RTP/AVP 124 101\r\n\
a=rtpmap:124 opus/48000/2\r\na=rtpmap:101 telephone-event/8000\r\na=fmtp:124 maxaveragebitrate=16000;stereo=0\r\na=fmtp:101 0-15\r\n\
a=ptime:20\r\na=sendrecv\r\n"
        );
        // A mono or 16 kHz "opus" line is not valid Opus and must be skipped.
        let odd = AudioSdp::parse(&REINVITE.replace("opus/48000/2", "opus/16000")).unwrap();
        assert_eq!(AudioSdp::answer(&odd, "10.0.0.5", 4000, 1, 2, &["opus", "PCMA"]).unwrap().audio_codec().unwrap().name, "PCMA");
        // Our own offer with Opus first survives a round trip.
        let offer = AudioSdp::offer("10.0.0.5", 4002, 9, &[Codec::opus(124, "useinbandfec=1"), Codec::new(8, "PCMA", 8000)]);
        assert!(offer.build().contains("m=audio 4002 RTP/AVP 124 8 101\r\na=rtpmap:124 opus/48000/2\r\n"));
        assert_eq!(AudioSdp::parse(&offer.build()).unwrap(), offer);
    }

    #[test]
    fn static_payload_types_and_video_rejection() {
        let o = AudioSdp::parse(WITH_VIDEO).unwrap();
        assert_eq!(o.codecs[0], Codec::new(0, "PCMU", 8000));
        // The direction of the video section must not leak into audio.
        assert_eq!(o.direction, Direction::SendRecv);
        let a = AudioSdp::answer(&o, "10.0.0.5", 4000, 1, 1, &["PCMU"]).unwrap();
        assert!(a.build().ends_with("a=sendrecv\r\nm=video 0 RTP/AVP 119 120\r\n"));
    }

    #[test]
    fn offer_roundtrip() {
        let o = AudioSdp::offer("10.0.0.5", 4002, 99, &[Codec::new(8, "PCMA", 8000), Codec::new(0, "PCMU", 8000)]);
        let p = AudioSdp::parse(&o.build()).unwrap();
        assert_eq!(p, o);
    }

    #[test]
    fn direction_reversal() {
        assert_eq!(Direction::SendOnly.reversed(), Direction::RecvOnly);
        assert_eq!(Direction::Inactive.reversed(), Direction::Inactive);
        assert!(Direction::RecvOnly.can_recv() && !Direction::RecvOnly.can_send());
    }
}
