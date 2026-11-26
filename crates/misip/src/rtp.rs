//! RTP packets (RFC 3550) and telephone-event payloads (RFC 4733).

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtpPacket<'a> {
    pub marker: bool,
    pub payload_type: u8,
    pub sequence: u16,
    pub timestamp: u32,
    pub ssrc: u32,
    pub payload: &'a [u8],
}

impl<'a> RtpPacket<'a> {
    /// Parses a packet, skipping CSRC list, header extension and padding.
    pub fn parse(data: &'a [u8]) -> Option<RtpPacket<'a>> {
        if data.len() < 12 || data[0] >> 6 != 2 {
            return None;
        }
        let padding = data[0] & 0x20 != 0;
        let extension = data[0] & 0x10 != 0;
        let csrc_count = (data[0] & 0x0f) as usize;
        let mut offset = 12 + 4 * csrc_count;
        if extension {
            let words = u16::from_be_bytes([*data.get(offset + 2)?, *data.get(offset + 3)?]) as usize;
            offset += 4 + 4 * words;
        }
        let mut end = data.len();
        if padding {
            let pad = *data.last()? as usize;
            if pad == 0 || pad > end {
                return None;
            }
            end -= pad;
        }
        if offset > end {
            return None;
        }
        Some(RtpPacket {
            marker: data[1] & 0x80 != 0,
            payload_type: data[1] & 0x7f,
            sequence: u16::from_be_bytes([data[2], data[3]]),
            timestamp: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            ssrc: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
            payload: &data[offset..end],
        })
    }

    pub fn write(&self, out: &mut Vec<u8>) {
        out.clear();
        out.push(0x80);
        out.push(self.payload_type & 0x7f | if self.marker { 0x80 } else { 0 });
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&self.ssrc.to_be_bytes());
        out.extend_from_slice(self.payload);
    }
}

/// Event code for a DTMF character (0-9, *, #, A-D).
pub fn dtmf_event(digit: char) -> Option<u8> {
    match digit.to_ascii_uppercase() {
        c @ '0'..='9' => Some(c as u8 - b'0'),
        '*' => Some(10),
        '#' => Some(11),
        c @ 'A'..='D' => Some(c as u8 - b'A' + 12),
        _ => None,
    }
}

/// telephone-event payload: event, end flag, volume (dBm0 below 0) and duration in timestamp units.
pub fn dtmf_payload(event: u8, end: bool, volume: u8, duration: u16) -> [u8; 4] {
    let d = duration.to_be_bytes();
    [event, (volume & 0x3f) | if end { 0x80 } else { 0 }, d[0], d[1]]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let p = RtpPacket { marker: true, payload_type: 8, sequence: 65535, timestamp: 0xdeadbeef, ssrc: 0x52502a94, payload: &[1, 2, 3] };
        let mut buf = Vec::new();
        p.write(&mut buf);
        assert_eq!(buf.len(), 15);
        assert_eq!(RtpPacket::parse(&buf), Some(p));
    }

    #[test]
    fn parses_extension_csrc_and_padding() {
        // V=2, P=1, X=1, CC=1
        let mut d = vec![0xb1, 0x00, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3];
        d.extend_from_slice(&[9, 9, 9, 9]); // CSRC
        d.extend_from_slice(&[0xbe, 0xde, 0, 1, 7, 7, 7, 7]); // extension, one word
        d.extend_from_slice(&[0xaa, 0xbb]); // payload
        d.extend_from_slice(&[0, 2]); // padding
        let p = RtpPacket::parse(&d).unwrap();
        assert_eq!(p.payload, &[0xaa, 0xbb]);
        assert_eq!(p.sequence, 1);
    }

    #[test]
    fn rejects_invalid() {
        assert!(RtpPacket::parse(&[0x80, 0, 0]).is_none());
        assert!(RtpPacket::parse(&[0x00; 12]).is_none());
    }

    #[test]
    fn dtmf() {
        assert_eq!(dtmf_event('5'), Some(5));
        assert_eq!(dtmf_event('#'), Some(11));
        assert_eq!(dtmf_event('d'), Some(15));
        assert_eq!(dtmf_event('x'), None);
        assert_eq!(dtmf_payload(1, true, 10, 800), [1, 0x8a, 0x03, 0x20]);
    }
}
