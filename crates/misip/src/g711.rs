//! G.711 A-law (PCMA) and mu-law (PCMU) companding of 16 bit linear PCM.

const ULAW_BIAS: i32 = 0x84;
const ULAW_CLIP: i32 = 32635;

pub fn linear_to_ulaw(pcm: i16) -> u8 {
    let mut s = pcm as i32;
    let sign = if s < 0 {
        s = -s;
        0x80
    } else {
        0
    };
    s = s.min(ULAW_CLIP) + ULAW_BIAS;
    let mut exp = 7;
    let mut mask = 0x4000;
    while exp > 0 && s & mask == 0 {
        exp -= 1;
        mask >>= 1;
    }
    let mantissa = (s >> (exp + 3)) & 0x0f;
    !((sign | (exp << 4) | mantissa) as u8)
}

pub fn ulaw_to_linear(u: u8) -> i16 {
    let u = !u;
    let exp = ((u >> 4) & 0x07) as i32;
    let mantissa = (u & 0x0f) as i32;
    let s = (((mantissa << 3) + ULAW_BIAS) << exp) - ULAW_BIAS;
    (if u & 0x80 != 0 { -s } else { s }) as i16
}

pub fn linear_to_alaw(pcm: i16) -> u8 {
    let mut s = pcm as i32;
    let sign = if s >= 0 {
        0x80
    } else {
        s = -s - 1;
        0
    };
    let (exp, mantissa) = if s >= 256 {
        let mut exp = 7;
        let mut mask = 0x4000;
        while s & mask == 0 {
            exp -= 1;
            mask >>= 1;
        }
        (exp, (s >> (exp + 3)) & 0x0f)
    } else {
        (0, s >> 4)
    };
    ((sign | (exp << 4) | mantissa) as u8) ^ 0x55
}

pub fn alaw_to_linear(a: u8) -> i16 {
    let a = a ^ 0x55;
    let exp = ((a >> 4) & 0x07) as i32;
    let mantissa = (a & 0x0f) as i32;
    let s = if exp == 0 { (mantissa << 4) + 8 } else { ((mantissa << 4) + 0x108) << (exp - 1) };
    (if a & 0x80 != 0 { s } else { -s }) as i16
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Law {
    A,
    Mu,
}

impl Law {
    /// Maps an SDP encoding name to the companding law.
    pub fn from_name(name: &str) -> Option<Law> {
        if name.eq_ignore_ascii_case("PCMA") {
            Some(Law::A)
        } else if name.eq_ignore_ascii_case("PCMU") {
            Some(Law::Mu)
        } else {
            None
        }
    }

    pub fn encode(self, pcm: &[i16], out: &mut Vec<u8>) {
        out.clear();
        match self {
            Law::A => out.extend(pcm.iter().map(|s| linear_to_alaw(*s))),
            Law::Mu => out.extend(pcm.iter().map(|s| linear_to_ulaw(*s))),
        }
    }

    pub fn decode(self, data: &[u8], out: &mut Vec<i16>) {
        out.clear();
        match self {
            Law::A => out.extend(data.iter().map(|b| alaw_to_linear(*b))),
            Law::Mu => out.extend(data.iter().map(|b| ulaw_to_linear(*b))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_values() {
        // Digital silence and full scale as defined by G.711.
        assert_eq!(linear_to_ulaw(0), 0xff);
        assert_eq!(linear_to_alaw(0), 0xd5);
        assert_eq!(linear_to_ulaw(i16::MAX), 0x80);
        assert_eq!(linear_to_ulaw(i16::MIN), 0x00);
        assert_eq!(linear_to_alaw(i16::MAX), 0xaa);
        assert_eq!(linear_to_alaw(i16::MIN), 0x2a);
        assert_eq!(ulaw_to_linear(0xff), 0);
        assert_eq!(alaw_to_linear(0xd5), 8);
    }

    #[test]
    fn roundtrip_error_is_bounded() {
        for s in (i16::MIN..=i16::MAX).step_by(7) {
            // Quantisation step grows with amplitude: about 1/16 of the value, at least 16.
            let limit = (s as i32).abs() / 16 + 16;
            let a = alaw_to_linear(linear_to_alaw(s)) as i32;
            assert!((a - s as i32).abs() <= limit, "alaw {s} -> {a}");
            // mu-law clips at 32635.
            let u = ulaw_to_linear(linear_to_ulaw(s)) as i32;
            let limit_u = limit + (32767 - ULAW_CLIP) + 16;
            assert!((u - s as i32).abs() <= limit_u, "ulaw {s} -> {u}");
        }
    }

    #[test]
    fn codes_are_stable() {
        // Decoding and re-encoding any code must give the same code back
        // (except the two mu-law zero codes, which both mean 0).
        for code in 0..=255u8 {
            assert_eq!(linear_to_alaw(alaw_to_linear(code)), code);
            if code != 0x7f {
                assert_eq!(linear_to_ulaw(ulaw_to_linear(code)), code);
            }
        }
    }

    #[test]
    fn law_helpers() {
        assert_eq!(Law::from_name("pcma"), Some(Law::A));
        assert_eq!(Law::from_name("opus"), None);
        let mut enc = Vec::new();
        let mut dec = Vec::new();
        Law::Mu.encode(&[0, 1000, -1000], &mut enc);
        Law::Mu.decode(&enc, &mut dec);
        assert_eq!(dec.len(), 3);
        assert!((dec[1] - 1000).abs() < 64 && (dec[2] + 1000).abs() < 64);
    }
}
