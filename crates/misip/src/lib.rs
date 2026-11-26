//! Protocol building blocks for a Mitel-compatible SIP softphone.
//!
//! Pure data handling without I/O: SIP messages, digest authentication,
//! SDP for audio, RTP packets and G.711.

pub mod digest;
pub mod g711;
pub mod message;
pub mod rtp;
pub mod sdp;

/// Random lowercase hex string with `len` characters.
pub fn random_hex(len: usize) -> String {
    let mut s = String::with_capacity(len + 16);
    while s.len() < len {
        s.push_str(&format!("{:016x}", rand::random::<u64>()));
    }
    s.truncate(len);
    s
}
