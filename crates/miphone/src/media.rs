//! Audio path of a call: sound card <-> codec <-> RTP over UDP.
//!
//! Everything runs on plain threads: one owning the audio streams, one sending a packet
//! every 20 ms and one receiving. The buffers between sound card and network hold mono
//! samples at the codec's rate: 8 kHz for G.711, 16 kHz for Opus.

use std::collections::VecDeque;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use misip::g711::Law;
use misip::rtp::{dtmf_event, dtmf_payload, RtpPacket};

/// Opus settings the Mitel client announces: wideband, 16 kbit/s average, in-band FEC.
pub const OPUS_FMTP: &str =
    "maxaveragebitrate=16000;maxplaybackrate=16000;stereo=0;cbr=0;useinbandfec=1;usedtx=0;sprop-maxcapturerate=16000;sprop-stereo=0;minptime=20";
const OPUS_RATE: u32 = 16000;
const OPUS_BITRATE: i32 = 16000;
/// Largest frame a peer may send in one packet (120 ms at 16 kHz).
const OPUS_MAX_FRAME: usize = 1920;

/// Sound devices to use for calls, by name. `None` means the system default.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AudioDevices {
    pub input: Option<String>,
    pub output: Option<String>,
}

/// Device choice shared with the user interface; read at the start of each call.
pub type AudioSettings = Arc<Mutex<AudioDevices>>;

/// Names of the available input and output devices.
pub fn list_devices() -> (Vec<String>, Vec<String>) {
    let host = cpal::default_host();
    let names = |devices: Option<Vec<cpal::Device>>| -> Vec<String> {
        let mut names: Vec<String> = devices.unwrap_or_default().iter().filter_map(device_name).collect();
        names.dedup();
        names
    };
    (names(host.input_devices().ok().map(Iterator::collect)), names(host.output_devices().ok().map(Iterator::collect)))
}

pub(crate) fn device_name(device: &cpal::Device) -> Option<String> {
    device.description().ok().map(|d| d.name().to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioCodec {
    G711(Law),
    Opus,
}

impl AudioCodec {
    /// Codec for an SDP encoding name, if we implement it.
    pub fn from_name(name: &str) -> Option<AudioCodec> {
        if name.eq_ignore_ascii_case("opus") {
            Some(AudioCodec::Opus)
        } else {
            Law::from_name(name).map(AudioCodec::G711)
        }
    }

    /// Sample rate of the PCM we feed the codec.
    fn sample_rate(self) -> u32 {
        match self {
            AudioCodec::G711(_) => 8000,
            AudioCodec::Opus => OPUS_RATE,
        }
    }

    /// Samples per 20 ms frame.
    fn frame_len(self) -> usize {
        self.sample_rate() as usize / 50
    }

    /// RTP timestamp units per 20 ms; Opus always counts at 48 kHz (RFC 7587).
    fn timestamp_step(self) -> u32 {
        match self {
            AudioCodec::G711(_) => 160,
            AudioCodec::Opus => 960,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MediaConfig {
    pub remote: Option<SocketAddr>,
    pub codec: AudioCodec,
    pub payload_type: u8,
    pub dtmf_payload_type: Option<u8>,
    pub send: bool,
    pub recv: bool,
}

struct State {
    cfg: Option<MediaConfig>,
    muted: bool,
    dtmf: VecDeque<u8>,
}

struct Shared {
    stop: AtomicBool,
    socket: UdpSocket,
    state: Mutex<State>,
    /// Sample rate of `capture` and `playback`.
    rate: AtomicU32,
    capture: Mutex<VecDeque<i16>>,
    playback: Mutex<VecDeque<i16>>,
}

impl Shared {
    /// Audio beyond 300 ms is dropped to bound the delay.
    fn max_buffered(&self) -> usize {
        self.rate.load(Ordering::Relaxed) as usize * 300 / 1000
    }
}

pub struct Media {
    shared: Arc<Shared>,
    port: u16,
}

impl Media {
    /// Binds the RTP socket and starts the threads. Nothing is sent until `configure` is called.
    /// Without `audio` no sound device is opened and silence is sent.
    pub fn start(audio: Option<&AudioSettings>) -> std::io::Result<Media> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(Duration::from_millis(100)))?;
        let port = socket.local_addr()?.port();
        let shared = Arc::new(Shared {
            stop: AtomicBool::new(false),
            socket,
            state: Mutex::new(State { cfg: None, muted: false, dtmf: VecDeque::new() }),
            rate: AtomicU32::new(8000),
            capture: Mutex::new(VecDeque::new()),
            playback: Mutex::new(VecDeque::new()),
        });
        if let Some(settings) = audio {
            let devices = settings.lock().unwrap().clone();
            let s = shared.clone();
            std::thread::spawn(move || audio_thread(s, devices));
        }
        let s = shared.clone();
        std::thread::spawn(move || send_thread(s));
        let s = shared.clone();
        std::thread::spawn(move || receive_thread(s));
        Ok(Media { shared, port })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn configure(&self, cfg: MediaConfig) {
        let rate = cfg.codec.sample_rate();
        let mut st = self.shared.state.lock().unwrap();
        if self.shared.rate.swap(rate, Ordering::Relaxed) != rate {
            // Buffered samples have the old rate and would play at the wrong speed.
            self.shared.capture.lock().unwrap().clear();
            self.shared.playback.lock().unwrap().clear();
        }
        st.cfg = Some(cfg);
    }

    pub fn set_muted(&self, muted: bool) {
        self.shared.state.lock().unwrap().muted = muted;
    }

    /// Queues DTMF digits; unknown characters are ignored. Returns false if the peer does not accept telephone events.
    pub fn send_dtmf(&self, digits: &str) -> bool {
        let mut st = self.shared.state.lock().unwrap();
        if st.cfg.as_ref().and_then(|c| c.dtmf_payload_type).is_none() {
            return false;
        }
        st.dtmf.extend(digits.chars().filter_map(dtmf_event));
        true
    }
}

impl Drop for Media {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::Relaxed);
    }
}

fn new_opus_encoder() -> Option<opus::Encoder> {
    let mut enc = opus::Encoder::new(OPUS_RATE, opus::Channels::Mono, opus::Application::Voip).ok()?;
    enc.set_bitrate(opus::Bitrate::Bits(OPUS_BITRATE)).ok()?;
    enc.set_inband_fec(true).ok()?;
    enc.set_packet_loss_perc(5).ok()?;
    Some(enc)
}

fn send_thread(sh: Arc<Shared>) {
    const EVENT_TICKS: u16 = 5; // 100 ms tone
    const GAP_TICKS: u16 = 3; // 60 ms pause between digits
    const EVENT_STEP: u16 = 160; // telephone-event durations count at 8 kHz
    let ssrc: u32 = rand::random();
    let mut seq: u16 = rand::random();
    let mut ts: u32 = rand::random();
    let mut first = true;
    // Current DTMF event: (event code, start timestamp, ticks elapsed)
    let mut event: Option<(u8, u32, u16)> = None;
    let mut gap = 0u16;
    let mut encoder: Option<opus::Encoder> = None;
    let mut pcm: Vec<i16> = Vec::new();
    let mut payload = Vec::with_capacity(512);
    let mut packet = Vec::with_capacity(512 + 12);
    let mut next = Instant::now();
    while !sh.stop.load(Ordering::Relaxed) {
        next += Duration::from_millis(20);
        let now = Instant::now();
        if next > now {
            std::thread::sleep(next - now);
        } else if now - next > Duration::from_millis(200) {
            next = now; // we were suspended; do not send a burst
        }

        let (cfg, muted) = {
            let mut st = sh.state.lock().unwrap();
            if event.is_none() && gap == 0 {
                if let Some(code) = st.dtmf.pop_front() {
                    event = Some((code, ts, 0));
                }
            }
            (st.cfg.clone(), st.muted)
        };
        let codec = cfg.as_ref().map(|c| c.codec).unwrap_or(AudioCodec::G711(Law::A));

        // Always drain the microphone, also while nothing is sent, so no stale audio piles up.
        {
            let mut cap = sh.capture.lock().unwrap();
            let excess = cap.len().saturating_sub(sh.max_buffered());
            cap.drain(..excess);
            pcm.clear();
            pcm.extend((0..codec.frame_len()).map(|_| cap.pop_front().unwrap_or(0)));
        }

        let frame_ts = ts;
        ts = ts.wrapping_add(codec.timestamp_step());
        let Some(cfg) = cfg else { continue };
        let Some(remote) = cfg.remote.filter(|_| cfg.send) else { continue };

        if let (Some((code, start, ticks)), Some(pt)) = (event, cfg.dtmf_payload_type) {
            let ticks = ticks + 1;
            let end = ticks >= EVENT_TICKS;
            let body = dtmf_payload(code, end, 10, ticks * EVENT_STEP);
            // The final packet is sent three times, as RFC 4733 recommends.
            for _ in 0..if end { 3 } else { 1 } {
                RtpPacket { marker: ticks == 1, payload_type: pt, sequence: seq, timestamp: start, ssrc, payload: &body }.write(&mut packet);
                seq = seq.wrapping_add(1);
                let _ = sh.socket.send_to(&packet, remote);
            }
            if end {
                event = None;
                gap = GAP_TICKS;
            } else {
                event = Some((code, start, ticks));
            }
            continue;
        }
        event = None;
        if gap > 0 {
            gap -= 1;
            continue;
        }

        if muted {
            pcm.iter_mut().for_each(|s| *s = 0);
        }
        match codec {
            AudioCodec::G711(law) => {
                encoder = None;
                law.encode(&pcm, &mut payload);
            }
            AudioCodec::Opus => {
                if encoder.is_none() {
                    encoder = new_opus_encoder();
                }
                let Some(enc) = encoder.as_mut() else { continue };
                payload.resize(512, 0);
                match enc.encode(&pcm, &mut payload) {
                    Ok(n) => payload.truncate(n),
                    Err(_) => continue,
                }
            }
        }
        RtpPacket { marker: first, payload_type: cfg.payload_type, sequence: seq, timestamp: frame_ts, ssrc, payload: &payload }.write(&mut packet);
        first = false;
        seq = seq.wrapping_add(1);
        let _ = sh.socket.send_to(&packet, remote);
    }
}

fn receive_thread(sh: Arc<Shared>) {
    let mut buf = [0u8; 2048];
    let mut pcm: Vec<i16> = Vec::with_capacity(OPUS_MAX_FRAME);
    let mut decoder: Option<opus::Decoder> = None;
    while !sh.stop.load(Ordering::Relaxed) {
        let Ok((n, _from)) = sh.socket.recv_from(&mut buf) else { continue };
        let Some(pkt) = RtpPacket::parse(&buf[..n]) else { continue };
        let cfg = sh.state.lock().unwrap().cfg.clone();
        let Some(cfg) = cfg else { continue };
        if !cfg.recv || pkt.payload_type != cfg.payload_type || pkt.payload.is_empty() {
            continue;
        }
        match cfg.codec {
            AudioCodec::G711(law) => {
                decoder = None;
                law.decode(pkt.payload, &mut pcm);
            }
            AudioCodec::Opus => {
                if decoder.is_none() {
                    decoder = opus::Decoder::new(OPUS_RATE, opus::Channels::Mono).ok();
                }
                let Some(dec) = decoder.as_mut() else { continue };
                pcm.resize(OPUS_MAX_FRAME, 0);
                match dec.decode(pkt.payload, &mut pcm, false) {
                    Ok(samples) => pcm.truncate(samples),
                    Err(_) => continue,
                }
            }
        }
        let mut play = sh.playback.lock().unwrap();
        play.extend(pcm.iter());
        let excess = play.len().saturating_sub(sh.max_buffered());
        play.drain(..excess);
    }
}

/// Opens the default input and output devices and keeps the streams alive until the call ends.
fn audio_thread(sh: Arc<Shared>, devices: AudioDevices) {
    let host = cpal::default_host();
    let output = match open_output(&host, sh.clone(), devices.output.as_deref()) {
        Ok(s) => Some(s),
        Err(e) => {
            eprintln!("Audioausgabe nicht verfuegbar: {e}");
            None
        }
    };
    let input = match open_input(&host, sh.clone(), devices.input.as_deref()) {
        Ok(s) => Some(s),
        Err(e) => {
            eprintln!("Mikrofon nicht verfuegbar: {e}");
            None
        }
    };
    while !sh.stop.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(50));
    }
    drop(input);
    drop(output);
}

fn open_output(host: &cpal::Host, sh: Arc<Shared>, name: Option<&str>) -> anyhow::Result<cpal::Stream> {
    // A chosen device that has disappeared (unplugged headset) falls back to the default.
    let chosen = name.and_then(|n| host.output_devices().ok()?.find(|d| device_name(d).as_deref() == Some(n)));
    let device = chosen.or_else(|| host.default_output_device()).ok_or_else(|| anyhow::anyhow!("kein Ausgabegeraet"))?;
    let supported = device.default_output_config()?;
    let format = supported.sample_format();
    let config: cpal::StreamConfig = supported.into();
    let stream = match format {
        cpal::SampleFormat::F32 => build_output::<f32>(&device, &config, sh)?,
        cpal::SampleFormat::I16 => build_output::<i16>(&device, &config, sh)?,
        cpal::SampleFormat::U16 => build_output::<u16>(&device, &config, sh)?,
        other => anyhow::bail!("nicht unterstuetztes Ausgabeformat {other:?}"),
    };
    stream.play()?;
    Ok(stream)
}

fn open_input(host: &cpal::Host, sh: Arc<Shared>, name: Option<&str>) -> anyhow::Result<cpal::Stream> {
    let chosen = name.and_then(|n| host.input_devices().ok()?.find(|d| device_name(d).as_deref() == Some(n)));
    let device = chosen.or_else(|| host.default_input_device()).ok_or_else(|| anyhow::anyhow!("kein Eingabegeraet"))?;
    let supported = device.default_input_config()?;
    let format = supported.sample_format();
    let config: cpal::StreamConfig = supported.into();
    let stream = match format {
        cpal::SampleFormat::F32 => build_input::<f32>(&device, &config, sh)?,
        cpal::SampleFormat::I16 => build_input::<i16>(&device, &config, sh)?,
        cpal::SampleFormat::U16 => build_input::<u16>(&device, &config, sh)?,
        other => anyhow::bail!("nicht unterstuetztes Eingabeformat {other:?}"),
    };
    stream.play()?;
    Ok(stream)
}

/// Playback: samples at the codec rate are stretched to the device rate by linear interpolation.
fn build_output<T>(device: &cpal::Device, config: &cpal::StreamConfig, sh: Arc<Shared>) -> anyhow::Result<cpal::Stream>
where
    T: cpal::SizedSample + cpal::FromSample<f32>,
{
    let channels = config.channels as usize;
    let device_rate = sample_rate_hz(config) as f32;
    let mut phase = 1.0f32;
    let (mut prev, mut cur) = (0.0f32, 0.0f32);
    let stream = device.build_output_stream(
        *config,
        move |data: &mut [T], _: &cpal::OutputCallbackInfo| {
            let step = sh.rate.load(Ordering::Relaxed) as f32 / device_rate;
            let mut play = sh.playback.lock().unwrap();
            for frame in data.chunks_mut(channels) {
                while phase >= 1.0 {
                    phase -= 1.0;
                    prev = cur;
                    cur = play.pop_front().map(|s| s as f32 / 32768.0).unwrap_or(0.0);
                }
                let v = prev + (cur - prev) * phase;
                phase += step;
                for out in frame.iter_mut() {
                    *out = T::from_sample(v);
                }
            }
        },
        |e| eprintln!("Audioausgabe: {e}"),
        None,
    )?;
    Ok(stream)
}

/// Capture: the first channel is averaged down to the codec rate.
fn build_input<T>(device: &cpal::Device, config: &cpal::StreamConfig, sh: Arc<Shared>) -> anyhow::Result<cpal::Stream>
where
    T: cpal::SizedSample,
    f32: cpal::FromSample<T>,
{
    use cpal::Sample;
    let channels = config.channels as usize;
    let device_rate = sample_rate_hz(config) as f32;
    let mut phase = 0.0f32;
    let (mut acc, mut count) = (0.0f32, 0u32);
    let stream = device.build_input_stream(
        *config,
        move |data: &[T], _: &cpal::InputCallbackInfo| {
            let step = sh.rate.load(Ordering::Relaxed) as f32 / device_rate;
            let mut cap = sh.capture.lock().unwrap();
            for frame in data.chunks(channels) {
                acc += f32::from_sample(frame[0]);
                count += 1;
                phase += step;
                if phase >= 1.0 {
                    phase -= 1.0;
                    let v = (acc / count as f32).clamp(-1.0, 1.0);
                    cap.push_back((v * 32767.0) as i16);
                    acc = 0.0;
                    count = 0;
                }
            }
        },
        |e| eprintln!("Mikrofon: {e}"),
        None,
    )?;
    Ok(stream)
}

fn sample_rate_hz(config: &cpal::StreamConfig) -> u32 {
    config.sample_rate
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(remote: SocketAddr, codec: AudioCodec, pt: u8) -> MediaConfig {
        MediaConfig { remote: Some(remote), codec, payload_type: pt, dtmf_payload_type: Some(101), send: true, recv: true }
    }

    fn addr(m: &Media) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], m.port()))
    }

    fn rms(samples: &[i16]) -> f64 {
        (samples.iter().map(|s| (*s as f64).powi(2)).sum::<f64>() / samples.len().max(1) as f64).sqrt()
    }

    /// Two sessions on the loopback interface exchange audio and DTMF.
    #[test]
    fn rtp_flows_between_two_sessions() {
        const FRAME: usize = 160;
        let a = Media::start(None).unwrap();
        let b = Media::start(None).unwrap();
        let pcma = AudioCodec::G711(Law::A);
        // A known level on A's "microphone" must arrive at B's "speaker".
        a.shared.capture.lock().unwrap().extend(std::iter::repeat_n(8000i16, FRAME * 5));
        a.configure(config(addr(&b), pcma, 8));
        b.configure(config(addr(&a), pcma, 8));
        std::thread::sleep(Duration::from_millis(250));
        let heard: Vec<i16> = b.shared.playback.lock().unwrap().iter().copied().collect();
        assert!(heard.len() >= FRAME * 5, "only {} samples arrived", heard.len());
        assert!(heard.iter().filter(|s| (**s - 8000).abs() < 300).count() >= FRAME * 4, "level was not transported");
        assert!(a.shared.playback.lock().unwrap().len() >= FRAME * 5);

        // DTMF goes out as telephone-event packets, which must not end up as audio.
        let probe = UdpSocket::bind("127.0.0.1:0").unwrap();
        probe.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        a.configure(config(probe.local_addr().unwrap(), AudioCodec::G711(Law::Mu), 0));
        assert!(a.send_dtmf("5"));
        let mut buf = [0u8; 256];
        let mut events = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline && events.len() < 7 {
            let Ok((n, _)) = probe.recv_from(&mut buf) else { break };
            let p = RtpPacket::parse(&buf[..n]).unwrap();
            if p.payload_type == 101 {
                events.push((p.marker, p.timestamp, p.payload.to_vec()));
            }
        }
        assert_eq!(events.len(), 7, "4 running packets and 3 end packets expected");
        assert!(events[0].0 && !events[1].0, "marker only on the first packet");
        assert!(events.iter().all(|e| e.1 == events[0].1 && e.2[0] == 5), "same timestamp and event code");
        assert_eq!(events[0].2[1] & 0x80, 0);
        assert!(events[4..].iter().all(|e| e.2[1] & 0x80 != 0 && e.2[2..] == [0x03, 0x20]), "end flag and 100 ms duration");

        // Receive-disabled sessions stay silent.
        b.configure(MediaConfig { recv: false, ..config(addr(&a), pcma, 8) });
        std::thread::sleep(Duration::from_millis(60));
        b.shared.playback.lock().unwrap().clear();
        a.configure(config(addr(&b), pcma, 8));
        std::thread::sleep(Duration::from_millis(100));
        assert!(b.shared.playback.lock().unwrap().is_empty());
    }

    /// A tone survives the trip through the Opus encoder, RTP and the decoder at 16 kHz.
    #[test]
    fn opus_carries_wideband_audio() {
        let a = Media::start(None).unwrap();
        let probe = UdpSocket::bind("127.0.0.1:0").unwrap();
        probe.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        a.configure(config(probe.local_addr().unwrap(), AudioCodec::Opus, 124));
        // 5 kHz is above what an 8 kHz codec can carry at all.
        let tone: Vec<i16> = (0..OPUS_RATE as usize / 4)
            .map(|i| ((i as f64 * 5000.0 * std::f64::consts::TAU / OPUS_RATE as f64).sin() * 8000.0) as i16)
            .collect();
        a.shared.capture.lock().unwrap().extend(tone.iter());

        let mut dec = opus::Decoder::new(OPUS_RATE, opus::Channels::Mono).unwrap();
        let mut buf = [0u8; 1500];
        let mut out = vec![0i16; OPUS_MAX_FRAME];
        let mut decoded = Vec::new();
        let mut last: Option<(u16, u32)> = None;
        for _ in 0..11 {
            let (n, _) = probe.recv_from(&mut buf).expect("no RTP packet");
            let p = RtpPacket::parse(&buf[..n]).unwrap();
            assert_eq!(p.payload_type, 124);
            assert!(p.payload.len() < 160, "about 16 kbit/s expected, got {} bytes per 20 ms", p.payload.len());
            if let Some((seq, ts)) = last {
                assert_eq!(p.sequence, seq.wrapping_add(1));
                assert_eq!(p.timestamp, ts.wrapping_add(960), "Opus timestamps count at 48 kHz");
            }
            last = Some((p.sequence, p.timestamp));
            let samples = dec.decode(p.payload, &mut out, false).unwrap();
            assert_eq!(samples, 320, "20 ms at 16 kHz");
            decoded.extend_from_slice(&out[..samples]);
        }
        // Skip the codec's start-up; the tone lasts 250 ms.
        let level = rms(&decoded[640..3200]);
        assert!(level > 2000.0 && level < 9000.0, "tone level after Opus: {level}");
    }

    /// Switching the codec during a call changes the buffer rate and drops stale samples.
    #[test]
    fn codec_switch_resets_buffers() {
        let a = Media::start(None).unwrap();
        let b = Media::start(None).unwrap();
        a.configure(config(addr(&b), AudioCodec::G711(Law::A), 8));
        b.configure(config(addr(&a), AudioCodec::G711(Law::A), 8));
        std::thread::sleep(Duration::from_millis(100));
        assert!(!b.shared.playback.lock().unwrap().is_empty());
        a.configure(config(addr(&b), AudioCodec::Opus, 124));
        b.configure(config(addr(&a), AudioCodec::Opus, 124));
        assert_eq!(b.shared.rate.load(Ordering::Relaxed), 16000);
        std::thread::sleep(Duration::from_millis(200));
        let buffered = b.shared.playback.lock().unwrap().len();
        // At least five 20 ms Opus frames of 320 samples arrived since the switch.
        assert!(buffered >= 320 * 5, "buffered {buffered}");
    }
}
