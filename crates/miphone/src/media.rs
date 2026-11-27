//! Audio path of a call: sound card <-> codec <-> RTP over UDP.
//!
//! Everything runs on plain threads: one owning the audio streams, one sending a packet
//! every 20 ms and one receiving. The buffers between sound card and network hold mono
//! samples at the codec's rate: 8 kHz for G.711, 16 kHz for Opus.

use nnnoiseless::DenoiseState;
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioDevices {
    pub input: Option<String>,
    pub output: Option<String>,
    /// Background noise is taken out of the microphone's sound. Unlike the devices, this
    /// also takes effect during a call.
    pub noise_suppression: bool,
}

impl Default for AudioDevices {
    fn default() -> AudioDevices {
        AudioDevices { input: None, output: None, noise_suppression: true }
    }
}

/// Device choice shared with the user interface; the devices are read at the start of each
/// call.
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
            let settings = settings.clone();
            let s = shared.clone();
            std::thread::spawn(move || audio_thread(s, settings));
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
fn audio_thread(sh: Arc<Shared>, settings: AudioSettings) {
    let devices = settings.lock().unwrap().clone();
    let host = cpal::default_host();
    let output = match open_output(&host, sh.clone(), devices.output.as_deref()) {
        Ok(s) => Some(s),
        Err(e) => {
            eprintln!("Audioausgabe nicht verfuegbar: {e}");
            None
        }
    };
    let input = match open_input(&host, sh.clone(), devices.input.as_deref(), settings) {
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

fn open_input(host: &cpal::Host, sh: Arc<Shared>, name: Option<&str>, settings: AudioSettings) -> anyhow::Result<cpal::Stream> {
    let chosen = name.and_then(|n| host.input_devices().ok()?.find(|d| device_name(d).as_deref() == Some(n)));
    let device = chosen.or_else(|| host.default_input_device()).ok_or_else(|| anyhow::anyhow!("kein Eingabegeraet"))?;
    let supported = device.default_input_config()?;
    let format = supported.sample_format();
    let config: cpal::StreamConfig = supported.into();
    let stream = match format {
        cpal::SampleFormat::F32 => build_input::<f32>(&device, &config, sh, settings)?,
        cpal::SampleFormat::I16 => build_input::<i16>(&device, &config, sh, settings)?,
        cpal::SampleFormat::U16 => build_input::<u16>(&device, &config, sh, settings)?,
        other => anyhow::bail!("nicht unterstuetztes Eingabeformat {other:?}"),
    };
    stream.play()?;
    Ok(stream)
}

/// Zero crossings of the resampling filter on each side of its centre.
const FILTER_ZEROS: usize = 16;
/// Entries of the filter table between two zero crossings.
const FILTER_STEPS: usize = 64;
/// The filter cuts off a little below half the lower sample rate, to have room to fall off.
const FILTER_CUTOFF: f32 = 0.95;
/// After the sound ran out, this much is collected before it plays again, so that packets
/// arriving a little unevenly do not tear a hole into it each time.
const PLAYBACK_CUSHION_MS: usize = 40;

/// The filter: a sinc under a Blackman window, from its centre to its last zero crossing.
fn filter_table() -> &'static [f32] {
    static TABLE: std::sync::OnceLock<Vec<f32>> = std::sync::OnceLock::new();
    TABLE.get_or_init(|| {
        let len = FILTER_ZEROS * FILTER_STEPS;
        (0..=len + 1)
            .map(|i| {
                let u = i as f32 / FILTER_STEPS as f32;
                let x = (i as f32 / len as f32).min(1.0) * std::f32::consts::PI;
                let window = 0.42 + 0.5 * x.cos() + 0.08 * (2.0 * x).cos();
                let sinc = if i == 0 { 1.0 } else { (std::f32::consts::PI * u).sin() / (std::f32::consts::PI * u) };
                sinc * window
            })
            .collect()
    })
}

/// Converts sound from one sample rate to another with a low-pass filter. Without the
/// filter, sound stretched to a higher rate gets mirror images of itself above the old
/// range (it sounds tinny), and sound squeezed to a lower rate gets what no longer fits
/// folded back into it.
struct Resampler {
    from: u32,
    /// Input samples per output sample.
    step: f64,
    /// Zero crossings of the filter per input sample.
    scale: f32,
    half: usize,
    /// The last `2 * half` input samples.
    window: VecDeque<f32>,
    /// Where the next output sample lies, in input samples after `window[half - 1]`.
    phase: f64,
}

impl Resampler {
    fn new(from: u32, to: u32) -> Resampler {
        let scale = (to as f32 / from as f32).min(1.0) * FILTER_CUTOFF;
        let half = (FILTER_ZEROS as f32 / scale).ceil() as usize;
        Resampler { from, step: from as f64 / to as f64, scale, half, window: VecDeque::from(vec![0.0; 2 * half]), phase: 1.0 }
    }

    fn shift(&mut self, sample: f32) {
        self.window.pop_front();
        self.window.push_back(sample);
        self.phase -= 1.0;
    }

    fn value(&self) -> f32 {
        let table = filter_table();
        let centre = (self.half - 1) as f32 + self.phase as f32;
        let (mut sum, mut weights) = (0.0f32, 0.0f32);
        for (i, sample) in self.window.iter().enumerate() {
            let at = (i as f32 - centre).abs() * self.scale * FILTER_STEPS as f32;
            let index = at as usize;
            if index < table.len() - 1 {
                let weight = table[index] + (table[index + 1] - table[index]) * (at - index as f32);
                sum += sample * weight;
                weights += weight;
            }
        }
        // Dividing by the weights keeps the loudness the same wherever the sample lies.
        if weights.abs() > 1e-6 { sum / weights } else { 0.0 }
    }

    /// The next output sample; `input` is asked for as many input samples as it takes.
    fn pull(&mut self, mut input: impl FnMut() -> f32) -> f32 {
        while self.phase >= 1.0 {
            self.shift(input());
        }
        let value = self.value();
        self.phase += self.step;
        value
    }

    /// Takes one input sample and hands out the output samples that are due with it.
    fn push(&mut self, sample: f32, mut output: impl FnMut(f32)) {
        self.shift(sample);
        while self.phase < 1.0 {
            output(self.value());
            self.phase += self.step;
        }
    }
}

/// Playback: samples at the codec rate are converted to the rate of the device.
fn build_output<T>(device: &cpal::Device, config: &cpal::StreamConfig, sh: Arc<Shared>) -> anyhow::Result<cpal::Stream>
where
    T: cpal::SizedSample + cpal::FromSample<f32>,
{
    let channels = config.channels as usize;
    let device_rate = sample_rate_hz(config);
    let mut resampler = Resampler::new(sh.rate.load(Ordering::Relaxed), device_rate);
    // Nothing plays until the cushion is there.
    let mut filling = true;
    let stream = device.build_output_stream(
        *config,
        move |data: &mut [T], _: &cpal::OutputCallbackInfo| {
            let rate = sh.rate.load(Ordering::Relaxed);
            if resampler.from != rate {
                resampler = Resampler::new(rate, device_rate);
                filling = true;
            }
            let mut play = sh.playback.lock().unwrap();
            if filling && play.len() >= rate as usize * PLAYBACK_CUSHION_MS / 1000 {
                filling = false;
            }
            for frame in data.chunks_mut(channels) {
                let v = resampler.pull(|| {
                    if filling {
                        return 0.0;
                    }
                    match play.pop_front() {
                        Some(s) => s as f32 / 32768.0,
                        None => {
                            filling = true;
                            0.0
                        }
                    }
                });
                for out in frame.iter_mut() {
                    *out = T::from_sample(v.clamp(-1.0, 1.0));
                }
            }
        },
        |e| eprintln!("Audioausgabe: {e}"),
        None,
    )?;
    Ok(stream)
}

/// The rate the noise suppression works at.
const DENOISE_RATE: u32 = 48000;

/// The way of the microphone's sound to the codec: to 48 kHz, through the noise suppression
/// (RNNoise) if it is on, then to the rate of the codec.
struct Capture {
    /// Not needed for a device that runs at 48 kHz.
    to_48k: Option<Resampler>,
    to_codec: Resampler,
    codec_rate: u32,
    denoise: Box<DenoiseState<'static>>,
    /// Sound at 48 kHz waiting to fill a frame of the noise suppression, in its scale (16 bit).
    frame: Vec<f32>,
    cleaned: [f32; DenoiseState::FRAME_SIZE],
    at_48k: Vec<f32>,
}

impl Capture {
    fn new(device_rate: u32, codec_rate: u32) -> Capture {
        Capture {
            to_48k: (device_rate != DENOISE_RATE).then(|| Resampler::new(device_rate, DENOISE_RATE)),
            to_codec: Resampler::new(DENOISE_RATE, codec_rate),
            codec_rate,
            denoise: DenoiseState::new(),
            frame: Vec::with_capacity(DenoiseState::FRAME_SIZE),
            cleaned: [0.0; DenoiseState::FRAME_SIZE],
            at_48k: Vec::new(),
        }
    }

    /// Takes one sample of the device (between -1 and 1) and appends to `out` what is due
    /// at the rate of the codec.
    fn feed(&mut self, sample: f32, codec_rate: u32, suppress_noise: bool, out: &mut VecDeque<i16>) {
        if codec_rate != self.codec_rate {
            self.codec_rate = codec_rate;
            self.to_codec = Resampler::new(DENOISE_RATE, codec_rate);
        }
        let Capture { to_48k, to_codec, denoise, frame, cleaned, at_48k, .. } = self;
        at_48k.clear();
        match to_48k {
            Some(resampler) => resampler.push(sample, |v| at_48k.push(v)),
            None => at_48k.push(sample),
        }
        let mut emit = |v: f32| out.push_back((v.clamp(-1.0, 1.0) * 32767.0) as i16);
        for &v in at_48k.iter() {
            if suppress_noise {
                frame.push(v * 32768.0);
                if frame.len() == DenoiseState::FRAME_SIZE {
                    denoise.process_frame(cleaned, frame);
                    frame.clear();
                    for cleaned in cleaned.iter() {
                        to_codec.push(cleaned / 32768.0, &mut emit);
                    }
                }
            } else {
                // Switched off in the middle of a frame: what waited goes out as it is.
                for waiting in frame.drain(..) {
                    to_codec.push(waiting / 32768.0, &mut emit);
                }
                to_codec.push(v, &mut emit);
            }
        }
    }
}

/// Capture: the first channel goes through the noise suppression and to the codec rate.
fn build_input<T>(device: &cpal::Device, config: &cpal::StreamConfig, sh: Arc<Shared>, settings: AudioSettings) -> anyhow::Result<cpal::Stream>
where
    T: cpal::SizedSample,
    f32: cpal::FromSample<T>,
{
    use cpal::Sample;
    let channels = config.channels as usize;
    let device_rate = sample_rate_hz(config);
    let mut capture = Capture::new(device_rate, sh.rate.load(Ordering::Relaxed));
    let mut suppress_noise = settings.lock().unwrap().noise_suppression;
    let stream = device.build_input_stream(
        *config,
        move |data: &[T], _: &cpal::InputCallbackInfo| {
            let rate = sh.rate.load(Ordering::Relaxed);
            // The sound must not wait for the user interface; if it holds the settings right
            // now, the last choice stays for this round.
            if let Ok(settings) = settings.try_lock() {
                suppress_noise = settings.noise_suppression;
            }
            let mut cap = sh.capture.lock().unwrap();
            for frame in data.chunks(channels) {
                capture.feed(f32::from_sample(frame[0]), rate, suppress_noise, &mut cap);
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
    /// A tone of `hz` at the rate `from`, converted to the rate `to`: how loud the tone
    /// still is, and how loud everything else is that the conversion added (both as RMS).
    fn convert_tone(hz: f64, from: u32, to: u32, push: bool) -> (f64, f64) {
        let mut resampler = Resampler::new(from, to);
        let mut n = 0u64;
        let mut next = || {
            n += 1;
            (std::f64::consts::TAU * hz * n as f64 / from as f64).sin() as f32 * 0.5
        };
        let mut out = Vec::new();
        if push {
            for _ in 0..from {
                resampler.push(next(), |v| out.push(v as f64));
            }
        } else {
            out.extend((0..to).map(|_| resampler.pull(&mut next) as f64));
        }
        let out = &out[out.len() / 4..]; // without the start, where the filter is still empty
        let part = |f: fn(f64) -> f64| out.iter().enumerate().map(|(i, v)| v * f(std::f64::consts::TAU * hz * i as f64 / to as f64)).sum::<f64>() * 2.0 / out.len() as f64;
        let tone = (part(f64::sin).powi(2) + part(f64::cos).powi(2)) / 2.0;
        let total = out.iter().map(|v| v * v).sum::<f64>() / out.len() as f64;
        (tone.sqrt(), (total - tone).max(0.0).sqrt())
    }

    #[test]
    fn resampling_keeps_the_sound_and_adds_nothing() {
        let level = 0.5 / 2f64.sqrt();
        // Playback of telephone sound (8 kHz) and of Opus (16 kHz) on common devices.
        for (hz, from, to) in [(1000.0, 8000, 48000), (3000.0, 8000, 48000), (3000.0, 8000, 44100), (6000.0, 16000, 48000), (1000.0, 48000, 48000)] {
            let (tone, rest) = convert_tone(hz, from, to, false);
            assert!((tone / level - 1.0).abs() < 0.03, "{hz} Hz {from}->{to}: level {tone}");
            assert!(rest / level < 0.005, "{hz} Hz {from}->{to}: {rest} of other sound");
        }
        // The microphone: what the codec can carry passes ...
        for (hz, from, to) in [(1000.0, 48000, 8000), (3000.0, 44100, 8000), (6000.0, 48000, 16000)] {
            let (tone, rest) = convert_tone(hz, from, to, true);
            assert!((tone / level - 1.0).abs() < 0.03, "{hz} Hz {from}->{to}: level {tone}");
            assert!(rest / level < 0.005, "{hz} Hz {from}->{to}: {rest} of other sound");
        }
        // ... and what it cannot carry is removed, not folded back as a lower tone.
        let (tone, rest) = convert_tone(6000.0, 48000, 8000, true);
        assert!(tone.max(rest) / level < 0.005, "6 kHz at 8 kHz: {tone} / {rest}");
    }

    #[test]
    fn noise_suppression_quiets_noise() {
        // Four seconds of quiet hiss from a 44.1 kHz microphone, for a call with Opus. The
        // suppression needs a moment to tell that this is no speech.
        let run = |suppress: bool| -> (usize, f64) {
            let mut capture = Capture::new(44100, 16000);
            let mut out = VecDeque::new();
            let mut seed = 12345u32;
            for _ in 0..176400 {
                seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
                capture.feed((seed >> 8) as f32 / (1 << 23) as f32 * 0.02 - 0.02, 16000, suppress, &mut out);
            }
            let late: Vec<i16> = out.iter().skip(out.len() * 3 / 4).copied().collect();
            (out.len(), rms(&late))
        };
        let ((plain_len, plain), (clean_len, clean)) = (run(false), run(true));
        assert!(plain_len.abs_diff(64000) <= 2 && clean_len.abs_diff(64000) <= 480, "{plain_len} / {clean_len} samples");
        assert!(plain > 100.0, "the hiss is there without suppression: {plain}");
        assert!(clean < plain / 2.0, "hiss of {plain} is left at {clean}");
    }

    #[test]
    fn resampling_keeps_the_pace() {
        let mut resampler = Resampler::new(8000, 44100);
        let mut asked = 0;
        for _ in 0..44100 {
            resampler.pull(|| {
                asked += 1;
                0.0
            });
        }
        assert!((7999..=8001).contains(&asked), "{asked} samples asked for in a second");
        let mut resampler = Resampler::new(44100, 16000);
        let mut made = 0;
        for _ in 0..44100 {
            resampler.push(0.0, |_| made += 1);
        }
        assert!((15999..=16001).contains(&made), "{made} samples made in a second");
    }

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
