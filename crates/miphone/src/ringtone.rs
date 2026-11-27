//! Ringtones: the tones built into the program or a sound file of the user, played in a
//! loop on one or several output devices until the call is answered or gone.
//!
//! Also the tones a telephone line makes while our call rings at the other end or the other
//! end is busy. The telephone system only reports these states; the tone is made here.

use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use symphonia::core::codecs::audio::AudioDecoderOptions;
use symphonia::core::errors::Error as DecodeError;
use symphonia::core::formats::probe::Hint;
use symphonia::core::formats::TrackType;
use symphonia::core::io::{MediaSource, MediaSourceStream};

use crate::media::device_name;

/// The tones that come with the program, with the name shown to the user.
pub const BUILTIN: [(&str, &[u8]); 2] = [
    ("Klingelton 1", include_bytes!("../assets/ringtones/ringtone-030.mp3")),
    ("Klingelton 2", include_bytes!("../assets/ringtones/ringtone-091.mp3")),
];

/// File types offered when the user picks a tone of their own.
pub const FILE_EXTENSIONS: [&str; 4] = ["mp3", "wav", "flac", "ogg"];

/// No more than this much of a sound file is played before it starts over.
const MAX_SECONDS: usize = 60;

/// Which sound rings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tone {
    /// Index into `BUILTIN`.
    Builtin(usize),
    File(PathBuf),
}

impl Default for Tone {
    fn default() -> Tone {
        Tone::Builtin(0)
    }
}

impl Tone {
    /// The tone from its form in the settings; anything unknown is the first built-in tone.
    pub fn from_setting(setting: &str) -> Tone {
        match setting.strip_prefix("builtin:") {
            Some(index) => Tone::Builtin(index.parse().ok().filter(|i| *i < BUILTIN.len()).unwrap_or(0)),
            None if setting.is_empty() => Tone::default(),
            None => Tone::File(PathBuf::from(setting)),
        }
    }

    pub fn to_setting(&self) -> String {
        match self {
            Tone::Builtin(index) => format!("builtin:{index}"),
            Tone::File(path) => path.to_string_lossy().into_owned(),
        }
    }

    /// Name shown to the user: of the built-in tone, or the file name.
    pub fn label(&self) -> String {
        match self {
            Tone::Builtin(index) => BUILTIN.get(*index).unwrap_or(&BUILTIN[0]).0.to_string(),
            Tone::File(path) => path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| path.to_string_lossy().into_owned()),
        }
    }

    fn load(&self) -> Result<Sound> {
        match self {
            Tone::Builtin(index) => decode(Box::new(Cursor::new(BUILTIN.get(*index).unwrap_or(&BUILTIN[0]).1)), Some("mp3")),
            Tone::File(path) => {
                let file = std::fs::File::open(path).with_context(|| format!("{} kann nicht geöffnet werden", path.display()))?;
                decode(Box::new(file), path.extension().and_then(|e| e.to_str())).with_context(|| format!("{} kann nicht abgespielt werden", path.display()))
            }
        }
    }
}

/// A decoded sound: interleaved samples between -1 and 1.
struct Sound {
    rate: u32,
    channels: usize,
    samples: Vec<f32>,
}

impl Sound {
    fn frames(&self) -> usize {
        self.samples.len() / self.channels
    }
}

fn decode(source: Box<dyn MediaSource>, extension: Option<&str>) -> Result<Sound> {
    let mut hint = Hint::new();
    if let Some(extension) = extension {
        hint.with_extension(extension);
    }
    let stream = MediaSourceStream::new(source, Default::default());
    let mut format = symphonia::default::get_probe()
        .probe(&hint, stream, Default::default(), Default::default())
        .map_err(|e| anyhow!("unbekanntes Audioformat ({e})"))?;
    let track = format.default_track(TrackType::Audio).ok_or_else(|| anyhow!("die Datei enthält keinen Ton"))?;
    let track_id = track.id;
    let params = track.codec_params.as_ref().and_then(|p| p.audio()).ok_or_else(|| anyhow!("die Datei enthält keinen Ton"))?;
    let mut decoder = symphonia::default::get_codecs()
        .make_audio_decoder(params, &AudioDecoderOptions::default())
        .map_err(|e| anyhow!("nicht unterstütztes Audioformat ({e})"))?;

    let mut sound = Sound { rate: 0, channels: 0, samples: Vec::new() };
    let mut chunk: Vec<f32> = Vec::new();
    while let Ok(Some(packet)) = format.next_packet() {
        if packet.track_id != track_id {
            continue;
        }
        match decoder.decode(&packet) {
            Ok(buffer) => {
                let (rate, channels) = (buffer.spec().rate(), buffer.spec().channels().count());
                if sound.samples.is_empty() {
                    (sound.rate, sound.channels) = (rate, channels);
                } else if (rate, channels) != (sound.rate, sound.channels) {
                    break; // a file that changes its format midway: keep what we have
                }
                chunk.resize(buffer.samples_interleaved(), 0.0);
                buffer.copy_to_slice_interleaved(&mut chunk);
                sound.samples.extend_from_slice(&chunk);
                if sound.samples.len() >= sound.rate as usize * sound.channels * MAX_SECONDS {
                    break;
                }
            }
            // A damaged packet is skipped; the rest still plays.
            Err(DecodeError::DecodeError(_)) => {}
            Err(_) => break,
        }
    }
    if sound.rate == 0 || sound.channels == 0 || sound.frames() == 0 {
        bail!("die Datei enthält keinen Ton");
    }
    Ok(sound)
}

/// A tone the telephone makes by itself. Those of the line sound as in Germany: 425 Hz in
/// a rhythm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    /// The call rings at the other end: one second of tone, four of silence.
    Ringback,
    /// The other end is busy: tone and silence of 480 ms each.
    Busy,
    /// The call is over: two short tones, the second one lower, as mobile phones make them.
    Ended,
}

impl Signal {
    const RATE: u32 = 8000;
    /// Loud enough to hear, quieter than speech.
    const LEVEL: f32 = 0.18;

    /// The tones in their order, each with its pitch in Hz (0 is silence) and its length
    /// in milliseconds.
    fn pattern(self) -> &'static [(f32, usize)] {
        match self {
            Signal::Ringback => &[(425.0, 1000), (0.0, 4000)],
            Signal::Busy => &[(425.0, 480), (0.0, 480)],
            Signal::Ended => &[(480.0, 140), (0.0, 60), (360.0, 200), (0.0, 400)],
        }
    }

    /// How long a tone that is heard only once plays; the others go on until stopped.
    pub fn once(self) -> Option<Duration> {
        match self {
            // Up to the silence at the end, which leaves room to stop in time.
            Signal::Ended => Some(Duration::from_millis(500)),
            Signal::Ringback | Signal::Busy => None,
        }
    }

    /// One round of the pattern, to be played in a loop.
    fn sound(self) -> Sound {
        let frames = |ms: usize| ms * Self::RATE as usize / 1000;
        let fade = frames(8);
        let mut samples = Vec::new();
        for &(pitch, ms) in self.pattern() {
            let len = frames(ms);
            samples.extend((0..len).map(|i| {
                // Fading in and out keeps the tone from starting and ending with a click.
                let edge = (i.min(len - 1 - i) as f32 / fade as f32).min(1.0);
                (std::f32::consts::TAU * pitch * i as f32 / Self::RATE as f32).sin() * Self::LEVEL * edge
            }));
        }
        Sound { rate: Self::RATE, channels: 1, samples }
    }
}

/// The gain for a volume between 0 and 1. Squared, because loudness is not heard linearly
/// and the lower half of a linear slider would do almost nothing.
fn gain(volume: f32) -> f32 {
    let volume = volume.clamp(0.0, 1.0);
    volume * volume
}

struct Shared {
    stop: AtomicBool,
    /// The gain as the bits of an `f32`.
    gain: AtomicU32,
    error: Mutex<Option<String>>,
}

/// A ringtone that is playing. It rings until this value is dropped.
pub struct Ringer {
    shared: Arc<Shared>,
}

impl Ringer {
    /// Starts ringing on the output devices of these names; none means the system's default
    /// device. Devices that are not there are left out, and if none of them is there the
    /// default device rings. `volume` is between 0 and 1.
    pub fn start(tone: Tone, outputs: Vec<String>, volume: f32) -> Ringer {
        let shared = Arc::new(Shared { stop: AtomicBool::new(false), gain: AtomicU32::new(gain(volume).to_bits()), error: Mutex::new(None) });
        let thread_shared = shared.clone();
        // Decoding takes a moment and the streams must stay on the thread that opened them.
        std::thread::spawn(move || ring_thread(thread_shared, tone, outputs));
        Ringer { shared }
    }

    /// Plays a tone of the telephone on the output device of this name, or on the system's
    /// default device, until this value is dropped or `limit` is over. A tone that is heard
    /// only once ends by itself.
    pub fn signal(signal: Signal, output: Option<String>, limit: Option<Duration>) -> Ringer {
        let limit = signal.once().or(limit);
        let shared = Arc::new(Shared { stop: AtomicBool::new(false), gain: AtomicU32::new(1f32.to_bits()), error: Mutex::new(None) });
        let thread_shared = shared.clone();
        std::thread::spawn(move || play(thread_shared, signal.sound(), output.into_iter().collect(), "Signalton", limit));
        Ringer { shared }
    }

    pub fn set_volume(&self, volume: f32) {
        self.shared.gain.store(gain(volume).to_bits(), Ordering::Relaxed);
    }

    /// A problem that came up since the last call, to tell the user.
    pub fn take_error(&self) -> Option<String> {
        self.shared.error.lock().unwrap().take()
    }
}

impl Drop for Ringer {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::Relaxed);
    }
}

fn ring_thread(shared: Arc<Shared>, tone: Tone, outputs: Vec<String>) {
    let report = |message: String| *shared.error.lock().unwrap() = Some(message);
    let sound = match tone.load() {
        Ok(sound) => sound,
        // A call must not go unheard because the user's file is gone or broken.
        Err(e) if tone != Tone::default() => {
            report(format!("Klingelton: {e:#}. Es klingelt der Standardton."));
            match Tone::default().load() {
                Ok(sound) => sound,
                Err(_) => return,
            }
        }
        Err(e) => return report(format!("Klingelton: {e:#}")),
    };
    play(shared, sound, outputs, "Klingelton", None);
}

/// Plays the sound in a loop on the devices of these names until told to stop or until
/// `limit` is over. `what` names the sound in messages to the user.
fn play(shared: Arc<Shared>, sound: Sound, outputs: Vec<String>, what: &str, limit: Option<Duration>) {
    let report = |message: String| *shared.error.lock().unwrap() = Some(message);
    let sound = Arc::new(sound);

    let host = cpal::default_host();
    let mut devices: Vec<cpal::Device> = match host.output_devices() {
        Ok(all) if !outputs.is_empty() => all.filter(|d| device_name(d).is_some_and(|name| outputs.contains(&name))).collect(),
        _ => Vec::new(),
    };
    if devices.is_empty() {
        devices.extend(host.default_output_device());
    }
    let mut streams = Vec::new();
    for device in &devices {
        match open_stream(device, sound.clone(), shared.clone()) {
            Ok(stream) => streams.push(stream),
            Err(e) => report(format!("{what} auf {}: {e:#}", device_name(device).unwrap_or_else(|| "Ausgabegerät".into()))),
        }
    }
    if streams.is_empty() {
        if devices.is_empty() {
            report(format!("{what}: kein Ausgabegerät gefunden"));
        }
        return;
    }
    let end = limit.map(|limit| Instant::now() + limit);
    while !shared.stop.load(Ordering::Relaxed) && end.is_none_or(|end| Instant::now() < end) {
        std::thread::sleep(Duration::from_millis(30));
    }
    drop(streams);
}

fn open_stream(device: &cpal::Device, sound: Arc<Sound>, shared: Arc<Shared>) -> Result<cpal::Stream> {
    let supported = device.default_output_config()?;
    let format = supported.sample_format();
    let config: cpal::StreamConfig = supported.into();
    let stream = match format {
        cpal::SampleFormat::F32 => build_stream::<f32>(device, &config, sound, shared)?,
        cpal::SampleFormat::I16 => build_stream::<i16>(device, &config, sound, shared)?,
        cpal::SampleFormat::U16 => build_stream::<u16>(device, &config, sound, shared)?,
        other => bail!("nicht unterstütztes Ausgabeformat {other:?}"),
    };
    stream.play()?;
    Ok(stream)
}

/// Plays the sound in a loop, stretched to the rate of the device by linear interpolation.
fn build_stream<T>(device: &cpal::Device, config: &cpal::StreamConfig, sound: Arc<Sound>, shared: Arc<Shared>) -> Result<cpal::Stream>
where
    T: cpal::SizedSample + cpal::FromSample<f32>,
{
    let channels = config.channels as usize;
    let step = sound.rate as f64 / config.sample_rate as f64;
    let mut position = 0.0f64;
    let stream = device.build_output_stream(
        *config,
        move |data: &mut [T], _: &cpal::OutputCallbackInfo| {
            let gain = f32::from_bits(shared.gain.load(Ordering::Relaxed));
            for frame in data.chunks_mut(channels) {
                for (channel, out) in frame.iter_mut().enumerate() {
                    *out = T::from_sample(sample_at(&sound, position, channel) * gain);
                }
                position = (position + step) % sound.frames() as f64;
            }
        },
        |e| eprintln!("Klingelton: {e}"),
        None,
    )?;
    Ok(stream)
}

/// The sound at a position in frames, which may lie between two of them, for one channel
/// of the device. A mono sound goes to every channel; the end wraps around to the start.
fn sample_at(sound: &Sound, position: f64, channel: usize) -> f32 {
    let frames = sound.frames();
    let index = (position as usize).min(frames - 1);
    let fraction = (position - index as f64) as f32;
    let channel = channel % sound.channels;
    let at = |frame: usize| sound.samples[(frame % frames) * sound.channels + channel];
    at(index) + (at(index + 1) - at(index)) * fraction
}

/// Whether a file is one the user may pick, going by its name.
pub fn is_sound_file(path: &Path) -> bool {
    path.extension().and_then(|e| e.to_str()).is_some_and(|e| FILE_EXTENSIONS.contains(&e.to_lowercase().as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_tones_decode() {
        for index in 0..BUILTIN.len() {
            let sound = Tone::Builtin(index).load().unwrap();
            assert!(sound.rate >= 8000 && (1..=2).contains(&sound.channels), "tone {index}: {} Hz, {} channels", sound.rate, sound.channels);
            assert!(sound.frames() > sound.rate as usize, "tone {index} is longer than a second");
            assert!(sound.samples.iter().any(|s| s.abs() > 0.05), "tone {index} is not silent");
            assert!(sound.samples.iter().all(|s| s.abs() <= 1.5));
        }
    }

    /// Rings quietly for a moment on the default device and on every device by name.
    /// Needs a sound device and is heard, so it runs only when asked for:
    /// `cargo test -p miphone rings_on_real_devices -- --ignored`.
    #[test]
    #[ignore]
    fn rings_on_real_devices() {
        let (_, outputs) = crate::media::list_devices();
        for (tone, devices) in [(Tone::Builtin(0), Vec::new()), (Tone::Builtin(1), outputs), (Tone::File(PathBuf::from("fehlt.mp3")), Vec::new())] {
            let (missing_file, all_devices) = (matches!(tone, Tone::File(_)), !devices.is_empty());
            let ringer = Ringer::start(tone, devices, 0.3);
            std::thread::sleep(Duration::from_millis(1200));
            ringer.set_volume(0.15);
            std::thread::sleep(Duration::from_millis(500));
            let error = ringer.take_error();
            if all_devices {
                // One of many devices may be taken by another program; the others still ring.
                println!("all devices: {error:?}");
            } else {
                // A missing file is reported and the default tone rings instead.
                assert_eq!(error.is_some(), missing_file, "{error:?}");
            }
        }
    }

    #[test]
    fn makes_the_tones_of_the_line() {
        for (signal, tone, round) in [(Signal::Ringback, 8000, 40000), (Signal::Busy, 3840, 7680)] {
            let sound = signal.sound();
            assert_eq!((sound.rate, sound.channels, sound.frames()), (8000, 1, round));
            assert!(sound.samples[tone..].iter().all(|s| *s == 0.0), "{signal:?}: silence after the tone");
            assert_eq!(sound.samples[0], 0.0, "{signal:?}: starts softly");
            assert!(sound.samples[tone - 1].abs() < 0.01, "{signal:?}: ends softly");
            let peak = sound.samples.iter().fold(0f32, |peak, s| peak.max(s.abs()));
            assert!((0.17..=0.18).contains(&peak), "{signal:?}: peak {peak}");
            // 425 Hz: the tone crosses zero 850 times a second.
            let crossings = sound.samples[..tone].windows(2).filter(|w| (w[0] < 0.0) != (w[1] < 0.0)).count();
            let expected = 850 * tone / 8000;
            assert!(crossings.abs_diff(expected) <= 2, "{signal:?}: {crossings} crossings, expected {expected}");
        }
    }

    #[test]
    fn makes_the_tone_for_the_end_of_a_call() {
        let sound = Signal::Ended.sound();
        assert_eq!(sound.frames(), 6400);
        let loud = |from: usize, to: usize| sound.samples[from * 8..to * 8].iter().any(|s| s.abs() > 0.1);
        assert!(loud(0, 140) && !loud(140, 200) && loud(200, 400) && !loud(400, 800));
        // It stops in the silence at its end, before it would start over.
        let once = Signal::Ended.once().unwrap().as_millis();
        assert!((400..800 - 100).contains(&once) && Signal::Busy.once().is_none());
    }

    /// Plays the tones for a moment; heard, so it runs only when asked for:
    /// `cargo test -p miphone signals_on_real_device -- --ignored`.
    #[test]
    #[ignore]
    fn signals_on_real_device() {
        let ringback = Ringer::signal(Signal::Ringback, None, None);
        std::thread::sleep(Duration::from_millis(1500));
        assert_eq!(ringback.take_error(), None);
        drop(ringback);
        let busy = Ringer::signal(Signal::Busy, None, Some(Duration::from_millis(1500)));
        std::thread::sleep(Duration::from_millis(2000));
        assert_eq!(busy.take_error(), None);
        let ended = Ringer::signal(Signal::Ended, None, None);
        std::thread::sleep(Duration::from_millis(1500));
        assert_eq!(ended.take_error(), None);
    }

    #[test]
    fn tone_settings_roundtrip() {
        for tone in [Tone::Builtin(0), Tone::Builtin(1), Tone::File(PathBuf::from(r"C:\Musik\ring.wav"))] {
            assert_eq!(Tone::from_setting(&tone.to_setting()), tone);
        }
        // Settings of an older version, or a tone that no longer exists.
        assert_eq!(Tone::from_setting(""), Tone::Builtin(0));
        assert_eq!(Tone::from_setting("builtin:9"), Tone::Builtin(0));
        assert_eq!(Tone::Builtin(1).label(), "Klingelton 2");
        assert_eq!(Tone::File(PathBuf::from(r"C:\Musik\ring.wav")).label(), "ring.wav");
        assert!(is_sound_file(Path::new("a/Ring.MP3")) && !is_sound_file(Path::new("a/ring.txt")) && !is_sound_file(Path::new("mp3")));
    }

    #[test]
    fn files_that_are_no_sound_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kein-ton.mp3");
        std::fs::write(&path, b"das ist kein Ton").unwrap();
        assert!(Tone::File(path).load().is_err());
        assert!(Tone::File(dir.path().join("fehlt.wav")).load().is_err());
    }

    #[test]
    fn reads_wav_and_interpolates() {
        // A 16 bit stereo file with four frames: left counts up, right is silent.
        let frames: [i16; 4] = [0, 8192, 16384, 24576];
        let data: Vec<u8> = frames.iter().flat_map(|left| [left.to_le_bytes(), 0i16.to_le_bytes()].concat()).collect();
        let mut wav = Vec::new();
        wav.extend_from_slice(b"RIFF");
        wav.extend_from_slice(&(36 + data.len() as u32).to_le_bytes());
        wav.extend_from_slice(b"WAVEfmt ");
        for field in [16u32.to_le_bytes().to_vec(), 1u16.to_le_bytes().to_vec(), 2u16.to_le_bytes().to_vec(), 8000u32.to_le_bytes().to_vec(), 32000u32.to_le_bytes().to_vec(), 4u16.to_le_bytes().to_vec(), 16u16.to_le_bytes().to_vec()] {
            wav.extend_from_slice(&field);
        }
        wav.extend_from_slice(b"data");
        wav.extend_from_slice(&(data.len() as u32).to_le_bytes());
        wav.extend_from_slice(&data);

        let sound = decode(Box::new(Cursor::new(wav)), Some("wav")).unwrap();
        assert_eq!((sound.rate, sound.channels, sound.frames()), (8000, 2, 4));
        let close = |a: f32, b: f32| (a - b).abs() < 0.001;
        assert!(close(sample_at(&sound, 1.0, 0), 0.25) && close(sample_at(&sound, 1.5, 0), 0.375));
        assert!(close(sample_at(&sound, 2.0, 1), 0.0), "the right channel stays silent");
        assert!(close(sample_at(&sound, 2.0, 2), 0.5), "a third speaker gets the left channel again");
        assert!(close(sample_at(&sound, 3.5, 0), 0.375), "the end runs into the start");
        assert!(close(gain(0.5), 0.25) && close(gain(7.0), 1.0) && close(gain(-1.0), 0.0));
    }
}
