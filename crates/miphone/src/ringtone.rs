//! Ringtones: the tones built into the program or a sound file of the user, played in a
//! loop on one or several output devices until the call is answered or gone.

use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

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
            Err(e) => report(format!("Klingelton auf {}: {e:#}", device_name(device).unwrap_or_else(|| "Ausgabegerät".into()))),
        }
    }
    if streams.is_empty() {
        if devices.is_empty() {
            report("Klingelton: kein Ausgabegerät gefunden".into());
        }
        return;
    }
    while !shared.stop.load(Ordering::Relaxed) {
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
