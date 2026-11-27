//! Looks for a newer release of the program on GitHub and puts it in the place of the
//! running one.
//!
//! The releases are those of the repository the program was built in: the release workflow
//! runs on GitHub, which names the repository in `GITHUB_REPOSITORY`. A build made anywhere
//! else has no releases to look at and does not look for updates.

use std::ffi::OsString;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// `owner/name` of the repository with the releases; `None` for a build made elsewhere.
pub const REPOSITORY: Option<&str> = option_env!("GITHUB_REPOSITORY");
/// The version of the running program.
pub const CURRENT: &str = env!("CARGO_PKG_VERSION");

/// The end of the name of the archive a release carries for this system.
const ARCHIVE_SUFFIX: &str = "-windows-x64.zip";
/// The programs in the archive: the one with the window, which is the one that updates
/// itself, and the one for the console, which is replaced if it lies next to it.
const WINDOW_PROGRAM: &str = "miphone-gui.exe";
const CONSOLE_PROGRAM: &str = "miphone.exe";
/// Nothing larger than this is downloaded or unpacked.
const MAX_SIZE: u64 = 200 * 1024 * 1024;

/// A release that is newer than the running program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    /// Without the `v` of the tag.
    pub version: String,
    /// The page of the release, with what changed.
    pub page: String,
    archive: String,
    size: u64,
    /// SHA-256 of the archive as GitHub states it, in hex.
    sha256: Option<String>,
}

impl Release {
    /// A release that does not exist, to show how the window offers one.
    pub fn sample(version: &str) -> Release {
        Release { version: version.to_string(), page: "https://github.com/".into(), archive: String::new(), size: 0, sha256: None }
    }
}

/// `1.2.3` or `1.2.3-pre.4`; a version with a suffix comes before the one without.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Version {
    numbers: [u64; 3],
    release: bool,
    pre: u64,
}

impl Version {
    fn parse(text: &str) -> Option<Version> {
        let text = text.strip_prefix('v').unwrap_or(text);
        let (core, suffix) = match text.split_once('-') {
            Some((core, suffix)) => (core, Some(suffix)),
            None => (text, None),
        };
        let mut parts = core.split('.').map(|part| part.parse::<u64>().ok());
        let numbers = [parts.next()??, parts.next()??, parts.next()??];
        if parts.next().is_some() {
            return None;
        }
        let pre = suffix.and_then(|s| s.rsplit('.').next()?.parse().ok()).unwrap_or(0);
        Some(Version { numbers, release: suffix.is_none(), pre })
    }
}

#[derive(Debug, Deserialize)]
struct Published {
    tag_name: String,
    html_url: String,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    assets: Vec<Asset>,
}

#[derive(Debug, Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
    #[serde(default)]
    size: u64,
    digest: Option<String>,
}

/// The newest of the published releases that is newer than `current`. Pre-releases count
/// only for someone who runs a pre-release. Addresses that do not lead to the repository
/// are not followed.
fn choose(published: Vec<Published>, repository: &str, current: &str) -> Option<Release> {
    let current = Version::parse(current)?;
    let home = format!("https://github.com/{repository}/releases/");
    let downloads = format!("{home}download/");
    published
        .into_iter()
        .filter(|p| !p.draft && (!p.prerelease || !current.release))
        .filter_map(|p| {
            let version = Version::parse(&p.tag_name)?;
            // A tag with a suffix is a pre-release, whatever the release says about itself.
            if version <= current || (!version.release && current.release) || !p.html_url.starts_with(&home) {
                return None;
            }
            let asset = p.assets.into_iter().find(|a| a.name.ends_with(ARCHIVE_SUFFIX) && a.browser_download_url.starts_with(&downloads))?;
            let sha256 = asset.digest.as_deref().and_then(|d| d.strip_prefix("sha256:")).map(str::to_ascii_lowercase);
            let release = Release {
                version: p.tag_name.trim_start_matches('v').to_string(),
                page: p.html_url,
                archive: asset.browser_download_url,
                size: asset.size,
                sha256,
            };
            Some((version, release))
        })
        .max_by_key(|(version, _)| *version)
        .map(|(_, release)| release)
}

fn client(timeout: Duration) -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .user_agent(concat!("miphone/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(15))
        .timeout(timeout)
        .build()?)
}

/// Asks GitHub for a release of `repository` that is newer than `current`.
pub async fn check(repository: &str, current: &str) -> Result<Option<Release>> {
    let url = format!("https://api.github.com/repos/{repository}/releases?per_page=30");
    let response = client(Duration::from_secs(30))?.get(url).header("Accept", "application/vnd.github+json").send().await?.error_for_status()?;
    Ok(choose(response.json().await?, repository, current))
}

/// Downloads the release and puts its programs in the place of the running ones. Returns
/// the path of the program to start again; the running one goes on until it is closed.
pub async fn install(release: &Release) -> Result<PathBuf> {
    let program = std::env::current_exe().context("the path of the program is unknown")?;
    let archive = download(release).await?;
    let target = program.clone();
    tokio::task::spawn_blocking(move || replace(&target, &archive)).await??;
    Ok(program)
}

async fn download(release: &Release) -> Result<Vec<u8>> {
    if release.size > MAX_SIZE {
        bail!("the download is too large ({} MB)", release.size / (1024 * 1024));
    }
    let mut response = client(Duration::from_secs(600))?.get(&release.archive).send().await?.error_for_status()?;
    let mut archive = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        archive.extend_from_slice(&chunk);
        if archive.len() as u64 > MAX_SIZE {
            bail!("the download is too large");
        }
    }
    if release.size != 0 && archive.len() as u64 != release.size {
        bail!("the download is incomplete ({} of {} bytes)", archive.len(), release.size);
    }
    if let Some(expected) = &release.sha256 {
        let found: String = Sha256::digest(&archive).iter().map(|byte| format!("{byte:02x}")).collect();
        if &found != expected {
            bail!("the download does not have the checksum of the release");
        }
    }
    Ok(archive)
}

/// `path` with `.suffix` after its name.
fn beside(path: &Path, suffix: &str) -> PathBuf {
    let mut name = OsString::from(path.as_os_str());
    name.push(".");
    name.push(suffix);
    PathBuf::from(name)
}

/// The file of this name in the archive, in whatever folder it lies there.
fn unpack(zip: &mut zip::ZipArchive<std::io::Cursor<&[u8]>>, name: &str) -> Result<Option<Vec<u8>>> {
    for index in 0..zip.len() {
        let file = zip.by_index(index)?;
        let found = file.is_file() && file.enclosed_name().is_some_and(|path| path.file_name().is_some_and(|n| n == name));
        if found {
            let mut data = Vec::new();
            file.take(MAX_SIZE + 1).read_to_end(&mut data)?;
            if data.len() as u64 > MAX_SIZE {
                bail!("{name} in the download is too large");
            }
            return Ok(Some(data));
        }
    }
    Ok(None)
}

/// Puts the new file in the place of the old one. A program that runs cannot be written
/// to, but it can be renamed: it stays beside as `.old` until `clean_up` removes it.
fn swap(new: &Path, place: &Path) -> Result<()> {
    let old = beside(place, "old");
    let _ = std::fs::remove_file(&old);
    std::fs::rename(place, &old).with_context(|| format!("{} cannot be moved aside", place.display()))?;
    if let Err(e) = std::fs::rename(new, place) {
        let _ = std::fs::rename(&old, place);
        return Err(e).with_context(|| format!("{} cannot be replaced", place.display()));
    }
    Ok(())
}

/// Replaces `program` (and the console program next to it, if there is one) with those in
/// the archive.
fn replace(program: &Path, archive: &[u8]) -> Result<()> {
    let folder = program.parent().ok_or_else(|| anyhow!("the program has no folder"))?;
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(archive)).context("the download is not an archive")?;
    let window = unpack(&mut zip, WINDOW_PROGRAM)?.ok_or_else(|| anyhow!("{WINDOW_PROGRAM} is missing in the download"))?;
    let console_place = folder.join(CONSOLE_PROGRAM);
    let console = if console_place.is_file() && console_place != program { unpack(&mut zip, CONSOLE_PROGRAM)? } else { None };

    // Everything is written before anything is replaced.
    let new = beside(program, "new");
    std::fs::write(&new, window).with_context(|| format!("the folder {} cannot be written to", folder.display()))?;
    let console = match console {
        Some(data) => {
            let new = beside(&console_place, "new");
            std::fs::write(&new, data).is_ok().then_some(new)
        }
        None => None,
    };
    let done = swap(&new, program);
    if done.is_err() {
        let _ = std::fs::remove_file(&new);
    }
    if let Some(new) = console {
        // The window's program decides; the other one follows if it can.
        if done.is_err() || swap(&new, &console_place).is_err() {
            let _ = std::fs::remove_file(&new);
        }
    }
    done
}

/// Removes what an update left beside the programs. Called at the start of the program;
/// what still runs stays until the next time.
pub fn clean_up() {
    let Ok(program) = std::env::current_exe() else { return };
    let Some(folder) = program.parent() else { return };
    for place in [program.clone(), folder.join(CONSOLE_PROGRAM)] {
        for suffix in ["old", "new"] {
            let _ = std::fs::remove_file(beside(&place, suffix));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const REPO: &str = "someone/miphone";

    fn published(tag: &str, prerelease: bool) -> Published {
        let json = serde_json::json!({
            "tag_name": tag,
            "html_url": format!("https://github.com/{REPO}/releases/tag/{tag}"),
            "prerelease": prerelease,
            "assets": [
                { "name": "notes.txt", "browser_download_url": format!("https://github.com/{REPO}/releases/download/{tag}/notes.txt") },
                {
                    "name": format!("miphone-{tag}-windows-x64.zip"),
                    "browser_download_url": format!("https://github.com/{REPO}/releases/download/{tag}/miphone-{tag}-windows-x64.zip"),
                    "size": 1234,
                    "digest": "sha256:ABCDEF",
                },
            ],
        });
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn orders_versions() {
        let v = |text: &str| Version::parse(text).unwrap();
        assert!(v("0.1.9") < v("0.1.10") && v("0.1.10") < v("0.2.0") && v("0.9.9") < v("v1.0.0"));
        assert!(v("0.2.2-pre.4") < v("0.2.2") && v("0.2.1") < v("0.2.2-pre.1") && v("0.2.2-pre.4") < v("0.2.2-pre.10"));
        for bad in ["", "1.2", "1.2.3.4", "one.2.3", "v"] {
            assert_eq!(Version::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn offers_the_newest_release() {
        let all = || vec![published("v0.2.0", false), published("v0.3.0-pre.2", true), published("v0.2.1", false), published("v0.1.0", false)];
        let found = choose(all(), REPO, "0.2.0").unwrap();
        assert_eq!((found.version.as_str(), found.size, found.sha256.as_deref()), ("0.2.1", 1234, Some("abcdef")));
        assert_eq!(found.page, format!("https://github.com/{REPO}/releases/tag/v0.2.1"));
        assert!(found.archive.ends_with("/v0.2.1/miphone-v0.2.1-windows-x64.zip"));
        // Pre-releases are for those who run one; they also get the release that follows.
        assert_eq!(choose(all(), REPO, "0.2.1-pre.1").unwrap().version, "0.3.0-pre.2");
        assert_eq!(choose(vec![published("v0.2.1", false)], REPO, "0.2.1-pre.3").unwrap().version, "0.2.1");
        assert_eq!(choose(vec![published("v0.3.0-pre.2", false)], REPO, "0.2.1"), None);
        assert_eq!(choose(all(), REPO, "0.2.1"), None);
        assert_eq!(choose(all(), REPO, "0.3.0"), None);
    }

    #[test]
    fn leaves_out_what_cannot_be_installed() {
        let mut draft = published("v9.0.0", false);
        draft.draft = true;
        let mut empty = published("v9.0.1", false);
        empty.assets.clear();
        let mut elsewhere = published("v9.0.2", false);
        elsewhere.assets[1].browser_download_url = "https://example.org/miphone-v9.0.2-windows-x64.zip".into();
        assert_eq!(choose(vec![draft, empty, elsewhere], REPO, "0.1.0"), None);
        // Releases of another repository are not ours either.
        assert_eq!(choose(vec![published("v9.0.3", false)], "someone/else", "0.1.0"), None);
    }

    fn archive(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        for (name, data) in files {
            zip.start_file(*name, options).unwrap();
            zip.write_all(data).unwrap();
        }
        zip.finish().unwrap().into_inner()
    }

    #[test]
    fn replaces_the_programs() {
        let dir = tempfile::tempdir().unwrap();
        // The user may have given the program another name.
        let (program, console, other) = (dir.path().join("Telefon.exe"), dir.path().join(CONSOLE_PROGRAM), dir.path().join("README.md"));
        for path in [&program, &console, &other] {
            std::fs::write(path, b"old").unwrap();
        }
        let new = archive(&[("miphone-v9/README.md", b"new readme"), ("miphone-v9/miphone-gui.exe", b"new window"), ("miphone-v9/miphone.exe", b"new console")]);
        replace(&program, &new).unwrap();
        assert_eq!(std::fs::read(&program).unwrap(), b"new window");
        assert_eq!(std::fs::read(&console).unwrap(), b"new console");
        assert_eq!(std::fs::read(&other).unwrap(), b"old");
        assert_eq!(std::fs::read(beside(&program, "old")).unwrap(), b"old");
        assert!(!beside(&program, "new").exists() && !beside(&console, "new").exists());

        // An archive without the program changes nothing.
        let error = replace(&program, &archive(&[("miphone-v9/miphone.exe", b"newer console")])).unwrap_err();
        assert!(error.to_string().contains(WINDOW_PROGRAM), "{error}");
        assert!(replace(&program, b"not an archive").is_err());
        assert_eq!(std::fs::read(&program).unwrap(), b"new window");
        assert_eq!(std::fs::read(&console).unwrap(), b"new console");
    }

    #[test]
    fn leaves_the_console_program_out_if_it_is_not_there() {
        let dir = tempfile::tempdir().unwrap();
        let program = dir.path().join(WINDOW_PROGRAM);
        std::fs::write(&program, b"old").unwrap();
        replace(&program, &archive(&[("miphone-gui.exe", b"new window"), ("miphone.exe", b"new console")])).unwrap();
        assert_eq!(std::fs::read(&program).unwrap(), b"new window");
        assert!(!dir.path().join(CONSOLE_PROGRAM).exists());
    }

    /// Asks GitHub and downloads the newest release; needs the network and the name of a
    /// repository, so it runs only when asked for:
    /// `MIPHONE_TEST_REPOSITORY=owner/name cargo test -p miphone downloads_a_real_release -- --ignored --nocapture`
    #[tokio::test]
    #[ignore]
    async fn downloads_a_real_release() {
        let repository = std::env::var("MIPHONE_TEST_REPOSITORY").expect("MIPHONE_TEST_REPOSITORY");
        let release = check(&repository, "0.0.1-pre.1").await.unwrap().expect("a release");
        println!("{release:?}");
        let dir = tempfile::tempdir().unwrap();
        let program = dir.path().join(WINDOW_PROGRAM);
        std::fs::write(&program, b"old").unwrap();
        replace(&program, &download(&release).await.unwrap()).unwrap();
        let size = std::fs::metadata(&program).unwrap().len();
        println!("{size} bytes");
        assert!(size > 1_000_000);
    }
}
