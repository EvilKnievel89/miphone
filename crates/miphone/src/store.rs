//! Persistent data of the softphone under `%APPDATA%\miphone` (roaming profile), or under
//! `%APPDATA%\miphone.<profile>` when the program was started with a profile name.
//!
//! Everything written is encrypted with the Windows data protection API (DPAPI) for the
//! logged-in Windows user, so the files are useless to other users and on other machines
//! that do not have the user's profile:
//!
//! * `settings.dat` - the settings, one encrypted JSON document.
//! * `contacts.dat` - the corporate directory as last loaded from the server, one encrypted
//!   JSON document.
//! * `history.db` - the call history, an SQLite database in which each row holds one
//!   encrypted call record. Only the number of calls and the order they were made in are
//!   visible without decryption. The contacts the user created are kept in the same
//!   database in the same way.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use crate::micollab::Contact;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub server: String,
    pub user: String,
    /// Stored only if the user chose to stay logged in.
    pub password: Option<String>,
    pub stay_logged_in: bool,
    /// Extension chosen for an account that has several.
    pub number: Option<String>,
    /// The user's own choice between the border gateway (teleworker) and the PBX; `None`
    /// follows the profile.
    pub teleworker: Option<bool>,
    /// `light`, `dark` or `system`.
    pub theme: String,
    /// Chosen sound devices by name; `None` is the system default.
    pub audio_input: Option<String>,
    pub audio_output: Option<String>,
    /// Contact list as "Last, First" sorted by last name instead of "First Last" sorted by
    /// first name.
    pub last_name_first: bool,
    /// Output devices the ringtone plays on, by name; none is the system default.
    pub ring_outputs: Vec<String>,
    /// The ringtone: `builtin:<index>` or the path of a sound file; empty is the first
    /// built-in tone.
    pub ringtone: String,
    /// Volume of the ringtone in percent; `None` is the program's default.
    pub ring_volume: Option<u8>,
    /// Noise suppression for the microphone; `None` is the program's default (on).
    pub noise_suppression: Option<bool>,
    /// The buttons and lights of USB headsets are used; `None` is the program's default (off).
    pub headset: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallRecord {
    pub peer: String,
    pub incoming: bool,
    pub answered: bool,
    /// Start of the call, seconds since the Unix epoch.
    pub started: i64,
    pub duration_secs: Option<u64>,
}

/// The directory as last loaded, with the server's marker for asking what changed since.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct DirectoryCache {
    /// Server and user the directory was loaded for; a cache of another account is not used.
    pub owner: String,
    pub timestamp: serde_json::Value,
    pub contacts: Vec<Contact>,
}

pub struct Store {
    dir: PathBuf,
    db: Connection,
}

impl Store {
    /// Opens the store in the user's roaming application data folder, creating it if needed.
    /// A profile has a store of its own beside the one used without a profile.
    pub fn open(profile: Option<&str>) -> Result<Store> {
        let folder = folder_name(profile)?;
        let appdata = std::env::var_os("APPDATA").ok_or_else(|| anyhow!("Umgebungsvariable APPDATA fehlt"))?;
        Store::open_in(&PathBuf::from(appdata).join(folder))
    }

    pub fn open_in(dir: &Path) -> Result<Store> {
        std::fs::create_dir_all(dir).with_context(|| format!("Ordner {} kann nicht angelegt werden", dir.display()))?;
        let db = Connection::open(dir.join("history.db")).context("Verlaufsdatenbank kann nicht geöffnet werden")?;
        db.execute("CREATE TABLE IF NOT EXISTS calls (id INTEGER PRIMARY KEY AUTOINCREMENT, record BLOB NOT NULL)", [])?;
        db.execute("CREATE TABLE IF NOT EXISTS own_contacts (id INTEGER PRIMARY KEY AUTOINCREMENT, record BLOB NOT NULL)", [])?;
        Ok(Store { dir: dir.to_path_buf(), db })
    }

    /// Deletes the whole store folder with everything in it. The store is consumed, because
    /// the open database would keep its file locked.
    pub fn reset(self) -> Result<()> {
        let Store { dir, db } = self;
        drop(db);
        std::fs::remove_dir_all(&dir).with_context(|| format!("Ordner {} kann nicht gelöscht werden", dir.display()))
    }

    fn settings_path(&self) -> PathBuf {
        self.dir.join("settings.dat")
    }

    /// The saved settings; defaults if there are none or they cannot be decrypted
    /// (e.g. the file was copied from another user).
    pub fn load_settings(&self) -> Settings {
        std::fs::read(self.settings_path())
            .ok()
            .and_then(|blob| dpapi::unprotect(&blob).ok())
            .and_then(|json| serde_json::from_slice(&json).ok())
            .unwrap_or_default()
    }

    pub fn save_settings(&self, settings: &Settings) -> Result<()> {
        let blob = dpapi::protect(&serde_json::to_vec(settings)?)?;
        // Write to a temporary file first so a crash cannot leave half a file behind.
        let tmp = self.dir.join("settings.tmp");
        std::fs::write(&tmp, blob)?;
        std::fs::rename(&tmp, self.settings_path()).context("Einstellungen können nicht gespeichert werden")?;
        Ok(())
    }

    /// The cached directory; empty if there is none or it cannot be decrypted.
    pub fn load_directory(&self) -> DirectoryCache {
        std::fs::read(self.dir.join("contacts.dat"))
            .ok()
            .and_then(|blob| dpapi::unprotect(&blob).ok())
            .and_then(|json| serde_json::from_slice(&json).ok())
            .unwrap_or_default()
    }

    pub fn save_directory(&self, directory: &DirectoryCache) -> Result<()> {
        let blob = dpapi::protect(&serde_json::to_vec(directory)?)?;
        let tmp = self.dir.join("contacts.tmp");
        std::fs::write(&tmp, blob)?;
        std::fs::rename(&tmp, self.dir.join("contacts.dat")).context("Verzeichnis kann nicht gespeichert werden")?;
        Ok(())
    }

    pub fn add_call(&self, record: &CallRecord) -> Result<()> {
        let blob = dpapi::protect(&serde_json::to_vec(record)?)?;
        self.db.execute("INSERT INTO calls (record) VALUES (?1)", [blob])?;
        Ok(())
    }

    /// The most recent calls, oldest first. Rows that cannot be decrypted are skipped.
    pub fn recent_calls(&self, limit: usize) -> Result<Vec<CallRecord>> {
        let mut stmt = self.db.prepare("SELECT record FROM calls ORDER BY id DESC LIMIT ?1")?;
        let blobs = stmt.query_map([limit as i64], |row| row.get::<_, Vec<u8>>(0))?;
        let mut calls: Vec<CallRecord> = blobs
            .filter_map(|blob| blob.ok())
            .filter_map(|blob| dpapi::unprotect(&blob).ok())
            .filter_map(|json| serde_json::from_slice(&json).ok())
            .collect();
        calls.reverse();
        Ok(calls)
    }

    pub fn clear_calls(&self) -> Result<()> {
        self.db.execute("DELETE FROM calls", [])?;
        // Make sure the deleted rows are really gone from the file.
        self.db.execute("VACUUM", [])?;
        Ok(())
    }

    /// Saves a contact the user created. A contact without id is new and gets one; with
    /// an id it replaces the saved contact of that id.
    pub fn save_own_contact(&self, contact: &mut Contact) -> Result<()> {
        // The id is the row's key and not part of the stored record.
        let blob = dpapi::protect(&serde_json::to_vec(&Contact { id: String::new(), ..contact.clone() })?)?;
        match own_contact_row(&contact.id) {
            Some(row) => {
                if self.db.execute("UPDATE own_contacts SET record = ?1 WHERE id = ?2", (blob, row))? == 0 {
                    return Err(anyhow!("Der Kontakt ist nicht mehr gespeichert"));
                }
            }
            None => {
                self.db.execute("INSERT INTO own_contacts (record) VALUES (?1)", [blob])?;
                contact.id = format!("{OWN_CONTACT_PREFIX}{}", self.db.last_insert_rowid());
            }
        }
        Ok(())
    }

    pub fn delete_own_contact(&self, id: &str) -> Result<()> {
        if let Some(row) = own_contact_row(id) {
            self.db.execute("DELETE FROM own_contacts WHERE id = ?1", [row])?;
        }
        Ok(())
    }

    /// The contacts the user created. Rows that cannot be decrypted are skipped.
    pub fn own_contacts(&self) -> Result<Vec<Contact>> {
        let mut stmt = self.db.prepare("SELECT id, record FROM own_contacts ORDER BY id")?;
        let rows = stmt.query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)))?;
        Ok(rows
            .filter_map(|row| row.ok())
            .filter_map(|(id, blob)| {
                let contact: Contact = serde_json::from_slice(&dpapi::unprotect(&blob).ok()?).ok()?;
                Some(Contact { id: format!("{OWN_CONTACT_PREFIX}{id}"), ..contact })
            })
            .collect())
    }
}

/// Name of the store's folder: `miphone`, or `miphone.<profile>` for a profile. The profile
/// becomes part of a folder name, so only letters, digits, `-` and `_` are accepted.
pub fn folder_name(profile: Option<&str>) -> Result<String> {
    match profile {
        None => Ok("miphone".to_string()),
        Some(name) if !name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') => Ok(format!("miphone.{name}")),
        Some(name) => Err(anyhow!("Ungültiger Profilname \"{name}\": erlaubt sind Buchstaben, Ziffern, - und _")),
    }
}

/// Ids of the user's own contacts start with this, so they cannot collide with ids of the
/// corporate directory.
const OWN_CONTACT_PREFIX: &str = "own-";

/// The database row of an own contact's id; `None` for a contact not saved yet.
fn own_contact_row(id: &str) -> Option<i64> {
    id.strip_prefix(OWN_CONTACT_PREFIX)?.parse().ok()
}

/// Windows data protection for the current user.
mod dpapi {
    use anyhow::{bail, Result};

    #[cfg(windows)]
    fn crypt(data: &[u8], protect: bool) -> Result<Vec<u8>> {
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Cryptography::{CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB};

        let input = CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 };
        let mut output = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
        // SAFETY: `input` points to `data`, which outlives the call and is only read. On
        // success the system allocates `output.pbData` with `cbData` valid bytes; we copy
        // them and release the buffer with `LocalFree` as the API requires.
        unsafe {
            let ok = if protect {
                CryptProtectData(&input, std::ptr::null(), std::ptr::null(), std::ptr::null(), std::ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut output)
            } else {
                CryptUnprotectData(&input, std::ptr::null_mut(), std::ptr::null(), std::ptr::null(), std::ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut output)
            };
            if ok == 0 || output.pbData.is_null() {
                bail!("{} mit DPAPI fehlgeschlagen", if protect { "Verschlüsseln" } else { "Entschlüsseln" });
            }
            let result = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
            LocalFree(output.pbData as _);
            Ok(result)
        }
    }

    #[cfg(not(windows))]
    fn crypt(_data: &[u8], _protect: bool) -> Result<Vec<u8>> {
        bail!("Die verschlüsselte Ablage gibt es nur unter Windows");
    }

    pub fn protect(data: &[u8]) -> Result<Vec<u8>> {
        crypt(data, true)
    }

    pub fn unprotect(data: &[u8]) -> Result<Vec<u8>> {
        crypt(data, false)
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn dpapi_roundtrip() {
        let secret = b"geheimes Kennwort \xc3\xa4";
        let blob = dpapi::protect(secret).unwrap();
        assert!(!contains(&blob, b"geheim"));
        assert_eq!(dpapi::unprotect(&blob).unwrap(), secret);
        assert_eq!(dpapi::unprotect(&dpapi::protect(b"").unwrap()).unwrap(), b"");
        let mut damaged = blob.clone();
        let last = damaged.len() - 1;
        damaged[last] ^= 0xff;
        assert!(dpapi::unprotect(&damaged).is_err());
        assert!(dpapi::unprotect(b"not a blob").is_err());
    }

    #[test]
    fn profiles_have_their_own_folder() {
        assert_eq!(folder_name(None).unwrap(), "miphone");
        assert_eq!(folder_name(Some("Büro_2-test")).unwrap(), "miphone.Büro_2-test");
        // Nothing that could leave the folder or is not a valid folder name.
        for bad in ["", "..", "a/b", "a\\b", "a.b", "a b", "c:", "x*"] {
            assert!(folder_name(Some(bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn settings_are_stored_encrypted() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open_in(dir.path()).unwrap();
        assert_eq!(store.load_settings(), Settings::default());
        let settings = Settings {
            server: "mc.example.org".into(),
            user: "alice@example.org".into(),
            password: Some("Tr0ub4dor&3".into()),
            stay_logged_in: true,
            number: Some("8*1002".into()),
            teleworker: Some(false),
            theme: "dark".into(),
            audio_input: Some("Headset Mikrofon".into()),
            audio_output: None,
            last_name_first: true,
            ring_outputs: vec!["Headset Lautsprecher".into(), "Monitor".into()],
            ringtone: "builtin:1".into(),
            ring_volume: Some(40),
            noise_suppression: Some(false),
            headset: Some(true),
        };
        store.save_settings(&settings).unwrap();
        let raw = std::fs::read(dir.path().join("settings.dat")).unwrap();
        for plain in ["mc.example.org", "alice", "Tr0ub4dor", "Headset", "password"] {
            assert!(!contains(&raw, plain.as_bytes()), "{plain} is readable in settings.dat");
        }
        // A second instance reads the same values back.
        assert_eq!(Store::open_in(dir.path()).unwrap().load_settings(), settings);
        assert!(!dir.path().join("settings.tmp").exists());
    }

    #[test]
    fn unreadable_settings_fall_back_to_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open_in(dir.path()).unwrap();
        std::fs::write(dir.path().join("settings.dat"), b"{\"server\":\"plain\"}").unwrap();
        assert_eq!(store.load_settings(), Settings::default());
        // Settings from an older version without newer fields still load.
        std::fs::write(dir.path().join("settings.dat"), dpapi::protect(br#"{"server":"s","user":"u"}"#).unwrap()).unwrap();
        let s = store.load_settings();
        assert_eq!((s.server.as_str(), s.user.as_str(), s.password, s.stay_logged_in), ("s", "u", None, false));
    }

    #[test]
    fn reset_removes_the_folder() {
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("miphone");
        let store = Store::open_in(&dir).unwrap();
        store.save_settings(&Settings { server: "s".into(), ..Settings::default() }).unwrap();
        store.add_call(&CallRecord { peer: "1".into(), incoming: true, answered: false, started: 1, duration_secs: None }).unwrap();
        std::fs::write(dir.join("something-else.txt"), "x").unwrap();
        store.reset().unwrap();
        assert!(!dir.exists(), "the folder itself is gone");
        assert!(parent.path().exists(), "nothing outside it is touched");
        // A new store starts empty.
        let again = Store::open_in(&dir).unwrap();
        assert_eq!(again.load_settings(), Settings::default());
        assert!(again.recent_calls(10).unwrap().is_empty());
    }

    #[test]
    fn directory_cache_is_stored_encrypted() {
        use crate::micollab::Phone;
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open_in(dir.path()).unwrap();
        assert_eq!(store.load_directory(), DirectoryCache::default());
        let cache = DirectoryCache {
            owner: "mc.example.org|alice".into(),
            timestamp: serde_json::json!("2026-11-26T10:00:00.000Z"),
            contacts: vec![Contact {
                id: "c-1".into(),
                first_name: "Erika".into(),
                last_name: "Muster".into(),
                phones: vec![Phone { number: "1001".into(), label: "Work".into() }],
                ..Contact::default()
            }],
        };
        store.save_directory(&cache).unwrap();
        let raw = std::fs::read(dir.path().join("contacts.dat")).unwrap();
        assert!(!contains(&raw, b"Erika") && !contains(&raw, b"1001") && !contains(&raw, b"contacts"));
        assert_eq!(store.load_directory(), cache);
    }

    #[test]
    fn own_contacts_are_stored_encrypted_in_sqlite() {
        use crate::micollab::Phone;
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open_in(dir.path()).unwrap();
        assert!(store.own_contacts().unwrap().is_empty());
        let person = |first: &str, number: &str| Contact {
            first_name: first.into(),
            last_name: "Muster".into(),
            phones: vec![Phone { number: number.into(), label: "Mobil".into() }],
            ..Contact::default()
        };
        let (mut erika, mut max) = (person("Erika", "0170 1234567"), person("Max", "0171 7654321"));
        store.save_own_contact(&mut erika).unwrap();
        store.save_own_contact(&mut max).unwrap();
        assert!(erika.id.starts_with("own-") && erika.id != max.id);

        // Changing a saved contact keeps its id and adds no row.
        erika.company = "Beispiel GmbH".into();
        store.save_own_contact(&mut erika).unwrap();
        drop(store);

        let raw = std::fs::read(dir.path().join("history.db")).unwrap();
        assert!(!contains(&raw, b"Erika") && !contains(&raw, b"0170") && !contains(&raw, b"Beispiel"));

        let store = Store::open_in(dir.path()).unwrap();
        assert_eq!(store.own_contacts().unwrap(), vec![erika.clone(), max.clone()]);
        store.delete_own_contact(&erika.id).unwrap();
        assert_eq!(store.own_contacts().unwrap(), vec![max]);
        assert!(store.save_own_contact(&mut erika).is_err(), "a deleted contact is not silently recreated");
        // Ids that are not ours are left alone.
        store.delete_own_contact("c-1").unwrap();
        assert_eq!(store.own_contacts().unwrap().len(), 1);
    }

    #[test]
    fn history_is_stored_encrypted_in_sqlite() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open_in(dir.path()).unwrap();
        let call = |peer: &str, started| CallRecord { peer: peer.into(), incoming: true, answered: true, started, duration_secs: Some(42) };
        for i in 0..5 {
            store.add_call(&call(&format!("Erika Muster (100{i})"), 1_800_000_000 + i)).unwrap();
        }
        drop(store);

        let raw = std::fs::read(dir.path().join("history.db")).unwrap();
        assert!(raw.starts_with(b"SQLite format 3"));
        assert!(!contains(&raw, b"Erika") && !contains(&raw, b"1001") && !contains(&raw, b"peer"));

        let store = Store::open_in(dir.path()).unwrap();
        let all = store.recent_calls(100).unwrap();
        assert_eq!(all.len(), 5);
        assert_eq!(all[0], call("Erika Muster (1000)", 1_800_000_000));
        // A limit keeps the newest entries, still oldest first.
        let last_two = store.recent_calls(2).unwrap();
        assert_eq!(last_two.iter().map(|c| c.started).collect::<Vec<_>>(), vec![1_800_000_003, 1_800_000_004]);

        // A row that cannot be decrypted is skipped instead of breaking the list.
        store.db.execute("INSERT INTO calls (record) VALUES (?1)", [b"garbage".to_vec()]).unwrap();
        assert_eq!(store.recent_calls(100).unwrap().len(), 5);

        store.clear_calls().unwrap();
        assert!(store.recent_calls(100).unwrap().is_empty());
    }
}
