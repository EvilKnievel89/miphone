//! Graphical front end for the softphone, built with egui.
//!
//! The window only draws state and sends commands; provisioning, SIP and audio run on a
//! tokio runtime in the background and report back through a channel.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc as std_mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use eframe::egui;
use egui_material_icons::icons::{
    ICON_ADD, ICON_BACKSPACE, ICON_CALL, ICON_CALL_MADE, ICON_CALL_MISSED, ICON_CALL_RECEIVED, ICON_CONTACTS, ICON_EDIT, ICON_HISTORY, ICON_LOGOUT,
    ICON_REFRESH, ICON_SETTINGS,
};
use egui_material_icons::{icon_text, MaterialIcon};
use miphone::config::{MicollabConfig, SipConfig};
use miphone::media::{self, AudioSettings};
use miphone::micollab::{self, Contact, Status};
use miphone::provision;
use miphone::ringtone::{self, Ringer, Tone};
use miphone::store::{CallRecord, DirectoryCache, Settings, Store};
use miphone::ua::{self, CallPhase, CallSnapshot, Command, Event, Snapshot};
use miphone::wsp::{self, Indicator, Presence, ServerEvent, Watchlist};
use tokio::sync::mpsc;

fn main() -> eframe::Result {
    // The profile is part of the title, to tell the windows of several profiles apart.
    let title = match profile_argument() {
        Some(profile) => format!("miphone {} – {profile}", env!("CARGO_PKG_VERSION")),
        None => concat!("miphone ", env!("CARGO_PKG_VERSION")).to_string(),
    };
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(title)
            .with_inner_size([400.0 * UI_SCALE, 660.0 * UI_SCALE])
            .with_min_inner_size([360.0 * UI_SCALE, 560.0 * UI_SCALE])
            .with_icon(window_icon()),
        ..Default::default()
    };
    eframe::run_native("miphone", options, Box::new(|cc| Ok(Box::new(App::new(cc)))))
}

/// The profile named on the command line with `--profile:<name>`. Each profile keeps its
/// settings, contacts and history in a folder of its own, so several accounts can be used
/// side by side.
fn profile_argument() -> Option<String> {
    profile_in(std::env::args().skip(1))
}

fn profile_in(args: impl Iterator<Item = String>) -> Option<String> {
    args.into_iter().find_map(|a| a.strip_prefix("--profile:").or_else(|| a.strip_prefix("--profile=")).map(|name| name.trim().to_string()))
}

/// Everything (texts, icons, spacing) is drawn this much larger than egui's default size.
/// The window grows by the same factor, so the layout stays as designed.
const UI_SCALE: f32 = 1.1;

/// The icon shown in the title bar and taskbar: the largest image of `icon.ico`.
fn window_icon() -> egui::IconData {
    const ICO: &[u8] = include_bytes!("../../../icon.ico");
    largest_png_in_ico(ICO).and_then(|png| eframe::icon_data::from_png_bytes(png).ok()).unwrap_or_default()
}

/// Finds the biggest PNG-encoded image in an ICO file. Large icon sizes are stored as PNG.
fn largest_png_in_ico(ico: &[u8]) -> Option<&[u8]> {
    let u16_at = |o: usize| Some(u16::from_le_bytes(ico.get(o..o + 2)?.try_into().ok()?));
    let u32_at = |o: usize| Some(u32::from_le_bytes(ico.get(o..o + 4)?.try_into().ok()?) as usize);
    let count = u16_at(4)? as usize;
    (0..count)
        .filter_map(|i| {
            let entry = 6 + 16 * i;
            // A width of 0 stands for 256.
            let width = match *ico.get(entry)? {
                0 => 256,
                w => w as usize,
            };
            let data = ico.get(u32_at(entry + 12)?..)?.get(..u32_at(entry + 8)?)?;
            data.starts_with(b"\x89PNG").then_some((width, data))
        })
        .max_by_key(|(width, _)| *width)
        .map(|(_, data)| data)
}

/// Messages from the background session to the window.
enum Backend {
    LoginFailed(String),
    /// The account has several extensions; the user has to pick one.
    ChooseNumber(Vec<provision::Choice>),
    /// `can_switch`: the profile has a second SIP account the user may change over to.
    LoggedIn { number: Option<String>, teleworker: bool, can_switch: bool },
    /// The softphone changed over to the other SIP account.
    AccountSwitched { teleworker: bool },
    Ua(Event),
    /// The connection dropped; a new attempt follows.
    ConnectionLost(String),
    Statuses(Vec<Status>),
    CurrentStatus(Status),
    StatusError(String),
    /// The server's event channel is up; status changes now arrive at once.
    EventChannel,
    Presence(Presence),
    /// The user's name as the server knows it.
    Profile { first_name: String, last_name: String },
    ContactPresence { id: String, presence: Presence },
    /// Result of a directory sync: new or changed contacts, ids of removed ones and the
    /// marker for the next sync. `full` replaces everything known so far.
    Directory { contacts: Vec<Contact>, deleted: Vec<String>, timestamp: serde_json::Value, full: bool },
    Groups(Vec<ContactGroup>),
    DirectoryError(String),
}

/// One of the user's contact groups with the ids of its members.
#[derive(Debug, Clone, PartialEq)]
struct ContactGroup {
    name: String,
    members: Vec<String>,
}

/// The window's connections into the background tasks that talk to the MiCollab server.
struct ServerLinks {
    /// Status ids the user picked.
    choices: mpsc::Receiver<serde_json::Value>,
    /// Contacts whose presence is shown, and the signal that the list changed.
    watchlist: Watchlist,
    watch_changed: mpsc::UnboundedReceiver<()>,
    /// What the encrypted cache already holds: the sync marker and whether there are contacts.
    directory_since: serde_json::Value,
    have_directory: bool,
    /// Asks for another directory sync.
    refresh_directory: mpsc::Receiver<()>,
}

/// Sends a message to the window and wakes it up.
#[derive(Clone)]
struct Notifier {
    tx: std_mpsc::Sender<Backend>,
    ctx: egui::Context,
}

impl Notifier {
    fn send(&self, msg: Backend) {
        let _ = self.tx.send(msg);
        self.ctx.request_repaint();
    }
}

/// Holds the server's event channel open and reconnects when it drops.
/// Ends (and signs the session off) when `stop` fires or is dropped.
async fn event_channel(
    login: MicollabConfig,
    password: String,
    client: Arc<micollab::Client>,
    notify: Notifier,
    watchlist: Watchlist,
    mut watch_changed: mpsc::UnboundedReceiver<()>,
    events: mpsc::UnboundedSender<ServerEvent>,
    mut stop: mpsc::Receiver<()>,
) {
    let session_key = wsp::new_session_key();
    let credentials = wsp::Login { server: &login.server, user: &login.user, password: &password, tls_insecure: login.tls_insecure, session_key: &session_key };
    let mut account = None;
    loop {
        let attempt = async {
            if account.is_none() {
                account = Some(client.account().await?);
            }
            wsp::run(&credentials, account.as_ref().expect("set above"), &watchlist, &mut watch_changed, &events, &mut stop).await
        };
        match attempt.await {
            Ok(()) => return,
            Err(e) => notify.send(Backend::StatusError(format!("{e:#}"))),
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(10)) => {}
            _ = stop.recv() => return,
        }
    }
}

/// Keeps the list of presence statuses and the current one up to date and applies the
/// user's choice. Ends when the window drops its end of `choices` (logout).
/// Loads the directory and the user's contact groups, first at login and then whenever
/// asked. With a cache only the changes since the last sync are fetched.
async fn directory(client: Arc<micollab::Client>, notify: Notifier, mut since: serde_json::Value, mut have_cache: bool, mut refresh: mpsc::Receiver<()>) {
    loop {
        let full = !have_cache || since.is_null();
        let sync = async {
            let changes = client.changed_contacts(if full { None } else { Some(&since) }).await?;
            let mut contacts = Vec::with_capacity(changes.modified.len());
            for batch in changes.modified.chunks(50) {
                contacts.extend(client.contacts(batch).await?);
            }
            anyhow::Ok((contacts, changes.deleted, changes.timestamp))
        };
        match sync.await {
            Ok((contacts, deleted, timestamp)) => {
                since = timestamp.clone();
                have_cache = true;
                notify.send(Backend::Directory { contacts, deleted, timestamp, full });
            }
            Err(e) => notify.send(Backend::DirectoryError(format!("{e:#}"))),
        }
        let groups = async {
            let mut groups = Vec::new();
            for group in client.groups().await? {
                let members = client.group_members(&group.id).await?;
                groups.push(ContactGroup { name: group.name, members });
            }
            anyhow::Ok(groups)
        };
        match groups.await {
            Ok(groups) => notify.send(Backend::Groups(groups)),
            Err(e) => notify.send(Backend::DirectoryError(format!("{e:#}"))),
        }
        if refresh.recv().await.is_none() {
            return; // logged out
        }
    }
}

async fn presence(
    login: MicollabConfig,
    password: String,
    client: Arc<micollab::Client>,
    notify: Notifier,
    mut choices: mpsc::Receiver<serde_json::Value>,
    watchlist: Watchlist,
    watch_changed: mpsc::UnboundedReceiver<()>,
) {
    let (server_tx, mut server_events) = mpsc::unbounded_channel();
    // Dropping `_stop` at the end of this function ends the event channel.
    let (_stop, stop_rx) = mpsc::channel(1);
    tokio::spawn(event_channel(login, password, client.clone(), notify.clone(), watchlist, watch_changed, server_tx, stop_rx));

    if let Ok(account) = client.account().await {
        notify.send(Backend::Profile { first_name: account.first_name, last_name: account.last_name });
    }
    let mut have_list = false;
    // False after an event that already carries everything, so nothing is fetched for it.
    let mut fetch = true;
    loop {
        if fetch && !have_list {
            match client.statuses().await {
                Ok(list) => {
                    have_list = true;
                    notify.send(Backend::Statuses(list));
                }
                Err(e) => notify.send(Backend::StatusError(format!("{e:#}"))),
            }
        }
        if fetch {
            match client.current_status().await {
                Ok(status) => notify.send(Backend::CurrentStatus(status)),
                Err(e) => notify.send(Backend::StatusError(format!("{e:#}"))),
            }
        }
        fetch = true;
        tokio::select! {
            // Fallback in case a notification is missed or the event channel is down.
            _ = tokio::time::sleep(Duration::from_secs(60)) => {}
            event = server_events.recv() => match event {
                // The user may have added or renamed statuses, so reload the list as well.
                Some(ServerEvent::StatusChanged) => have_list = false,
                Some(ServerEvent::Connected) => notify.send(Backend::EventChannel),
                Some(ServerEvent::Presence(p)) => {
                    notify.send(Backend::Presence(p));
                    fetch = false; // carries the status itself
                }
                Some(ServerEvent::ContactPresence { id, presence }) => {
                    notify.send(Backend::ContactPresence { id, presence });
                    fetch = false;
                }
                None => {}
            },
            choice = choices.recv() => match choice {
                Some(id) => {
                    if let Err(e) = client.set_status(&id).await {
                        notify.send(Backend::StatusError(format!("{e:#}")));
                    }
                }
                None => return,
            },
        }
    }
}

/// Logs in to the MiCollab server, downloads the SIP account and runs the softphone until
/// the user logs out. The MiCollab password stays in memory for the session, because the
/// presence status is read and set with it.
async fn session(
    server: String,
    user: String,
    number: Option<String>,
    teleworker: Option<bool>,
    password: String,
    audio: AudioSettings,
    notify: Notifier,
    mut cmds: mpsc::Receiver<Command>,
    links: ServerLinks,
    switch_account: Arc<AtomicBool>,
) {
    // Like the Mitel client, drop a trailing "@<server>" from the login name.
    let user = provision::login_name(&server, &user);
    let login = MicollabConfig { server, user, user_agent: None, number, teleworker, tls_insecure: false };
    let mut profile = match provision::fetch(&login, &password, false).await {
        Ok(p) => p,
        Err(e) => {
            return notify.send(match e.downcast_ref::<provision::MultipleDeployments>() {
                Some(several) => Backend::ChooseNumber(several.0.clone()),
                None => Backend::LoginFailed(format!("{e:#}")),
            })
        }
    };
    match micollab::Client::new(&login, &password) {
        Ok(client) => {
            let client = Arc::new(client);
            tokio::spawn(presence(login.clone(), password.clone(), client.clone(), notify.clone(), links.choices, links.watchlist, links.watch_changed));
            tokio::spawn(directory(client, notify.clone(), links.directory_since, links.have_directory, links.refresh_directory));
        }
        Err(e) => notify.send(Backend::StatusError(format!("{e:#}"))),
    }
    drop(password);
    let mut cfg = SipConfig { acd: profile.acd, ..SipConfig::default() };
    cfg.use_account(&profile.account);
    notify.send(Backend::LoggedIn { number: profile.number.clone(), teleworker: profile.teleworker, can_switch: profile.other.is_some() });

    let (events, mut event_rx) = mpsc::unbounded_channel();
    let forward = notify.clone();
    tokio::spawn(async move {
        while let Some(event) = event_rx.recv().await {
            forward.send(Backend::Ua(event));
        }
    });
    loop {
        let quit = match ua::run(&cfg, &profile.account.password, false, Some(audio.clone()), &events, &mut cmds).await {
            Ok(()) => true,
            Err(e) => {
                let via = if profile.teleworker { "Teleworker" } else { "Telefonanlage" };
                notify.send(Backend::ConnectionLost(format!("Verbindung verloren ({via}): {e:#}")));
                // Wait before reconnecting, but leave at once if the user logs out meanwhile.
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(5)) => false,
                    cmd = cmds.recv() => matches!(cmd, None | Some(Command::Quit)),
                }
            }
        };
        if quit {
            // The softphone signed off: either for good or to register with the other account.
            if !(switch_account.swap(false, Ordering::SeqCst) && profile.switch()) {
                return;
            }
            cfg.use_account(&profile.account);
            notify.send(Backend::AccountSwitched { teleworker: profile.teleworker });
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Page {
    Phone,
    Contacts,
    History,
    Settings,
}

#[derive(Default)]
struct LoginForm {
    server: String,
    user: String,
    password: String,
    /// Keep the password (encrypted) and log in automatically at the next start.
    stay_logged_in: bool,
    /// Extension to use if the account has several; asked for when needed.
    number: Option<String>,
    /// The user's choice between teleworker and PBX account; `None` follows the profile.
    teleworker: Option<bool>,
    /// Extensions to choose from, while the question is open.
    number_choices: Vec<provision::Choice>,
    error: Option<String>,
    /// A neutral message, e.g. after resetting.
    notice: Option<String>,
    /// The user clicked "Zurücksetzen" and is asked to confirm.
    confirm_reset: bool,
    busy: bool,
}

/// The call currently shown, with what the history needs to know about it later.
struct Tracked {
    peer: String,
    incoming: bool,
    started: chrono::DateTime<chrono::Local>,
    connected: Option<Instant>,
}

struct HistoryEntry {
    peer: String,
    incoming: bool,
    answered: bool,
    started: chrono::DateTime<chrono::Local>,
    duration: Option<Duration>,
}

/// Which contacts the contact page lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContactTab {
    /// The corporate directory from the server.
    Company,
    /// The contacts the user created, stored on this computer only.
    Own,
}

/// Kinds of number an own contact can have, in the order of the form.
const OWN_PHONE_LABELS: [&str; 3] = ["Geschäftlich", "Mobil", "Privat"];

/// The form for creating or changing one of the user's own contacts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ContactForm {
    /// Id of the contact being changed; empty for a new one.
    id: String,
    first_name: String,
    last_name: String,
    company: String,
    department: String,
    email: String,
    /// Numbers in the order of `OWN_PHONE_LABELS`.
    numbers: [String; 3],
    /// The delete button was clicked once and asks for a second click.
    confirm_delete: bool,
}

impl ContactForm {
    fn edit(contact: &Contact) -> ContactForm {
        let mut numbers: [String; 3] = Default::default();
        for phone in &contact.phones {
            // A number of a kind the form does not know takes the first free field.
            let own_kind = OWN_PHONE_LABELS.iter().position(|label| *label == phone.label).filter(|i| numbers[*i].is_empty());
            if let Some(index) = own_kind.or_else(|| numbers.iter().position(String::is_empty)) {
                numbers[index] = phone.number.clone();
            }
        }
        ContactForm {
            id: contact.id.clone(),
            first_name: contact.first_name.clone(),
            last_name: contact.last_name.clone(),
            company: contact.company.clone(),
            department: contact.department.clone(),
            email: contact.email.clone(),
            numbers,
            confirm_delete: false,
        }
    }

    /// An empty form for a number that is not in the contacts yet.
    fn for_number(number: &str) -> ContactForm {
        let mut form = ContactForm::default();
        // German mobile numbers start with 015, 016 or 017; everything else counts as business.
        let mobile = ["015", "016", "017"].iter().any(|prefix| number_key(number).starts_with(prefix));
        form.numbers[if mobile { 1 } else { 0 }] = number.trim().to_string();
        form
    }

    /// A contact needs a name to be found in the list.
    fn complete(&self) -> bool {
        !self.first_name.trim().is_empty() || !self.last_name.trim().is_empty()
    }

    fn contact(&self) -> Contact {
        let phones = OWN_PHONE_LABELS
            .iter()
            .zip(&self.numbers)
            .filter(|(_, number)| !number.trim().is_empty())
            .map(|(label, number)| micollab::Phone { number: number.trim().to_string(), label: (*label).to_string() })
            .collect();
        Contact {
            id: self.id.clone(),
            first_name: self.first_name.trim().to_string(),
            last_name: self.last_name.trim().to_string(),
            company: self.company.trim().to_string(),
            department: self.department.trim().to_string(),
            email: self.email.trim().to_string(),
            phones,
            presence_id: None,
        }
    }
}

struct App {
    runtime: tokio::runtime::Runtime,
    theme: egui::ThemePreference,
    login: LoginForm,
    /// Channel from the running session; `None` while logged out.
    backend: Option<std_mpsc::Receiver<Backend>>,
    commands: Option<mpsc::Sender<Command>>,
    logged_in: bool,
    number: Option<String>,
    /// The softphone registers through the border gateway rather than directly at the PBX.
    teleworker: bool,
    /// The profile has both accounts and lets the user choose.
    can_switch_account: bool,
    /// Tells the session that the next sign-off is a change of account, not a logout.
    switch_account: Arc<AtomicBool>,
    /// The user's name for the avatar; empty until the server told us.
    user_name: String,
    statuses: Vec<Status>,
    current_status: Option<Status>,
    /// Our presence as the server sees it; `None` until the event channel delivered it.
    presence: Option<Presence>,
    status_choice: Option<mpsc::Sender<serde_json::Value>>,
    state: Snapshot,
    status_line: String,
    /// Dial pad keys typed on the keyboard, with the time until which they are drawn as pressed.
    typed_keys: Vec<(char, f64)>,
    page: Page,
    dial: String,
    tracked: Option<Tracked>,
    history: Vec<HistoryEntry>,
    /// Calls missed since the history page was last looked at, shown as a badge on its icon.
    missed_calls: usize,
    audio: AudioSettings,
    /// Output devices the ringtone plays on; none is the system default.
    ring_outputs: Vec<String>,
    ring_tone: Tone,
    /// Volume of the ringtone in percent.
    ring_volume: u8,
    /// The ringtone while it plays, for a call or as a sample in the settings.
    ringer: Option<Ringer>,
    /// The user is listening to the ringtone in the settings.
    ring_preview: bool,
    /// Demo mode shows calls that are not there and does not ring for them.
    demo: bool,
    inputs: Vec<String>,
    outputs: Vec<String>,
    /// Encrypted storage; `None` if it could not be opened (then nothing is saved) or after
    /// a reset, until something is saved again.
    store: Option<Store>,
    /// False if the store could not be opened at start; then it is not tried again.
    store_usable: bool,
    /// Password of a login in progress, kept until the server accepted it.
    pending_password: Option<String>,
    /// Password as it is currently stored on disk.
    saved_password: Option<String>,
    /// Demo mode only: show the status menu opened.
    demo_status_menu: bool,
    /// Demo mode only: show the number menu of a contact opened.
    demo_number_menu: bool,
    /// Show contacts as "Last, First" sorted by last name instead of "First Last" sorted by
    /// first name.
    last_name_first: bool,
    /// The corporate directory, sorted by name, and the marker for syncing changes.
    contacts: Vec<Contact>,
    directory_timestamp: serde_json::Value,
    directory_loading: bool,
    /// The contacts the user created, sorted by name.
    own_contacts: Vec<Contact>,
    contact_tab: ContactTab,
    /// The form shown in place of the contact list while a contact is created or changed.
    contact_form: Option<ContactForm>,
    /// Number of a caller who is not in the contacts, offered for saving after the call.
    save_offer: Option<String>,
    groups: Vec<ContactGroup>,
    contact_search: String,
    /// Index into `groups` of the group shown; `None` shows everyone.
    contact_group: Option<usize>,
    /// Presence of watched contacts by lower-case presence identity.
    contact_presence: HashMap<String, Presence>,
    watchlist: Watchlist,
    watch_signal: Option<mpsc::UnboundedSender<()>>,
    refresh_directory: Option<mpsc::Sender<()>>,
    /// Names of all contacts by dialled digits, to show names instead of bare numbers.
    names_by_number: HashMap<String, String>,
}

/// Volume of the ringtone in percent until the user chooses one.
const DEFAULT_RING_VOLUME: u8 = 70;

/// At most this many contacts are listed at once; a search narrows it down.
const CONTACTS_SHOWN: usize = 200;
/// Presence is watched for the first rows of the list only.
const PRESENCE_WATCHED: usize = 60;

/// The digits of a number as they would be dialled, to compare numbers written differently.
fn dial_key(number: &str) -> String {
    number.chars().filter(|c| c.is_ascii_digit() || *c == '+').collect()
}

/// Country code of the numbers the telephone system treats as national.
const COUNTRY_CODE: &str = "49";

/// A number in the one form used to compare it with others. Depending on its
/// configuration the telephone system reports the same national number as `+49 170 ...`,
/// `0049 170 ...` or `00170 ...` (outside line and national prefix), and contacts are
/// written in any of these or simply as `0170 ...`; all become `0170...`.
fn number_key(number: &str) -> String {
    let digits = dial_key(number);
    let national = digits
        .strip_prefix(&format!("+{COUNTRY_CODE}"))
        .or_else(|| digits.strip_prefix(&format!("00{COUNTRY_CODE}")))
        .or_else(|| digits.strip_prefix("00"));
    match national {
        Some(rest) if !rest.is_empty() => format!("0{}", rest.trim_start_matches('0')),
        _ => digits,
    }
}

/// Sorts by the name part that is shown first, then by the other one.
fn sort_contacts(contacts: &mut [Contact], last_name_first: bool) {
    contacts.sort_by_cached_key(|c| {
        let (first, last) = (c.first_name.trim().to_lowercase(), c.last_name.trim().to_lowercase());
        if last_name_first {
            (last, first)
        } else {
            (first, last)
        }
    });
}

fn contact_matches(contact: &Contact, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    // Digits typed are looked for in the numbers as written and in their common form.
    let (digits, key) = (dial_key(needle), number_key(needle));
    [&contact.first_name, &contact.last_name, &contact.company, &contact.department, &contact.email].iter().any(|f| f.to_lowercase().contains(needle))
        || contact.name().to_lowercase().contains(needle)
        || contact.name_last_first().to_lowercase().contains(needle)
        || (!digits.is_empty() && contact.phones.iter().any(|p| dial_key(&p.number).contains(&digits) || number_key(&p.number).contains(&key)))
}

/// Colour of a presence dot and whether it blinks.
fn indicator_dot(indicator: Indicator) -> (egui::Color32, bool) {
    match indicator {
        Indicator::Available => (egui::Color32::from_rgb(60, 170, 80), false),
        Indicator::Away => (egui::Color32::from_rgb(230, 170, 30), false),
        Indicator::Busy => (egui::Color32::from_rgb(210, 60, 55), false),
        Indicator::Ringing => (egui::Color32::from_rgb(210, 60, 55), true),
        Indicator::DoNotDisturb => (egui::Color32::from_rgb(150, 30, 60), false),
        Indicator::Offline | Indicator::Unknown => (egui::Color32::from_rgb(140, 140, 140), false),
    }
}

/// A round avatar with initials and, if given, a status dot (colour, blinking) in its corner.
fn avatar_widget(ui: &mut egui::Ui, size: f32, text: &str, dot: Option<(egui::Color32, bool)>, sense: egui::Sense) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(egui::vec2(size, size), sense);
    let painter = ui.painter();
    let accent = egui::Color32::from_rgb(26, 150, 140);
    painter.circle_filled(rect.center(), size / 2.0, if response.hovered() && sense.senses_click() { accent.gamma_multiply(0.85) } else { accent });
    painter.text(rect.center(), egui::Align2::CENTER_CENTER, text, egui::FontId::proportional(size * 0.41), egui::Color32::WHITE);
    if let Some((colour, blink)) = dot {
        let lit = !blink || ui.input(|i| i.time).fract() < 0.5;
        if blink {
            ui.ctx().request_repaint_after(Duration::from_millis(250));
        }
        // A ring in the background colour separates the dot from the avatar.
        let centre = rect.right_bottom() - egui::vec2(size * 0.15, size * 0.15);
        painter.circle_filled(centre, size * 0.2, ui.visuals().panel_fill);
        painter.circle_filled(centre, size * 0.145, if lit { colour } else { colour.gamma_multiply(0.25) });
    }
    response
}

/// How many calls of the stored history are shown.
const HISTORY_SHOWN: usize = 500;

fn theme_name(theme: egui::ThemePreference) -> &'static str {
    match theme {
        egui::ThemePreference::Light => "light",
        egui::ThemePreference::Dark => "dark",
        egui::ThemePreference::System => "system",
    }
}

fn theme_from_name(name: &str) -> egui::ThemePreference {
    match name {
        "light" => egui::ThemePreference::Light,
        "dark" => egui::ThemePreference::Dark,
        _ => egui::ThemePreference::System,
    }
}

impl HistoryEntry {
    fn from_record(r: CallRecord) -> HistoryEntry {
        let started = chrono::DateTime::from_timestamp(r.started, 0).unwrap_or_default().with_timezone(&chrono::Local);
        HistoryEntry { peer: r.peer, incoming: r.incoming, answered: r.answered, started, duration: r.duration_secs.map(Duration::from_secs) }
    }

    fn to_record(&self) -> CallRecord {
        CallRecord {
            peer: self.peer.clone(),
            incoming: self.incoming,
            answered: self.answered,
            started: self.started.timestamp(),
            duration_secs: self.duration.map(|d| d.as_secs()),
        }
    }
}

/// Open Sans (SIL Open Font License, see `assets/fonts/OFL.txt`), built into the executable.
const TEXT_FONT: &[u8] = include_bytes!("../assets/fonts/OpenSans-Regular.ttf");

/// Makes Open Sans the first choice for all proportional text; egui's own fonts stay as fallback
/// for characters it lacks.
fn install_text_font(ctx: &egui::Context) {
    use egui::epaint::text::{FontInsert, FontPriority, InsertFontFamily};
    ctx.add_font(FontInsert::new(
        "Open Sans",
        egui::FontData::from_static(TEXT_FONT),
        vec![InsertFontFamily { family: egui::FontFamily::Proportional, priority: FontPriority::Highest }],
    ));
}

/// How long a dial pad key stays drawn as pressed after its digit was typed, in seconds.
const KEY_FLASH: f64 = 0.025;

impl App {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let theme = egui::ThemePreference::System;
        cc.egui_ctx.set_theme(theme);
        install_text_font(&cc.egui_ctx);
        egui_material_icons::initialize(&cc.egui_ctx);
        cc.egui_ctx.set_zoom_factor(UI_SCALE);
        let (inputs, outputs) = media::list_devices();
        let mut app = App {
            runtime: tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("tokio runtime"),
            theme,
            login: LoginForm::default(),
            backend: None,
            commands: None,
            logged_in: false,
            number: None,
            teleworker: false,
            can_switch_account: false,
            switch_account: Arc::new(AtomicBool::new(false)),
            user_name: String::new(),
            statuses: Vec::new(),
            current_status: None,
            presence: None,
            status_choice: None,
            state: Snapshot::default(),
            status_line: String::new(),
            typed_keys: Vec::new(),
            page: Page::Phone,
            dial: String::new(),
            tracked: None,
            history: Vec::new(),
            missed_calls: 0,
            audio: AudioSettings::default(),
            ring_outputs: Vec::new(),
            ring_tone: Tone::default(),
            ring_volume: DEFAULT_RING_VOLUME,
            ringer: None,
            ring_preview: false,
            demo: false,
            inputs,
            outputs,
            store: None,
            store_usable: false,
            pending_password: None,
            saved_password: None,
            demo_status_menu: false,
            demo_number_menu: false,
            last_name_first: false,
            contacts: Vec::new(),
            directory_timestamp: serde_json::Value::Null,
            directory_loading: false,
            own_contacts: Vec::new(),
            contact_tab: ContactTab::Company,
            contact_form: None,
            save_offer: None,
            groups: Vec::new(),
            contact_search: String::new(),
            contact_group: None,
            contact_presence: HashMap::new(),
            watchlist: Watchlist::default(),
            watch_signal: None,
            refresh_directory: None,
            names_by_number: HashMap::new(),
        };
        // `--demo[=call|incoming|history|settings|status|contacts|numbers|own|newcontact|savenumber|missed|login|reset]` shows the main window with sample data
        // and without any network connection, for working on the layout.
        match std::env::args().find_map(|a| a.strip_prefix("--demo").map(str::to_string)) {
            Some(demo) => app.enter_demo(demo.trim_start_matches('=')),
            None => app.restore(&cc.egui_ctx),
        }
        app
    }

    /// Loads settings and history from the encrypted store and logs in if the user chose to stay logged in.
    fn restore(&mut self, ctx: &egui::Context) {
        let store = match Store::open(profile_argument().as_deref()) {
            Ok(store) => store,
            Err(e) => {
                self.login.error = Some(format!("Gespeicherte Daten sind nicht verfügbar, es wird nichts gespeichert: {e:#}"));
                return;
            }
        };
        let settings = store.load_settings();
        self.theme = theme_from_name(&settings.theme);
        ctx.set_theme(self.theme);
        {
            let mut devices = self.audio.lock().unwrap();
            devices.input = settings.audio_input;
            devices.output = settings.audio_output;
        }
        self.login.server = settings.server;
        self.login.user = settings.user;
        self.login.stay_logged_in = settings.stay_logged_in;
        self.login.number = settings.number;
        self.login.teleworker = settings.teleworker;
        self.saved_password = settings.password;
        self.last_name_first = settings.last_name_first;
        self.ring_outputs = settings.ring_outputs;
        self.ring_tone = Tone::from_setting(&settings.ringtone);
        self.ring_volume = settings.ring_volume.unwrap_or(DEFAULT_RING_VOLUME).min(100);
        self.history = store.recent_calls(HISTORY_SHOWN).unwrap_or_default().into_iter().map(HistoryEntry::from_record).collect();
        self.set_own_contacts(store.own_contacts().unwrap_or_default());
        self.store = Some(store);
        self.store_usable = true;
        if let (true, Some(password)) = (self.login.stay_logged_in, self.saved_password.clone()) {
            if !self.login.server.is_empty() && !self.login.user.is_empty() {
                self.login.password = password;
                self.start_login(ctx);
            }
        }
    }

    /// Opens the store again after a reset removed it. Does nothing if it is open.
    fn ensure_store(&mut self) {
        if self.store.is_none() && self.store_usable {
            self.store = Store::open(profile_argument().as_deref()).ok();
        }
    }

    /// Deletes everything miphone has saved and returns the window to its first-start state.
    fn reset_everything(&mut self, ctx: &egui::Context) {
        self.ensure_store();
        let result = match self.store.take() {
            Some(store) => store.reset(),
            None => Ok(()),
        };
        self.login = LoginForm::default();
        match result {
            Ok(()) => self.login.notice = Some("Alle gespeicherten Daten wurden gelöscht.".into()),
            Err(e) => self.login.error = Some(format!("Zurücksetzen fehlgeschlagen: {e:#}")),
        }
        self.saved_password = None;
        self.pending_password = None;
        self.history.clear();
        self.missed_calls = 0;
        self.last_name_first = false;
        self.contact_form = None;
        self.save_offer = None;
        self.contact_tab = ContactTab::Company;
        self.set_own_contacts(Vec::new());
        self.set_contacts(Vec::new());
        self.directory_timestamp = serde_json::Value::Null;
        *self.audio.lock().unwrap() = Default::default();
        self.ring_outputs.clear();
        self.ring_tone = Tone::default();
        self.ring_volume = DEFAULT_RING_VOLUME;
        self.ring_preview = false;
        self.theme = egui::ThemePreference::System;
        ctx.set_theme(self.theme);
    }

    /// Writes the current settings to the encrypted store.
    fn persist(&mut self) {
        self.ensure_store();
        let Some(store) = &self.store else { return };
        let devices = self.audio.lock().unwrap().clone();
        let settings = Settings {
            server: self.login.server.trim().to_string(),
            user: self.login.user.trim().to_string(),
            password: self.saved_password.clone(),
            stay_logged_in: self.login.stay_logged_in,
            number: self.login.number.clone(),
            teleworker: self.login.teleworker,
            theme: theme_name(self.theme).to_string(),
            audio_input: devices.input,
            audio_output: devices.output,
            last_name_first: self.last_name_first,
            ring_outputs: self.ring_outputs.clone(),
            ringtone: self.ring_tone.to_setting(),
            ring_volume: Some(self.ring_volume),
        };
        if let Err(e) = store.save_settings(&settings) {
            self.status_line = format!("Speichern fehlgeschlagen: {e:#}");
        }
    }

    fn enter_demo(&mut self, variant: &str) {
        self.demo = true;
        self.logged_in = true;
        self.number = Some("1234".into());
        self.user_name = "Max Mustermann".into();
        self.status_line = "Demo-Modus ohne Verbindung".into();
        self.state.registered = true;
        let now = chrono::Local::now();
        let entry = |peer: &str, incoming, answered, minutes, secs| HistoryEntry {
            peer: peer.into(),
            incoming,
            answered,
            started: now - chrono::Duration::minutes(minutes),
            duration: answered.then(|| Duration::from_secs(secs)),
        };
        let status = |id: i64, name: &str, im: &str, calls| Status { id: id.into(), name: name.into(), im_status: im.into(), available_for_calls: calls };
        self.statuses = vec![status(1, "Im Büro", "Idle", true), status(2, "Mobil", "Away", true), status(3, "Nicht stören", "Away", false)];
        self.current_status = self.statuses.first().cloned();
        let person = |id: &str, first: &str, last: &str, dept: &str, numbers: &[&str]| Contact {
            id: id.into(),
            first_name: first.into(),
            last_name: last.into(),
            department: dept.into(),
            phones: numbers.iter().map(|n| micollab::Phone { number: (*n).into(), label: "Work".into() }).collect(),
            presence_id: Some(format!("{id}@demo")),
            ..Contact::default()
        };
        self.set_contacts(vec![
            person("c1", "Erika", "Muster", "Vertrieb", &["1001", "0170 1234567", "+49 30 1234567"]),
            person("c2", "Max", "Beispiel", "Technik", &["1002"]),
            person("c3", "Anna", "Schmidt", "Buchhaltung", &["1003"]),
            person("c4", "Jonas", "Weber", "Technik", &["1004"]),
        ]);
        self.groups = vec![ContactGroup { name: "Favoriten".into(), members: vec!["c1".into(), "c4".into()] }];
        self.set_own_contacts(vec![
            Contact { company: "Beispiel Handwerk".into(), presence_id: None, ..person("own-1", "Petra", "Klein", "", &["030 5550100"]) },
            Contact { presence_id: None, ..person("own-2", "Tom", "Berger", "", &[]) },
        ]);
        let seen = |telephony: &str, external: &str, name: &str| Presence {
            telephony_state: telephony.into(),
            external_presence: external.into(),
            status_name: name.into(),
            available_for_calls: true,
            ..Presence::default()
        };
        self.contact_presence = HashMap::from([
            ("c1@demo".to_string(), seen("Idle", "Default", "Im Büro")),
            ("c2@demo".to_string(), seen("In A Call", "Default", "Im Büro")),
            ("c3@demo".to_string(), seen("Idle", "Away", "Abwesend")),
        ]);
        self.history = vec![entry("Erika Muster (1001)", true, true, 95, 312), entry("0170 1234567", false, true, 40, 75), entry("1002", true, false, 12, 0)];
        let call = |phase| CallSnapshot { peer: "Erika Muster (1001)".into(), incoming: true, phase, muted: false, codec: Some("opus".into()) };
        match variant {
            "call" => {
                self.state.call = Some(call(CallPhase::Active));
                self.tracked = Some(Tracked { peer: "Erika Muster (1001)".into(), incoming: true, started: now, connected: Some(Instant::now()) });
            }
            "incoming" => self.state.call = Some(CallSnapshot { codec: None, ..call(CallPhase::Incoming) }),
            "history" => self.page = Page::History,
            "contacts" => self.page = Page::Contacts,
            "numbers" => {
                self.page = Page::Contacts;
                self.demo_number_menu = true;
            }
            "own" => {
                self.page = Page::Contacts;
                self.contact_tab = ContactTab::Own;
            }
            "newcontact" => {
                self.page = Page::Contacts;
                self.contact_form = Some(ContactForm::default());
            }
            "savenumber" => self.save_offer = Some("0170 7654321".into()),
            "missed" => self.missed_calls = 2,
            "settings" => {
                self.page = Page::Settings;
                self.can_switch_account = true;
            }
            "status" => self.demo_status_menu = true,
            // The login form as on first start, without reading or writing saved data.
            "login" => self.logged_in = false,
            "reset" => {
                self.logged_in = false;
                self.login.confirm_reset = true;
            }
            _ => {}
        }
    }

    fn send(&self, cmd: Command) {
        if let Some(tx) = &self.commands {
            let _ = tx.try_send(cmd);
        }
    }

    fn start_login(&mut self, ctx: &egui::Context) {
        let (tx, rx) = std_mpsc::channel();
        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        let (choice_tx, choice_rx) = mpsc::channel(4);
        let (watch_tx, watch_rx) = mpsc::unbounded_channel();
        let (refresh_tx, refresh_rx) = mpsc::channel(2);
        // Start from the cached directory if it belongs to this account.
        let cache = self.store.as_ref().map(Store::load_directory).filter(|c| c.owner == self.directory_owner()).unwrap_or_default();
        self.directory_timestamp = cache.timestamp;
        self.set_contacts(cache.contacts);
        self.directory_loading = true;
        self.watchlist.lock().unwrap().clear();
        let links = ServerLinks {
            choices: choice_rx,
            watchlist: self.watchlist.clone(),
            watch_changed: watch_rx,
            directory_since: self.directory_timestamp.clone(),
            have_directory: !self.contacts.is_empty(),
            refresh_directory: refresh_rx,
        };
        let notify = Notifier { tx, ctx: ctx.clone() };
        let password = std::mem::take(&mut self.login.password);
        // Kept until the login is through: needed again if an extension has to be chosen first.
        self.pending_password = Some(password.clone());
        self.login.number_choices.clear();
        self.runtime.spawn(session(
            self.login.server.trim().to_string(),
            self.login.user.trim().to_string(),
            self.login.number.clone(),
            self.login.teleworker,
            password,
            self.audio.clone(),
            notify,
            cmd_rx,
            links,
            self.switch_account.clone(),
        ));
        self.watch_signal = Some(watch_tx);
        self.refresh_directory = Some(refresh_tx);
        self.backend = Some(rx);
        self.commands = Some(cmd_tx);
        self.status_choice = Some(choice_tx);
        self.login.busy = true;
        self.login.error = None;
        self.login.notice = None;
        self.login.confirm_reset = false;
    }

    fn logout(&mut self) {
        self.switch_account.store(false, Ordering::SeqCst);
        self.send(Command::Quit);
        // Logging out also forgets the stored password, the chosen extension and the choice of
        // SIP account, so the next login starts from the profile; server and user name stay.
        self.saved_password = None;
        self.pending_password = None;
        self.login.number = None;
        self.login.teleworker = None;
        self.can_switch_account = false;
        self.login.number_choices.clear();
        self.persist();
        // The session signs off in the background; the window returns to the login form.
        self.backend = None;
        self.commands = None;
        self.status_choice = None;
        self.statuses.clear();
        self.current_status = None;
        self.presence = None;
        self.user_name.clear();
        self.watch_signal = None;
        self.refresh_directory = None;
        self.contact_presence.clear();
        self.groups.clear();
        self.contact_group = None;
        self.contact_search.clear();
        self.contact_form = None;
        self.save_offer = None;
        self.contact_tab = ContactTab::Company;
        // The user's own contacts belong to this computer, not to the account, and stay.
        self.set_contacts(Vec::new());
        self.logged_in = false;
        self.login.busy = false;
        self.number = None;
        self.state = Snapshot::default();
        self.tracked = None;
        self.missed_calls = 0;
        self.status_line.clear();
        self.page = Page::Phone;
    }

    /// Identifies the account a cached directory belongs to.
    fn directory_owner(&self) -> String {
        format!("{}|{}", self.login.server.trim().to_lowercase(), self.login.user.trim().to_lowercase())
    }

    /// Replaces the directory, keeping it sorted and the number lookup up to date.
    fn set_contacts(&mut self, mut contacts: Vec<Contact>) {
        sort_contacts(&mut contacts, self.last_name_first);
        self.contacts = contacts;
        self.rebuild_names();
    }

    /// Replaces the user's own contacts, keeping them sorted and the number lookup up to date.
    fn set_own_contacts(&mut self, mut contacts: Vec<Contact>) {
        sort_contacts(&mut contacts, self.last_name_first);
        self.own_contacts = contacts;
        self.rebuild_names();
    }

    /// Rebuilds the lookup of names by number. For a number in both lists the user's own
    /// contact names it.
    fn rebuild_names(&mut self) {
        self.names_by_number = self
            .contacts
            .iter()
            .chain(&self.own_contacts)
            .filter(|c| !c.name().is_empty())
            .flat_map(|c| c.phones.iter().map(|p| (number_key(&p.number), c.name())))
            .filter(|(key, _)| !key.is_empty())
            .collect();
    }

    /// Stores the contact of the form and closes it; on failure the form stays open.
    fn save_contact_form(&mut self) {
        let Some(form) = &self.contact_form else { return };
        let mut contact = form.contact();
        self.ensure_store();
        match &self.store {
            Some(store) => {
                if let Err(e) = store.save_own_contact(&mut contact) {
                    self.status_line = format!("Kontakt konnte nicht gespeichert werden: {e:#}");
                    return;
                }
            }
            // Without a store the contact lives until the program ends.
            None if contact.id.is_empty() => contact.id = format!("unsaved-{}", chrono::Local::now().timestamp_micros()),
            None => {}
        }
        let mut contacts = std::mem::take(&mut self.own_contacts);
        contacts.retain(|c| c.id != contact.id);
        contacts.push(contact);
        self.set_own_contacts(contacts);
        self.contact_form = None;
        self.contact_tab = ContactTab::Own;
    }

    /// Deletes the contact of the form and closes it; on failure the form stays open.
    fn delete_contact_form(&mut self) {
        let Some(id) = self.contact_form.as_ref().map(|form| form.id.clone()) else { return };
        self.ensure_store();
        if let Some(Err(e)) = self.store.as_ref().map(|s| s.delete_own_contact(&id)) {
            self.status_line = format!("Kontakt konnte nicht gelöscht werden: {e:#}");
            return;
        }
        let mut contacts = std::mem::take(&mut self.own_contacts);
        contacts.retain(|c| c.id != id);
        self.set_own_contacts(contacts);
        self.contact_form = None;
    }

    /// Applies the result of a directory sync and stores it encrypted.
    fn merge_directory(&mut self, changed: Vec<Contact>, deleted: Vec<String>, timestamp: serde_json::Value, full: bool) {
        let mut contacts = if full { Vec::new() } else { std::mem::take(&mut self.contacts) };
        contacts.retain(|c| !deleted.contains(&c.id) && !changed.iter().any(|n| n.id == c.id));
        contacts.extend(changed);
        self.set_contacts(contacts);
        self.directory_timestamp = timestamp;
        self.directory_loading = false;
        self.ensure_store();
        let cache = DirectoryCache { owner: self.directory_owner(), timestamp: self.directory_timestamp.clone(), contacts: self.contacts.clone() };
        if let Some(Err(e)) = self.store.as_ref().map(|s| s.save_directory(&cache)) {
            self.status_line = format!("Verzeichnis konnte nicht gespeichert werden: {e:#}");
        }
    }

    /// A caller or callee as shown to the user: with the name from the directory if the
    /// server gave only a number.
    fn named(&self, peer: &str) -> String {
        if peer.contains('(') {
            return peer.to_string(); // already "Name (number)"
        }
        match self.names_by_number.get(&number_key(peer)) {
            Some(name) => format!("{name} ({peer})"),
            None => peer.to_string(),
        }
    }

    /// Starts and stops the ringtone: it plays while a call rings here and while the user
    /// listens to it in the settings.
    fn update_ringer(&mut self) {
        let incoming = self.state.call.as_ref().is_some_and(|call| call.phase == CallPhase::Incoming) && !self.demo;
        if self.page != Page::Settings || !self.logged_in {
            self.ring_preview = false;
        }
        match (incoming || self.ring_preview, self.ringer.is_some()) {
            (true, false) => self.ringer = Some(Ringer::start(self.ring_tone.clone(), self.ring_outputs.clone(), self.ring_volume as f32 / 100.0)),
            (false, true) => self.ringer = None,
            _ => {}
        }
        if let Some(error) = self.ringer.as_ref().and_then(Ringer::take_error) {
            self.status_line = error;
        }
    }

    /// Whether this is a number that no contact has. A caller without a number is not one.
    fn unknown_number(&self, number: &str) -> bool {
        let key = number_key(number);
        key.chars().any(|c| c.is_ascii_digit()) && !self.names_by_number.contains_key(&key)
    }

    /// The small window over the page that offers to save the number of the last caller.
    fn save_offer_window(&mut self, ctx: &egui::Context) {
        let Some(number) = self.save_offer.clone() else { return };
        // Saved in the meantime, by hand or by a directory sync: nothing left to offer.
        if !self.unknown_number(&number) {
            self.save_offer = None;
            return;
        }
        let (mut save, mut dismiss) = (false, false);
        egui::Window::new("Nummer speichern?")
            .collapsible(false)
            .resizable(false)
            .default_width(210.0)
            .anchor(egui::Align2::RIGHT_BOTTOM, [-12.0, -36.0])
            .show(ctx, |ui| {
                ui.label(egui::RichText::new(&number).strong());
                ui.label("Nicht in den Kontakten.");
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    save = ui.button("Speichern").clicked();
                    dismiss = ui.button("Nein").clicked();
                });
            });
        if save {
            self.contact_form = Some(ContactForm::for_number(&number));
            self.page = Page::Contacts;
        }
        if save || dismiss {
            self.save_offer = None;
        }
    }

    /// Asks the server for the presence of these contacts (and no others).
    fn watch(&mut self, mut ids: Vec<String>) {
        ids.sort();
        ids.dedup();
        let mut current = self.watchlist.lock().unwrap();
        if *current != ids {
            *current = ids;
            if let Some(signal) = &self.watch_signal {
                let _ = signal.send(());
            }
        }
    }

    fn place_call(&mut self) {
        let number = self.dial.trim().to_string();
        if !number.is_empty() && self.state.registered && self.state.call.is_none() {
            self.send(Command::Call(number));
        }
    }

    fn poll_backend(&mut self, ctx: &egui::Context) {
        let Some(rx) = &self.backend else { return };
        let messages: Vec<Backend> = rx.try_iter().collect();
        for msg in messages {
            match msg {
                Backend::ChooseNumber(choices) => {
                    self.login.busy = false;
                    self.login.number_choices = choices;
                    self.backend = None;
                    self.commands = None;
                }
                Backend::LoginFailed(error) => {
                    self.pending_password = None;
                    // A stored extension may no longer exist; ask again next time.
                    self.login.number = None;
                    self.login.busy = false;
                    self.login.error = Some(error);
                    self.backend = None;
                    self.commands = None;
                }
                Backend::LoggedIn { number, teleworker, can_switch } => {
                    // The server accepted the login: now it is worth remembering.
                    self.saved_password = self.pending_password.take().filter(|_| self.login.stay_logged_in);
                    self.persist();
                    self.logged_in = true;
                    self.login.busy = false;
                    self.number = number;
                    self.teleworker = teleworker;
                    self.can_switch_account = can_switch;
                    self.status_line = Self::connecting_text(teleworker).into();
                }
                Backend::AccountSwitched { teleworker } => {
                    self.teleworker = teleworker;
                    self.status_line = Self::connecting_text(teleworker).into();
                    self.on_state(Snapshot::default(), ctx);
                }
                Backend::ConnectionLost(text) => {
                    self.status_line = text;
                    self.on_state(Snapshot::default(), ctx);
                }
                Backend::Statuses(list) => self.statuses = list,
                Backend::CurrentStatus(status) => self.current_status = Some(status),
                Backend::StatusError(text) => self.status_line = format!("Status: {text}"),
                Backend::EventChannel => self.status_line = "Ereigniskanal zum MiCollab-Server verbunden.".into(),
                Backend::ContactPresence { id, presence } => {
                    self.contact_presence.insert(id, presence);
                }
                Backend::Directory { contacts, deleted, timestamp, full } => {
                    self.merge_directory(contacts, deleted, timestamp, full);
                    self.status_line = format!("Verzeichnis abgeglichen: {} Kontakte.", self.contacts.len());
                }
                Backend::Groups(groups) => {
                    self.groups = groups;
                    self.contact_group = self.contact_group.filter(|i| *i < self.groups.len());
                }
                Backend::DirectoryError(text) => {
                    self.directory_loading = false;
                    self.status_line = format!("Verzeichnis: {text}");
                }
                Backend::Profile { first_name, last_name } => self.user_name = format!("{first_name} {last_name}").trim().to_string(),
                Backend::Presence(p) => {
                    // The notification names the status, so the drop-down can follow at once.
                    if let Some(status) = self.statuses.iter().find(|s| s.id == p.status_id) {
                        self.current_status = Some(status.clone());
                    }
                    self.presence = Some(p);
                }
                Backend::Ua(Event::Log(line)) => self.status_line = line,
                Backend::Ua(Event::State(state)) => self.on_state(state, ctx),
            }
        }
    }

    /// Takes over a new state and keeps the call history up to date.
    fn on_state(&mut self, new: Snapshot, ctx: &egui::Context) {
        match (&mut self.tracked, &new.call) {
            (None, Some(call)) => {
                self.tracked = Some(Tracked {
                    peer: call.peer.clone(),
                    incoming: call.incoming,
                    started: chrono::Local::now(),
                    connected: matches!(call.phase, CallPhase::Active | CallPhase::Held).then(Instant::now),
                });
                if call.phase == CallPhase::Incoming {
                    // Make sure a ringing call is noticed.
                    self.page = Page::Phone;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                    ctx.send_viewport_cmd(egui::ViewportCommand::RequestUserAttention(egui::UserAttentionType::Critical));
                }
            }
            (Some(t), Some(call)) => {
                t.peer = call.peer.clone(); // the name may arrive after the number
                if t.connected.is_none() && matches!(call.phase, CallPhase::Active | CallPhase::Held) {
                    t.connected = Some(Instant::now());
                }
            }
            (Some(_), None) => {
                let t = self.tracked.take().expect("checked above");
                let entry = HistoryEntry {
                    peer: t.peer,
                    incoming: t.incoming,
                    answered: t.connected.is_some(),
                    started: t.started,
                    duration: t.connected.map(|c| c.elapsed()),
                };
                // A missed call is counted unless the history is on screen and shows it anyway.
                if entry.incoming && !entry.answered && self.page != Page::History {
                    self.missed_calls += 1;
                }
                // After a call that was taken, offer to save a caller the contacts do not know.
                if entry.incoming && entry.answered {
                    let number = number_of(&entry.peer);
                    if self.unknown_number(&number) {
                        self.save_offer = Some(number);
                    }
                }
                self.ensure_store();
                if let Some(Err(e)) = self.store.as_ref().map(|s| s.add_call(&entry.to_record())) {
                    self.status_line = format!("Verlauf konnte nicht gespeichert werden: {e:#}");
                }
                self.history.push(entry);
            }
            (None, None) => {}
        }
        self.state = new;
    }

    /// Colour of the status dot, a note about the phone state and whether the dot blinks.
    /// Like in the MiCollab client the phone state wins over the chosen status: busy while
    /// in a call, blinking while it rings.
    fn status(&self) -> (egui::Color32, &'static str, bool) {
        let grey = egui::Color32::from_rgb(140, 140, 140);
        let green = egui::Color32::from_rgb(60, 170, 80);
        let yellow = egui::Color32::from_rgb(230, 170, 30);
        let red = egui::Color32::from_rgb(210, 60, 55);
        let dnd = egui::Color32::from_rgb(150, 30, 60);
        match (&self.state.call, self.state.registered) {
            (Some(call), _) => match call.phase {
                CallPhase::Incoming => (red, "Eingehender Anruf", true),
                CallPhase::Dialing => (red, "Ruft an", true),
                CallPhase::Active => (red, "Im Gespräch", false),
                CallPhase::Held => (red, "Gehalten", false),
            },
            (None, false) => (grey, "Telefon nicht verbunden", false),
            // The server's view of our presence decides, as in the MiCollab client.
            (None, true) => match (self.presence.as_ref().map(Presence::indicator), &self.current_status) {
                (Some(Indicator::Available), _) => (green, "", false),
                (Some(Indicator::Away), _) => (yellow, "", false),
                (Some(Indicator::Busy), _) => (red, "", false),
                (Some(Indicator::Ringing), _) => (red, "", true),
                (Some(Indicator::DoNotDisturb), _) => (dnd, "Nicht stören", false),
                (Some(Indicator::Offline), _) => (grey, "Offline", false),
                (Some(Indicator::Unknown), _) => (grey, "", false),
                // No presence from the server yet: estimate from the chosen status.
                (None, Some(s)) if !s.available_for_calls => (red, "", false),
                (None, Some(s)) if s.im_status.eq_ignore_ascii_case("away") => (yellow, "", false),
                (None, _) => (green, "", false),
            },
        }
    }

    /// The user's avatar: initials in a circle with the status dot in its corner. A click
    /// opens the list of statuses.
    fn avatar(&mut self, ui: &mut egui::Ui) {
        let (colour, note, blink) = self.status();
        let name = if self.user_name.is_empty() { self.login.user.clone() } else { self.user_name.clone() };
        let response = avatar_widget(ui, 34.0, &initials(&name), Some((colour, blink)), egui::Sense::click());

        let status = self.current_status.as_ref().map(|s| s.name.clone()).unwrap_or_else(|| "Status unbekannt".into());
        let mut hover = format!("{name}\n{status}");
        if !note.is_empty() {
            hover.push_str(&format!(" · {note}"));
        }
        let response = response.on_hover_text(hover).on_hover_cursor(egui::CursorIcon::PointingHand);

        let mut chosen = None;
        let mut menu = egui::Popup::menu(&response);
        if self.demo_status_menu {
            menu = menu.open(true);
        }
        menu.show(|ui| {
            ui.set_min_width(170.0);
            ui.label(egui::RichText::new(&name).strong());
            ui.separator();
            if self.statuses.is_empty() {
                ui.label(egui::RichText::new("Statusliste nicht verfügbar").weak());
            }
            for status in &self.statuses {
                let selected = self.current_status.as_ref().is_some_and(|c| c.id == status.id);
                if ui.add(egui::Button::selectable(selected, &status.name)).clicked() {
                    if !selected {
                        chosen = Some(status.clone());
                    }
                    ui.close();
                }
            }
        });
        if let Some(status) = chosen {
            if let Some(tx) = &self.status_choice {
                let _ = tx.try_send(status.id.clone());
            }
            // Shown at once; the next message from the server confirms or corrects it.
            self.current_status = Some(status);
        }
    }

    // ----- screens ------------------------------------------------------------------------

    fn login_screen(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        egui::CentralPanel::default().show(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(60.0);
                ui.heading("miphone");
                ui.label("Anmeldung am MiCollab-Server");
                ui.add_space(24.0);
                let width = 280.0;
                let enabled = !self.login.busy;
                let server = ui.add_enabled(enabled, egui::TextEdit::singleline(&mut self.login.server).hint_text("Server").desired_width(width));
                ui.add_space(6.0);
                let user = ui.add_enabled(enabled, egui::TextEdit::singleline(&mut self.login.user).hint_text("Benutzername").desired_width(width));
                if server.changed() || user.changed() {
                    // Another account: a remembered extension or an open question no longer applies.
                    self.login.number = None;
                    self.login.number_choices.clear();
                    self.pending_password = None;
                }
                ui.add_space(6.0);
                let password = ui.add_enabled(
                    enabled,
                    egui::TextEdit::singleline(&mut self.login.password).hint_text("Kennwort").password(true).desired_width(width),
                );
                ui.add_space(8.0);
                ui.add_enabled(enabled, egui::Checkbox::new(&mut self.login.stay_logged_in, "Angemeldet bleiben"))
                    .on_hover_text("Speichert das Kennwort verschlüsselt für dieses Windows-Konto und meldet beim nächsten Start automatisch an.");
                ui.add_space(10.0);
                let complete = !self.login.server.trim().is_empty() && !self.login.user.trim().is_empty() && !self.login.password.is_empty();
                let enter = password.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                let clicked = ui.add_enabled(enabled && complete, egui::Button::new("Anmelden").min_size(egui::vec2(width, 32.0))).clicked();
                if (clicked || enter) && enabled && complete {
                    self.start_login(&ctx);
                }
                if !self.login.number_choices.is_empty() {
                    ui.add_space(14.0);
                    ui.label("Dieses Konto hat mehrere Nebenstellen.\nWelche soll miphone verwenden?");
                    ui.add_space(6.0);
                    let mut chosen = None;
                    for choice in &self.login.number_choices {
                        let text = if choice.label.is_empty() { choice.number.clone() } else { format!("{}  –  {}", choice.number, choice.label) };
                        let mut button = ui.add(egui::Button::new(text).min_size(egui::vec2(width, 30.0)));
                        if choice.softphone {
                            button = button.on_hover_text("Vom Server als Softphone geführt");
                        }
                        if button.clicked() {
                            chosen = Some(choice.number.clone());
                        }
                    }
                    if let (Some(number), Some(password)) = (chosen, self.pending_password.clone()) {
                        self.login.number = Some(number);
                        self.login.password = password;
                        self.start_login(&ctx);
                    }
                }
                ui.add_space(12.0);
                if self.login.busy {
                    ui.horizontal(|ui| {
                        ui.add_space((ui.available_width() - 200.0).max(0.0) / 2.0);
                        ui.spinner();
                        ui.label("Bereitstellung wird abgerufen ...");
                    });
                }
                if let Some(error) = &self.login.error {
                    ui.colored_label(egui::Color32::from_rgb(210, 60, 55), error);
                }
                if let Some(notice) = &self.login.notice {
                    ui.label(egui::RichText::new(notice).weak());
                }

                // At the very bottom: delete everything miphone has saved.
                ui.add_space((ui.available_height() - 34.0).max(12.0));
                let red = egui::Color32::from_rgb(210, 60, 55);
                if self.login.confirm_reset {
                    ui.horizontal(|ui| {
                        ui.add_space((ui.available_width() - 330.0).max(0.0) / 2.0);
                        ui.label("Alle gespeicherten Daten löschen?");
                        if ui.add(egui::Button::new(egui::RichText::new("Löschen").color(red)).frame(false)).clicked() {
                            self.reset_everything(&ctx);
                        }
                        if ui.add(egui::Button::new("Abbrechen").frame(false)).clicked() {
                            self.login.confirm_reset = false;
                        }
                    });
                } else {
                    let reset = ui
                        .add_enabled(enabled, egui::Button::new(egui::RichText::new("Zurücksetzen").color(red)).frame(false))
                        .on_hover_text("Löscht Einstellungen, gespeichertes Kennwort, Verlauf und Verzeichnis von diesem Rechner.");
                    if reset.clicked() {
                        self.login.confirm_reset = true;
                    }
                }
            });
        });
    }

    fn main_screen(&mut self, ui: &mut egui::Ui) {
        egui::Panel::top("header").show(ui, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                // The extension as a badge: bordered, rounded and slightly tinted.
                let accent = ui.visuals().selection.bg_fill;
                egui::Frame::new()
                    .fill(accent.gamma_multiply(0.25))
                    .stroke(egui::Stroke::new(1.0, accent))
                    .corner_radius(8)
                    .inner_margin(egui::Margin::symmetric(10, 4))
                    .show(ui, |ui| {
                        let number = self.number.clone().unwrap_or_else(|| "–".into());
                        ui.label(egui::RichText::new(number).strong().size(16.0)).on_hover_text("Nebenstelle");
                    });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| self.avatar(ui));
            });
            ui.add_space(6.0);
        });

        egui::Panel::left("sidebar").resizable(false).exact_size(NAV_SIZE + 16.0).show(ui, |ui| {
            ui.add_space(8.0);
            for (page, icon, label) in [(Page::Phone, ICON_CALL, "Telefon"), (Page::Contacts, ICON_CONTACTS, "Kontakte"), (Page::History, ICON_HISTORY, "Verlauf")] {
                self.nav_entry(ui, page, icon, label);
            }
            ui.with_layout(egui::Layout::bottom_up(egui::Align::Min), |ui| {
                ui.add_space(8.0);
                if nav_button(ui, false, ICON_LOGOUT, "Abmelden").clicked() {
                    self.logout();
                }
                self.nav_entry(ui, Page::Settings, ICON_SETTINGS, "Einstellungen");
            });
        });

        egui::Panel::bottom("statusbar").show(ui, |ui| {
            ui.add_space(2.0);
            ui.label(egui::RichText::new(&self.status_line).color(ui.visuals().text_color()).small());
            ui.add_space(2.0);
        });

        egui::CentralPanel::default().show(ui, |ui| match self.page {
            Page::Phone => self.phone_page(ui),
            Page::Contacts => self.contacts_page(ui),
            Page::History => self.history_page(ui),
            Page::Settings => {
                egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| self.settings_page(ui));
            }
        });
        let ctx = ui.ctx().clone();
        self.save_offer_window(&ctx);
    }

    fn nav_entry(&mut self, ui: &mut egui::Ui, page: Page, icon: MaterialIcon, label: &str) {
        // Looking at the history takes note of the missed calls.
        if self.page == Page::History {
            self.missed_calls = 0;
        }
        let button = nav_button(ui, self.page == page, icon, label);
        if page == Page::History && self.missed_calls > 0 {
            // A red badge with the number of missed calls on the corner of the icon.
            let centre = button.rect.right_top() + egui::vec2(-9.0, 9.0);
            let count = if self.missed_calls > 9 { "9+".to_string() } else { self.missed_calls.to_string() };
            ui.painter().circle_filled(centre, 8.0, egui::Color32::from_rgb(210, 60, 55));
            ui.painter().text(centre, egui::Align2::CENTER_CENTER, count, egui::FontId::proportional(10.5), egui::Color32::WHITE);
        }
        if button.clicked() {
            self.page = page;
        }
    }

    /// One key of the dial pad: a tone during a call, otherwise a digit of the number.
    fn press_key(&mut self, digit: &str, in_call: bool) {
        if in_call {
            self.send(Command::Dtmf(digit.to_string()));
        } else {
            self.dial.push_str(digit);
        }
    }

    fn phone_page(&mut self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(8.0);
            if let Some(call) = self.state.call.clone() {
                self.call_card(ui, &call);
                ui.add_space(12.0);
            }
            let in_call = self.state.call.as_ref().is_some_and(|c| matches!(c.phase, CallPhase::Active | CallPhase::Held));

            let field = ui.add(
                egui::TextEdit::singleline(&mut self.dial)
                    .hint_text("Nummer")
                    .font(egui::FontId::proportional(22.0))
                    .align(egui::Align2::CENTER_CENTER)
                    .desired_width(220.0),
            );
            if field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                self.place_call();
            }
            ui.add_space(10.0);

            // Digits typed on the keyboard act like the keys below, wherever the focus is. With the
            // focus in the field the field takes the text itself; the keys still show the press.
            let now = ui.input(|i| i.time);
            let (typed, backspace, enter) = ui.input(|i| {
                let typed: Vec<char> = i
                    .events
                    .iter()
                    .filter_map(|e| if let egui::Event::Text(t) = e { Some(t.chars()) } else { None })
                    .flatten()
                    .filter(|c| c.is_ascii_digit() || matches!(c, '*' | '#'))
                    .collect();
                (typed, i.key_pressed(egui::Key::Backspace), i.key_pressed(egui::Key::Enter))
            });
            let elsewhere = ui.memory(|m| m.focused().is_some_and(|id| id != field.id)) || egui::Popup::is_any_open(ui.ctx());
            self.typed_keys.retain(|(_, until)| *until > now);
            if !elsewhere {
                for &c in &typed {
                    // Only the key typed last is lit, so fast typing leaves no trail of earlier keys.
                    self.typed_keys.clear();
                    self.typed_keys.push((c, now + KEY_FLASH));
                    if !field.has_focus() {
                        self.press_key(&c.to_string(), in_call);
                    }
                }
                if !field.has_focus() && !field.lost_focus() {
                    if backspace {
                        self.dial.pop();
                    }
                    if enter && self.state.call.is_none() {
                        self.place_call();
                    }
                }
            }
            if !self.typed_keys.is_empty() {
                // Repaint at once rather than after a timer: timers on Windows are too coarse for this.
                ui.ctx().request_repaint();
            }

            let key = egui::vec2(64.0, 46.0);
            for row in [["1", "2", "3"], ["4", "5", "6"], ["7", "8", "9"], ["*", "0", "#"]] {
                ui.horizontal(|ui| {
                    ui.add_space((ui.available_width() - 3.0 * key.x - 2.0 * ui.spacing().item_spacing.x).max(0.0) / 2.0);
                    for digit in row {
                        let mut button = egui::Button::new(egui::RichText::new(digit).size(20.0)).min_size(key);
                        if self.typed_keys.iter().any(|(c, _)| digit.starts_with(*c)) {
                            let pressed = ui.visuals().widgets.active;
                            button = button.fill(pressed.bg_fill).stroke(pressed.bg_stroke);
                        }
                        if ui.add(button).clicked() {
                            self.press_key(digit, in_call);
                        }
                    }
                });
            }
            ui.add_space(10.0);

            ui.horizontal(|ui| {
                let wide = egui::vec2(136.0, 40.0);
                ui.add_space((ui.available_width() - wide.x - key.x - ui.spacing().item_spacing.x).max(0.0) / 2.0);
                let can_call = self.state.registered && self.state.call.is_none() && !self.dial.trim().is_empty();
                let call = egui::Button::new(icon_text(ICON_CALL).size(22.0).color(egui::Color32::WHITE))
                    .fill(egui::Color32::from_rgb(60, 170, 80))
                    .min_size(wide);
                if ui.add_enabled(can_call, call).on_hover_text("Anrufen").clicked() {
                    self.place_call();
                }
                if ui.add(egui::Button::new(icon_text(ICON_BACKSPACE).size(20.0)).min_size(egui::vec2(key.x, 40.0))).on_hover_text("Letzte Ziffer löschen").clicked() {
                    self.dial.pop();
                }
            });
        });
        if self.tracked.as_ref().is_some_and(|t| t.connected.is_some()) {
            ui.ctx().request_repaint_after(Duration::from_millis(500)); // keeps the call timer running
        }
    }

    fn call_card(&mut self, ui: &mut egui::Ui, call: &CallSnapshot) {
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.set_width(300.0);
            ui.vertical_centered(|ui| {
                ui.label(egui::RichText::new(self.named(&call.peer)).size(18.0).strong());
                let elapsed = self.tracked.as_ref().and_then(|t| t.connected).map(|c| format_duration(c.elapsed()));
                let line = match call.phase {
                    CallPhase::Incoming => "Eingehender Anruf".to_string(),
                    CallPhase::Dialing => "Ruft an ...".to_string(),
                    CallPhase::Active => format!("Im Gespräch  {}", elapsed.unwrap_or_default()),
                    CallPhase::Held => format!("Gehalten  {}", elapsed.unwrap_or_default()),
                };
                ui.label(line);
                if let Some(codec) = &call.codec {
                    ui.label(egui::RichText::new(codec.to_string()).weak().small());
                }
                ui.add_space(6.0);
                let size = egui::vec2(92.0, 32.0);
                let red = egui::Color32::from_rgb(210, 60, 55);
                let green = egui::Color32::from_rgb(60, 170, 80);
                let coloured = |text: &str, fill| egui::Button::new(egui::RichText::new(text).color(egui::Color32::WHITE)).fill(fill).min_size(size);
                ui.horizontal(|ui| {
                    let count = match call.phase {
                        CallPhase::Dialing => 1.0,
                        CallPhase::Incoming => 2.0,
                        CallPhase::Active | CallPhase::Held => 3.0,
                    };
                    ui.add_space((ui.available_width() - count * size.x - (count - 1.0) * ui.spacing().item_spacing.x).max(0.0) / 2.0);
                    match call.phase {
                        CallPhase::Incoming => {
                            if ui.add(coloured("Annehmen", green)).clicked() {
                                self.send(Command::Answer);
                            }
                            if ui.add(coloured("Ablehnen", red)).clicked() {
                                self.send(Command::Hangup);
                            }
                        }
                        CallPhase::Dialing => {
                            if ui.add(coloured("Abbrechen", red)).clicked() {
                                self.send(Command::Hangup);
                            }
                        }
                        CallPhase::Active | CallPhase::Held => {
                            let held = call.phase == CallPhase::Held;
                            if ui.add(egui::Button::new(if held { "Fortsetzen" } else { "Halten" }).min_size(size)).clicked() {
                                self.send(if held { Command::Resume } else { Command::Hold });
                            }
                            if ui.add(egui::Button::new(if call.muted { "Ton an" } else { "Stumm" }).selected(call.muted).min_size(size)).clicked() {
                                self.send(Command::Mute(!call.muted));
                            }
                            if ui.add(coloured("Auflegen", red)).clicked() {
                                self.send(Command::Hangup);
                            }
                        }
                    }
                });
                if matches!(call.phase, CallPhase::Active | CallPhase::Held) {
                    ui.add_space(4.0);
                    let target = self.dial.trim().to_string();
                    let label = if target.is_empty() { "Vermitteln (Nummer unten eingeben)".to_string() } else { format!("Vermitteln an {target}") };
                    if ui.add_enabled(!target.is_empty(), egui::Button::new(label).min_size(egui::vec2(284.0, 28.0))).clicked() {
                        self.send(Command::Transfer(target));
                        self.dial.clear();
                    }
                }
            });
        });
    }

    fn contacts_page(&mut self, ui: &mut egui::Ui) {
        if self.contact_form.is_some() {
            self.contact_form_page(ui);
            return;
        }
        ui.horizontal(|ui| {
            let width = ui.available_width() - 78.0;
            ui.add(egui::TextEdit::singleline(&mut self.contact_search).hint_text("Name, Nummer, Abteilung ...").desired_width(width));
            let refresh = ui.add_enabled(!self.directory_loading, egui::Button::new(icon_text(ICON_REFRESH).size(18.0))).on_hover_text("Verzeichnis neu abgleichen");
            if refresh.clicked() {
                if let Some(tx) = &self.refresh_directory {
                    self.directory_loading = tx.try_send(()).is_ok();
                }
            }
            if ui.button(icon_text(ICON_ADD).size(18.0)).on_hover_text("Hinzufügen").clicked() {
                self.contact_form = Some(ContactForm::default());
            }
        });
        ui.horizontal_wrapped(|ui| {
            ui.selectable_value(&mut self.contact_tab, ContactTab::Company, "Firma");
            ui.selectable_value(&mut self.contact_tab, ContactTab::Own, "Eigene");
            // The groups of the server divide the corporate directory only.
            if self.contact_tab == ContactTab::Company && !self.groups.is_empty() {
                ui.separator();
                if ui.add(egui::Button::selectable(self.contact_group.is_none(), "Alle")).clicked() {
                    self.contact_group = None;
                }
                for (index, group) in self.groups.iter().enumerate() {
                    if ui.add(egui::Button::selectable(self.contact_group == Some(index), &group.name)).clicked() {
                        self.contact_group = Some(index);
                    }
                }
            }
        });
        ui.separator();

        let own = self.contact_tab == ContactTab::Own;
        let needle = self.contact_search.trim().to_lowercase();
        let list = if own { &self.own_contacts } else { &self.contacts };
        let members = self.contact_group.and_then(|i| self.groups.get(i)).map(|g| &g.members).filter(|_| !own);
        let matching: Vec<usize> = list
            .iter()
            .enumerate()
            .filter(|(_, c)| members.is_none_or(|m| m.contains(&c.id)) && contact_matches(c, &needle))
            .map(|(index, _)| index)
            .collect();
        if matching.is_empty() {
            ui.add_space(8.0);
            ui.label(match (list.is_empty(), own, self.directory_loading) {
                (true, true, _) => "Noch keine eigenen Kontakte. Mit dem Plus oben legst du einen an.",
                (true, false, true) => "Verzeichnis wird geladen ...",
                (true, false, false) => "Das Verzeichnis ist leer.",
                (false, ..) => "Keine Treffer.",
            });
            return;
        }
        // Only the presence of the contacts at the top of the list is asked for.
        let wanted = matching.iter().take(PRESENCE_WATCHED).filter_map(|i| list[*i].presence_id.clone()).collect();
        self.watch(wanted);

        let list = if own { &self.own_contacts } else { &self.contacts };
        let mut dial = None;
        let mut edit = None;
        egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
            for index in matching.iter().take(CONTACTS_SHOWN) {
                let contact = &list[*index];
                let presence = contact.presence_id.as_ref().and_then(|id| self.contact_presence.get(&id.to_lowercase()));
                ui.horizontal(|ui| {
                    let name = if self.last_name_first { contact.name_last_first() } else { contact.name() };
                    avatar_widget(ui, 30.0, &initials(&contact.name()), presence.map(|p| indicator_dot(p.indicator())), egui::Sense::hover());
                    ui.vertical(|ui| {
                        ui.label(egui::RichText::new(if name.is_empty() { "(ohne Namen)" } else { &name }).strong());
                        let details: Vec<&str> = [contact.department.as_str(), contact.company.as_str()].into_iter().filter(|d| !d.is_empty()).collect();
                        let status = presence.map(|p| p.status_name.as_str()).filter(|s| !s.is_empty());
                        let line = details.into_iter().chain(status).collect::<Vec<_>>().join(" · ");
                        if !line.is_empty() {
                            ui.label(egui::RichText::new(line).color(ui.visuals().text_color()).small());
                        }
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        // One call button; a click opens the choice of the contact's numbers.
                        let button = ui
                            .add_enabled(!contact.phones.is_empty(), egui::Button::new(icon_text(ICON_CALL).size(18.0)))
                            .on_hover_text("Anrufen")
                            .on_disabled_hover_text("Keine Nummer hinterlegt");
                        let mut menu = egui::Popup::menu(&button);
                        if self.demo_number_menu && contact.phones.len() > 1 {
                            menu = menu.open(true);
                        }
                        menu.show(|ui| {
                            ui.set_min_width(190.0);
                            for phone in &contact.phones {
                                // Number on the left, its kind (Work, Mobile, ...) on the right.
                                if ui.add(egui::Button::new(&phone.number).shortcut_text(&phone.label)).clicked() {
                                    dial = Some(phone.number.clone());
                                    ui.close();
                                }
                            }
                        });
                        if own && ui.button(icon_text(ICON_EDIT).size(18.0)).on_hover_text("Bearbeiten").clicked() {
                            edit = Some(ContactForm::edit(contact));
                        }
                    });
                });
                ui.separator();
            }
            if matching.len() > CONTACTS_SHOWN {
                ui.label(egui::RichText::new(format!("{} weitere Kontakte – Suche verfeinern.", matching.len() - CONTACTS_SHOWN)).weak());
            }
        });
        if edit.is_some() {
            self.contact_form = edit;
        }
        if let Some(number) = dial {
            self.dial = number;
            self.page = Page::Phone;
            self.place_call();
        }
    }

    /// The form for one of the user's own contacts, shown in place of the list.
    fn contact_form_page(&mut self, ui: &mut egui::Ui) {
        let Some(form) = &mut self.contact_form else { return };
        let (mut save, mut cancel, mut delete) = (false, false, false);
        ui.heading(if form.id.is_empty() { "Neuer Kontakt" } else { "Kontakt bearbeiten" });
        ui.add_space(8.0);
        egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
            let complete = form.complete();
            let [work, mobile, home] = &mut form.numbers;
            let fields = [
                ("Vorname", &mut form.first_name),
                ("Nachname", &mut form.last_name),
                ("Firma", &mut form.company),
                ("Abteilung", &mut form.department),
                ("E-Mail", &mut form.email),
                ("Telefon geschäftlich", work),
                ("Telefon mobil", mobile),
                ("Telefon privat", home),
            ];
            egui::Grid::new("contact_form").num_columns(2).spacing([12.0, 8.0]).show(ui, |ui| {
                for (label, value) in fields {
                    ui.label(label);
                    ui.add(egui::TextEdit::singleline(value).desired_width(240.0));
                    ui.end_row();
                }
            });
            ui.add_space(14.0);
            ui.horizontal(|ui| {
                save = ui.add_enabled(complete, egui::Button::new("Speichern")).on_disabled_hover_text("Vor- oder Nachname fehlt").clicked();
                cancel = ui.button("Abbrechen").clicked();
                if !form.id.is_empty() {
                    ui.add_space(16.0);
                    // Deleting takes a second click on the same button.
                    if ui.button(if form.confirm_delete { "Wirklich löschen?" } else { "Löschen" }).clicked() {
                        delete = form.confirm_delete;
                        form.confirm_delete = true;
                    }
                }
            });
        });
        if save {
            self.save_contact_form();
        } else if delete {
            self.delete_contact_form();
        } else if cancel {
            self.contact_form = None;
        }
    }

    fn history_page(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("Verlauf");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.add_enabled(!self.history.is_empty(), egui::Button::new("Verlauf löschen")).clicked() {
                    self.history.clear();
                    if let Some(Err(e)) = self.store.as_ref().map(Store::clear_calls) {
                        self.status_line = format!("Verlauf konnte nicht gelöscht werden: {e:#}");
                    }
                }
            });
        });
        ui.add_space(8.0);
        if self.history.is_empty() {
            ui.label("Noch keine Anrufe.");
            return;
        }
        let mut redial = None;
        egui::ScrollArea::vertical().show(ui, |ui| {
            for entry in self.history.iter().rev() {
                ui.horizontal(|ui| {
                    let (icon, kind, colour) = match (entry.incoming, entry.answered) {
                        (true, true) => (ICON_CALL_RECEIVED, "Eingehend", ui.visuals().text_color()),
                        (true, false) => (ICON_CALL_MISSED, "Verpasst", egui::Color32::from_rgb(210, 60, 55)),
                        (false, true) => (ICON_CALL_MADE, "Ausgehend", ui.visuals().text_color()),
                        (false, false) => (ICON_CALL_MADE, "Nicht erreicht", ui.visuals().weak_text_color()),
                    };
                    ui.label(icon_text(icon).size(20.0).color(colour)).on_hover_text(kind);
                    ui.vertical(|ui| {
                        ui.label(egui::RichText::new(self.named(&entry.peer)).strong());
                        let duration = entry.duration.map(|d| format!("  {}", format_duration(d))).unwrap_or_default();
                        ui.label(egui::RichText::new(format!("{kind}  {}{duration}", entry.started.format("%d.%m. %H:%M"))).color(colour).small());
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button(icon_text(ICON_CALL).size(18.0)).on_hover_text("Anrufen").clicked() {
                            redial = Some(number_of(&entry.peer));
                        }
                    });
                });
                ui.separator();
            }
        });
        if let Some(number) = redial {
            self.dial = number;
            self.page = Page::Phone;
            self.place_call();
        }
    }

    fn connecting_text(teleworker: bool) -> &'static str {
        if teleworker {
            "Verbinde als Teleworker mit dem Telefonserver ..."
        } else {
            "Verbinde direkt mit der Telefonanlage ..."
        }
    }

    /// Signs the softphone off and registers it with the other SIP account of the profile.
    fn set_teleworker(&mut self, teleworker: bool) {
        self.teleworker = teleworker;
        self.login.teleworker = Some(teleworker);
        self.persist();
        self.switch_account.store(true, Ordering::SeqCst);
        self.send(Command::Quit);
        self.status_line = "Wechsle das Telefonkonto ...".into();
    }

    fn settings_page(&mut self, ui: &mut egui::Ui) {
        ui.heading("Einstellungen");
        ui.add_space(10.0);
        if self.can_switch_account {
            ui.label(egui::RichText::new("Telefonie").strong());
            // As in the Mitel client, the account cannot be changed during a call.
            let idle = self.state.call.is_none();
            let mut teleworker = self.teleworker;
            if ui.add_enabled(idle, egui::Checkbox::new(&mut teleworker, "Teleworker verwenden")).changed() {
                self.set_teleworker(teleworker);
            }
            ui.label(
                egui::RichText::new(if idle {
                    "An: Anmeldung über das Gateway, von überall. Aus: direkt an der Telefonanlage, nur im Firmennetz."
                } else {
                    "Während eines Gesprächs nicht änderbar."
                })
                .weak()
                .small(),
            );
            ui.add_space(16.0);
        }
        ui.label(egui::RichText::new("Darstellung").strong());
        ui.horizontal(|ui| {
            let before = self.theme;
            ui.selectable_value(&mut self.theme, egui::ThemePreference::Light, "Hell");
            ui.selectable_value(&mut self.theme, egui::ThemePreference::Dark, "Dunkel");
            ui.selectable_value(&mut self.theme, egui::ThemePreference::System, "Automatisch");
            if self.theme != before {
                ui.ctx().set_theme(self.theme);
                self.persist();
            }
        });
        ui.add_space(16.0);

        ui.label(egui::RichText::new("Kontakte").strong());
        ui.horizontal(|ui| {
            let before = self.last_name_first;
            ui.selectable_value(&mut self.last_name_first, false, "Vorname Nachname");
            ui.selectable_value(&mut self.last_name_first, true, "Nachname, Vorname");
            if self.last_name_first != before {
                sort_contacts(&mut self.contacts, self.last_name_first);
                sort_contacts(&mut self.own_contacts, self.last_name_first);
                self.persist();
            }
        });
        ui.label(egui::RichText::new("Anzeige und Sortierung der Kontaktliste.").weak().small());
        ui.add_space(16.0);

        ui.label(egui::RichText::new("Audio").strong());
        let mut devices = self.audio.lock().unwrap().clone();
        let before = devices.clone();
        device_picker(ui, "Mikrofon", "audio_in", &self.inputs, &mut devices.input);
        device_picker(ui, "Lautsprecher", "audio_out", &self.outputs, &mut devices.output);
        if devices != before {
            *self.audio.lock().unwrap() = devices;
            self.persist();
        }
        ui.add_space(6.0);
        if ui.button("Geräteliste aktualisieren").clicked() {
            (self.inputs, self.outputs) = media::list_devices();
        }
        ui.label(egui::RichText::new("Die Auswahl gilt ab dem nächsten Gespräch.").weak().small());
        ui.add_space(16.0);
        self.ringtone_settings(ui);
    }

    /// Where the ringtone plays, which one and how loud.
    fn ringtone_settings(&mut self, ui: &mut egui::Ui) {
        ui.label(egui::RichText::new("Klingelton").strong());
        let (outputs_before, tone_before) = (self.ring_outputs.clone(), self.ring_tone.clone());

        ui.add_space(4.0);
        ui.label("Ausgabegeräte");
        let chosen = match self.ring_outputs.as_slice() {
            [] => "Standardgerät".to_string(),
            [one] => one.clone(),
            several => format!("{} Geräte", several.len()),
        };
        // Devices chosen earlier that are unplugged now stay in the list, to be unticked.
        let missing: Vec<String> = self.ring_outputs.iter().filter(|name| !self.outputs.contains(name)).cloned().collect();
        egui::ComboBox::from_id_salt("ring_out")
            .width(280.0)
            .selected_text(chosen)
            // Several devices can be ticked, so a click inside does not close the list.
            .close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside)
            .show_ui(ui, |ui| {
                if ui.selectable_label(self.ring_outputs.is_empty(), "Standardgerät").clicked() {
                    self.ring_outputs.clear();
                }
                for name in self.outputs.iter().chain(&missing) {
                    let mut ticked = self.ring_outputs.contains(name);
                    if ui.checkbox(&mut ticked, name).changed() {
                        self.ring_outputs.retain(|n| n != name);
                        if ticked {
                            self.ring_outputs.push(name.clone());
                        }
                    }
                }
            });

        ui.add_space(4.0);
        ui.label("Ton");
        let mut browse = false;
        egui::ComboBox::from_id_salt("ring_tone").width(280.0).selected_text(self.ring_tone.label()).show_ui(ui, |ui| {
            for (index, (name, _)) in ringtone::BUILTIN.iter().enumerate() {
                ui.selectable_value(&mut self.ring_tone, Tone::Builtin(index), *name);
            }
            // The user's own file, once one was picked.
            if let Tone::File(path) = &self.ring_tone {
                let _ = ui.selectable_label(true, self.ring_tone.label()).on_hover_text(path.to_string_lossy());
            }
            browse = ui.selectable_label(false, "Durchsuche...").clicked();
        });
        if browse {
            let dialog = rfd::FileDialog::new().set_title("Klingelton wählen").add_filter("Audiodateien", &ringtone::FILE_EXTENSIONS);
            if let Some(path) = dialog.pick_file() {
                self.ring_tone = Tone::File(path);
            }
        }

        ui.add_space(4.0);
        ui.label("Lautstärke");
        ui.horizontal(|ui| {
            let slider = ui.add(egui::Slider::new(&mut self.ring_volume, 0..=100).suffix(" %"));
            if slider.changed() {
                if let Some(ringer) = &self.ringer {
                    ringer.set_volume(self.ring_volume as f32 / 100.0);
                }
            }
            // Saved once the slider is let go, not for every step on the way.
            if slider.drag_stopped() || (slider.changed() && !slider.dragged()) {
                self.persist();
            }
            if ui.button(if self.ring_preview { "Stopp" } else { "Anhören" }).clicked() {
                self.ring_preview = !self.ring_preview;
            }
        });

        if self.ring_outputs != outputs_before || self.ring_tone != tone_before {
            self.persist();
            // What is playing starts again with the new choice.
            self.ringer = None;
        }
    }
}

/// Up to two initials of a name: first and last word, e.g. "Erika von Muster" -> "EM".
/// A login name like "e.muster@example.org" gives "EM" as well.
fn initials(name: &str) -> String {
    let name = name.split('@').next().unwrap_or(name);
    let words: Vec<&str> = name.split(|c: char| c.is_whitespace() || c == '.' || c == ',' || c == '_' || c == '-').filter(|w| !w.is_empty()).collect();
    let first = words.first().and_then(|w| w.chars().next());
    let last = if words.len() > 1 { words.last().and_then(|w| w.chars().next()) } else { None };
    let text: String = first.into_iter().chain(last).flat_map(char::to_uppercase).collect();
    if text.is_empty() {
        "?".to_string()
    } else {
        text
    }
}

/// Edge length of a sidebar button.
const NAV_SIZE: f32 = 40.0;

/// A square sidebar button showing only a Material icon; the name appears as tooltip.
fn nav_button(ui: &mut egui::Ui, selected: bool, icon: MaterialIcon, label: &str) -> egui::Response {
    let button = egui::Button::selectable(selected, icon_text(icon).size(22.0)).min_size(egui::vec2(NAV_SIZE, NAV_SIZE));
    ui.add(button).on_hover_text(label)
}
/// Drop-down for one audio device; `None` stands for the system default.
fn device_picker(ui: &mut egui::Ui, label: &str, id: &str, names: &[String], selected: &mut Option<String>) {
    ui.add_space(4.0);
    ui.label(label);
    egui::ComboBox::from_id_salt(id)
        .width(280.0)
        .selected_text(selected.clone().unwrap_or_else(|| "Standardgerät".into()))
        .show_ui(ui, |ui| {
            ui.selectable_value(selected, None, "Standardgerät");
            for name in names {
                ui.selectable_value(selected, Some(name.clone()), name);
            }
        });
}

fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs >= 3600 {
        format!("{}:{:02}:{:02}", secs / 3600, secs / 60 % 60, secs % 60)
    } else {
        format!("{:02}:{:02}", secs / 60, secs % 60)
    }
}

/// The number inside a display string like `Name (1234)`, or the string itself.
fn number_of(peer: &str) -> String {
    match (peer.rfind('('), peer.rfind(')')) {
        (Some(open), Some(close)) if open < close => peer[open + 1..close].to_string(),
        _ => peer.to_string(),
    }
}

impl eframe::App for App {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_backend(ctx);
        self.update_ringer();
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        if self.logged_in {
            self.main_screen(ui);
        } else {
            self.login_screen(ui);
        }
    }

    fn on_exit(&mut self) {
        // Closing the window signs off like "Abmelden"; give the server a moment to answer.
        if self.commands.is_some() {
            self.send(Command::Quit);
            std::thread::sleep(Duration::from_millis(1500));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_png_in_icon_file() {
        // Directory with a 32 px bitmap entry and a 256 px PNG entry.
        let mut ico = vec![0, 0, 1, 0, 2, 0];
        let png = b"\x89PNG....";
        let bmp = [40u8, 0, 0, 0];
        let entry = |width: u8, len: usize, offset: usize| {
            let mut e = vec![width, width, 0, 0, 1, 0, 32, 0];
            e.extend((len as u32).to_le_bytes());
            e.extend((offset as u32).to_le_bytes());
            e
        };
        ico.extend(entry(32, bmp.len(), 38));
        ico.extend(entry(0, png.len(), 42));
        ico.extend(bmp);
        ico.extend(png);
        assert_eq!(largest_png_in_ico(&ico), Some(&png[..]));
        assert_eq!(largest_png_in_ico(&ico[..40]), None, "truncated file");
        assert_eq!(largest_png_in_ico(b""), None);
        // The real icon contains a PNG image that decodes.
        assert!(window_icon().width >= 64);
    }

    #[test]
    fn history_entries_survive_storage() {
        let record = CallRecord { peer: "Erika Muster (1001)".into(), incoming: true, answered: true, started: 1_800_000_000, duration_secs: Some(75) };
        let entry = HistoryEntry::from_record(record.clone());
        assert_eq!(entry.duration, Some(Duration::from_secs(75)));
        assert_eq!(entry.to_record(), record);
        let missed = CallRecord { answered: false, duration_secs: None, ..record };
        assert_eq!(HistoryEntry::from_record(missed.clone()).to_record(), missed);
    }

    #[test]
    fn theme_names_roundtrip() {
        for theme in [egui::ThemePreference::Light, egui::ThemePreference::Dark, egui::ThemePreference::System] {
            assert_eq!(theme_from_name(theme_name(theme)), theme);
        }
        // Unknown or missing values (first start) mean "follow the system".
        assert_eq!(theme_from_name(""), egui::ThemePreference::System);
    }

    fn contact(first: &str, last: &str, number: &str) -> Contact {
        Contact {
            id: format!("{first}-{last}"),
            first_name: first.into(),
            last_name: last.into(),
            department: "Vertrieb".into(),
            phones: vec![micollab::Phone { number: number.into(), label: "Work".into() }],
            ..Contact::default()
        }
    }

    #[test]
    fn contact_form_roundtrips() {
        let form = ContactForm {
            first_name: " Petra ".into(),
            last_name: "Klein".into(),
            company: "Beispiel Handwerk".into(),
            email: "petra@example.org".into(),
            numbers: ["".into(), " 0170 1234567 ".into(), "030 5550100".into()],
            ..ContactForm::default()
        };
        assert!(form.complete() && !ContactForm { company: "Nur Firma".into(), ..ContactForm::default() }.complete());
        let mut contact = form.contact();
        assert_eq!((contact.name().as_str(), contact.id.as_str(), contact.presence_id.as_ref()), ("Petra Klein", "", None));
        let phones: Vec<(&str, &str)> = contact.phones.iter().map(|p| (p.label.as_str(), p.number.as_str())).collect();
        assert_eq!(phones, vec![("Mobil", "0170 1234567"), ("Privat", "030 5550100")], "empty numbers are left out");

        // Opened again, every value is in its field and saving changes nothing.
        contact.id = "own-7".into();
        let again = ContactForm::edit(&contact);
        assert_eq!((again.id.as_str(), again.first_name.as_str(), &again.numbers), ("own-7", "Petra", &["".to_string(), "0170 1234567".into(), "030 5550100".into()]));
        assert_eq!(again.contact(), contact);
        // A number to save goes to the field of its kind.
        assert_eq!(ContactForm::for_number(" +49 170 1234567 ").numbers, [String::new(), "+49 170 1234567".into(), String::new()]);
        assert_eq!(ContactForm::for_number("030 5550100").numbers, ["030 5550100".to_string(), String::new(), String::new()]);
        // Numbers of a kind the form does not know are kept in the free fields.
        let foreign = Contact { phones: vec![contact.phones[0].clone(), micollab::Phone { number: "1001".into(), label: "Work".into() }], ..contact };
        assert_eq!(ContactForm::edit(&foreign).numbers, ["1001".to_string(), "0170 1234567".into(), String::new()]);
    }

    #[test]
    fn reads_profile_from_command_line() {
        let args = |list: &[&str]| list.iter().map(|a| a.to_string()).collect::<Vec<_>>().into_iter();
        assert_eq!(profile_in(args(&["--profile:buero"])).as_deref(), Some("buero"));
        assert_eq!(profile_in(args(&["--demo=call", "--profile=zwei"])).as_deref(), Some("zwei"));
        assert_eq!(profile_in(args(&["--demo", "profile:x"])), None);
        // An empty name is passed on and refused when the store is opened.
        assert_eq!(profile_in(args(&["--profile:"])).as_deref(), Some(""));
    }

    #[test]
    fn searches_contacts() {
        let c = contact("Erika", "Muster", "+49 30 1234-56");
        for needle in ["", "eri", "muster", "erika mu", "vertrieb", "3012", "+4930", "34-56"] {
            assert!(contact_matches(&c, needle), "{needle:?} should match");
        }
        for needle in ["max", "technik", "999"] {
            assert!(!contact_matches(&c, needle), "{needle:?} should not match");
        }
        assert!(contact_matches(&c, "muster, er"));
        assert_eq!(dial_key("+49 (30) 12-34"), "+49301234");
    }

    #[test]
    fn compares_numbers_written_differently() {
        // One national number in every form a telephone system or a contact may use.
        for written in ["+49 170 1234567", "0049 170 1234567", "00170 1234567", "0170 1234567", "+49 (0) 170 1234567", "0170/123-4567"] {
            assert_eq!(number_key(written), "01701234567", "{written}");
        }
        // Extensions, short numbers and numbers of other countries stay as they are.
        for (written, key) in [("1001", "1001"), ("8*1002", "81002"), ("0", "0"), ("00", "00"), ("110", "110"), ("+33 1 23 45", "+3312345"), ("", "")] {
            assert_eq!(number_key(written), key, "{written}");
        }
        // A contact saved with +49 is found by a search in the national form and the other way round.
        let c = contact("Erika", "Muster", "+49 170 1234567");
        assert!(contact_matches(&c, "0170 123") && contact_matches(&c, "+49170") && contact_matches(&c, "4567"));
        assert!(contact_matches(&contact("Max", "Beispiel", "0170 1234567"), "+49 170 12"));
        assert!(!contact_matches(&c, "0171"));
    }

    #[test]
    fn sorts_contacts_by_the_part_shown_first() {
        let mut list = vec![contact("Zoe", "Adler", "1"), contact("anna", "Zimmer", "2"), contact("Anna", "Berg", "3")];
        let order = |l: &[Contact]| l.iter().map(|c| c.phones[0].number.clone()).collect::<String>();
        sort_contacts(&mut list, false);
        assert_eq!(order(&list), "321");
        sort_contacts(&mut list, true);
        assert_eq!(order(&list), "132");
    }

    #[test]
    fn builds_initials() {
        assert_eq!(initials("Erika Muster"), "EM");
        assert_eq!(initials("Erika von Muster"), "EM");
        assert_eq!(initials("e.muster@example.org"), "EM");
        assert_eq!(initials("Muster, Erika"), "ME");
        assert_eq!(initials("erika"), "E");
        assert_eq!(initials("Änne Österle"), "ÄÖ");
        assert_eq!(initials("  "), "?");
    }

    #[test]
    fn formats_durations() {
        assert_eq!(format_duration(Duration::from_secs(5)), "00:05");
        assert_eq!(format_duration(Duration::from_secs(725)), "12:05");
        assert_eq!(format_duration(Duration::from_secs(3725)), "1:02:05");
    }

    #[test]
    fn extracts_number_for_redial() {
        assert_eq!(number_of("S.Bell (860014)"), "860014");
        assert_eq!(number_of("860027"), "860027");
        assert_eq!(number_of("Odd ) ( name"), "Odd ) ( name");
    }
}
