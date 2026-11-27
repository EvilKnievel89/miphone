//! Call control of USB headsets: the headset shows that a call rings or is in progress,
//! and its buttons answer, end and mute the call.
//!
//! This uses what the USB standard defines for telephony devices (HID usage pages
//! "Telephony" and "LED"), which headsets for office use of all makers implement. No
//! software of the maker is needed. A headset paired with Windows by Bluetooth directly,
//! without its USB adapter, is not reachable this way.
//!
//! The headset is only opened while a call rings or is in progress, and left alone
//! otherwise, to stay out of the way of other telephone programs using the same headset.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// What the headset is told about our call.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CallLights {
    /// A call rings here.
    pub ringing: bool,
    /// A call is being set up or in progress.
    pub off_hook: bool,
    pub muted: bool,
}

impl CallLights {
    fn idle(self) -> bool {
        !self.ringing && !self.off_hook
    }
}

/// What the user asked for with a button of the headset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Button {
    Answer,
    HangUp,
    ToggleMute,
}

/// After a button answered the call, the headset is shown the call as answered at once and
/// for at most this long, until the program has caught up. A headset that still sees the
/// call ringing may take its button back.
const ANSWER_GRACE: Duration = Duration::from_secs(2);

/// Makes button presses out of what one headset reports.
#[derive(Debug, Default)]
struct Buttons {
    /// The hook switch as the headset last reported it.
    hook: bool,
    mute_down: bool,
    /// The headset has no light for a call in progress, so it cannot be told about the
    /// call and its hook switch just changes with every press of the button.
    blind: bool,
}

impl Buttons {
    /// One report of the headset. `hook` and `mute` are the controls the report carries:
    /// their value, and whether the value is a state (absolute) or says "pressed" each time.
    fn on_report(&mut self, hook: Option<(bool, bool)>, mute: Option<(bool, bool)>, lights: CallLights) -> Vec<Button> {
        let mut pressed = Vec::new();
        match hook {
            Some((on, true)) if self.blind => {
                if on != self.hook {
                    if lights.ringing {
                        pressed.push(Button::Answer);
                    } else if lights.off_hook {
                        pressed.push(Button::HangUp);
                    }
                }
                self.hook = on;
            }
            Some((on, true)) => {
                // A headset also reports the hook when we changed its state, so only a change
                // that goes against what we showed it is the user's doing.
                if on && !self.hook && lights.ringing {
                    pressed.push(Button::Answer);
                } else if !on && self.hook && lights.off_hook && !lights.ringing {
                    pressed.push(Button::HangUp);
                }
                self.hook = on;
            }
            Some((true, false)) => {
                if lights.ringing {
                    pressed.push(Button::Answer);
                } else if lights.off_hook {
                    pressed.push(Button::HangUp);
                }
            }
            _ => {}
        }
        match mute {
            Some((on, true)) => {
                if on && !self.mute_down && lights.off_hook {
                    pressed.push(Button::ToggleMute);
                }
                self.mute_down = on;
            }
            Some((true, false)) if lights.off_hook => pressed.push(Button::ToggleMute),
            _ => {}
        }
        pressed
    }
}

struct Shared {
    stop: AtomicBool,
    lights: Mutex<CallLights>,
}

/// The connection to the headsets. It ends when this value is dropped.
pub struct Headset {
    shared: Arc<Shared>,
}

impl Headset {
    /// Starts looking after the headsets. `on_button` is called, on another thread, when a
    /// button of a headset was pressed.
    pub fn start(on_button: impl Fn(Button) + Send + 'static) -> Headset {
        let shared = Arc::new(Shared { stop: AtomicBool::new(false), lights: Mutex::new(CallLights::default()) });
        let thread_shared = shared.clone();
        std::thread::spawn(move || hid::run(thread_shared, on_button));
        Headset { shared }
    }

    /// Tells the headsets about the state of our call.
    pub fn set_lights(&self, lights: CallLights) {
        *self.shared.lights.lock().unwrap() = lights;
    }
}

impl Drop for Headset {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::Relaxed);
    }
}

/// The headsets that are plugged in and what each of them can do, to show the user.
pub fn describe() -> Vec<String> {
    hid::describe()
}

/// The numbers the USB standard gives to the controls we use.
mod usage {
    pub const PAGE_TELEPHONY: u16 = 0x0B;
    pub const PAGE_LED: u16 = 0x08;
    pub const HOOK_SWITCH: u16 = 0x20;
    pub const PHONE_MUTE: u16 = 0x2F;
    pub const RINGER: u16 = 0x9E;
    pub const LED_MUTE: u16 = 0x09;
    pub const LED_OFF_HOOK: u16 = 0x17;
    pub const LED_RING: u16 = 0x18;
}

/// Talking to the devices through the HID functions of Windows.
mod hid {
    use super::*;
    use std::ffi::c_void;
    use std::ptr;
    use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
        DIGCF_DEVICEINTERFACE, DIGCF_PRESENT, SP_DEVICE_INTERFACE_DATA, SP_DEVICE_INTERFACE_DETAIL_DATA_W, SetupDiDestroyDeviceInfoList,
        SetupDiEnumDeviceInterfaces, SetupDiGetClassDevsW, SetupDiGetDeviceInterfaceDetailW,
    };
    use windows_sys::Win32::Devices::HumanInterfaceDevice::{
        HIDP_BUTTON_CAPS, HIDP_CAPS, HIDP_STATUS_SUCCESS, HidD_FreePreparsedData, HidD_GetHidGuid, HidD_GetInputReport, HidD_GetPreparsedData, HidD_GetProductString,
        HidD_SetOutputReport, HidP_GetButtonCaps, HidP_GetCaps, HidP_GetUsages, HidP_InitializeReportForID, HidP_Input, HidP_Output, HidP_SetUsages,
    };
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_IO_INCOMPLETE, ERROR_IO_PENDING, GENERIC_READ, GENERIC_WRITE, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_FLAG_OVERLAPPED, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, ReadFile, WriteFile};
    use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, GetOverlappedResultEx, OVERLAPPED};
    use windows_sys::Win32::System::Threading::CreateEventW;

    /// A button or a light of the device: where it is found in the reports.
    #[derive(Debug, Clone, Copy)]
    struct Control {
        page: u16,
        usage: u16,
        report_id: u8,
        absolute: bool,
    }

    /// What a device has of the controls we use.
    #[derive(Debug, Default)]
    struct Controls {
        hook: Option<Control>,
        mute: Option<Control>,
        lights: Vec<Control>,
    }

    impl Controls {
        fn light(&self, page: u16, usage: u16) -> bool {
            self.lights.iter().any(|c| (c.page, c.usage) == (page, usage))
        }

        /// A light for mute alone does not make a headset: keyboards have one, too.
        fn useful(&self) -> bool {
            self.hook.is_some() || self.lights.iter().any(|c| (c.page, c.usage) != (usage::PAGE_LED, usage::LED_MUTE))
        }

        fn summary(&self) -> String {
            let mut buttons = Vec::new();
            if self.hook.is_some() {
                buttons.push("Annehmen/Auflegen");
            }
            if self.mute.is_some() {
                buttons.push("Stumm");
            }
            let mut lights = Vec::new();
            if self.light(usage::PAGE_LED, usage::LED_RING) || self.light(usage::PAGE_TELEPHONY, usage::RINGER) {
                lights.push("Klingeln");
            }
            if self.light(usage::PAGE_LED, usage::LED_OFF_HOOK) {
                lights.push("Gespräch");
            }
            if self.light(usage::PAGE_LED, usage::LED_MUTE) {
                lights.push("Stumm");
            }
            let list = |items: Vec<&str>| if items.is_empty() { "keine".to_string() } else { items.join(", ") };
            format!("Tasten: {}; Anzeigen: {}", list(buttons), list(lights))
        }
    }

    /// An open handle of a device with what Windows knows about its reports.
    struct Opened {
        handle: HANDLE,
        preparsed: isize,
        caps: HIDP_CAPS,
    }

    impl Opened {
        /// Opens the device; `access` 0 is enough to ask what it is.
        fn open(path: &[u16], access: u32) -> Option<Opened> {
            // SAFETY: `path` is a terminated string; the handle and the data Windows hands
            // out are freed in `drop`.
            unsafe {
                let handle = CreateFileW(path.as_ptr(), access, FILE_SHARE_READ | FILE_SHARE_WRITE, ptr::null(), OPEN_EXISTING, FILE_FLAG_OVERLAPPED, ptr::null_mut());
                if handle == INVALID_HANDLE_VALUE {
                    return None;
                }
                let mut opened = Opened { handle, preparsed: 0, caps: HIDP_CAPS::default() };
                if !HidD_GetPreparsedData(handle, &mut opened.preparsed) || HidP_GetCaps(opened.preparsed, &mut opened.caps) != HIDP_STATUS_SUCCESS {
                    return None; // `opened` is dropped and closes the handle
                }
                Some(opened)
            }
        }

        fn buttons(&self, report_type: i32, count: u16) -> Vec<Control> {
            let mut caps = vec![HIDP_BUTTON_CAPS::default(); count as usize];
            let mut len = count;
            // SAFETY: `caps` has room for `len` entries.
            if count == 0 || unsafe { HidP_GetButtonCaps(report_type, caps.as_mut_ptr(), &mut len, self.preparsed) } != HIDP_STATUS_SUCCESS {
                return Vec::new();
            }
            let mut controls = Vec::new();
            for cap in &caps[..len as usize] {
                // SAFETY: `IsRange` says which form of the union is filled in.
                let (min, max) = unsafe { if cap.IsRange { (cap.Anonymous.Range.UsageMin, cap.Anonymous.Range.UsageMax) } else { (cap.Anonymous.NotRange.Usage, cap.Anonymous.NotRange.Usage) } };
                for usage in min..=max.min(min.saturating_add(255)) {
                    controls.push(Control { page: cap.UsagePage, usage, report_id: cap.ReportID, absolute: cap.IsAbsolute });
                }
            }
            controls
        }

        fn controls(&self) -> Controls {
            let find = |all: &[Control], page: u16, usage: u16| all.iter().copied().find(|c| (c.page, c.usage) == (page, usage));
            let inputs = self.buttons(HidP_Input, self.caps.NumberInputButtonCaps);
            let outputs = self.buttons(HidP_Output, self.caps.NumberOutputButtonCaps);
            let wanted = [(usage::PAGE_LED, usage::LED_RING), (usage::PAGE_LED, usage::LED_OFF_HOOK), (usage::PAGE_LED, usage::LED_MUTE), (usage::PAGE_TELEPHONY, usage::RINGER)];
            Controls {
                hook: find(&inputs, usage::PAGE_TELEPHONY, usage::HOOK_SWITCH),
                mute: find(&inputs, usage::PAGE_TELEPHONY, usage::PHONE_MUTE),
                lights: wanted.iter().filter_map(|&(page, usage)| find(&outputs, page, usage)).collect(),
            }
        }

        fn name(&self) -> String {
            let mut buffer = [0u16; 127];
            // SAFETY: the length given is that of `buffer` in bytes.
            let ok = unsafe { HidD_GetProductString(self.handle, buffer.as_mut_ptr().cast(), (buffer.len() * 2) as u32) };
            let len = buffer.iter().position(|c| *c == 0).unwrap_or(buffer.len());
            let name = String::from_utf16_lossy(&buffer[..len]).trim().to_string();
            if ok && !name.is_empty() { name } else { "Headset".to_string() }
        }
    }

    impl Drop for Opened {
        fn drop(&mut self) {
            // SAFETY: both were handed out by Windows in `open` and are not used after this.
            unsafe {
                if self.preparsed != 0 {
                    HidD_FreePreparsedData(self.preparsed);
                }
                CloseHandle(self.handle);
            }
        }
    }

    /// The paths of all HID devices that are plugged in.
    fn device_paths() -> Vec<Vec<u16>> {
        let mut paths = Vec::new();
        // SAFETY: the structures are sized as Windows asks; the buffer for the path is as
        // large as Windows said it must be and aligned for the structure at its start.
        unsafe {
            let mut guid = std::mem::zeroed();
            HidD_GetHidGuid(&mut guid);
            let set = SetupDiGetClassDevsW(&guid, ptr::null(), ptr::null_mut(), DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
            if set == INVALID_HANDLE_VALUE as isize {
                return paths;
            }
            for index in 0.. {
                let mut interface: SP_DEVICE_INTERFACE_DATA = std::mem::zeroed();
                interface.cbSize = size_of::<SP_DEVICE_INTERFACE_DATA>() as u32;
                if SetupDiEnumDeviceInterfaces(set, ptr::null(), &guid, index, &mut interface) == 0 {
                    break;
                }
                let mut needed = 0u32;
                SetupDiGetDeviceInterfaceDetailW(set, &interface, ptr::null_mut(), 0, &mut needed, ptr::null_mut());
                if needed < 8 {
                    continue;
                }
                let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
                let detail = buffer.as_mut_ptr().cast::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>();
                (*detail).cbSize = size_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>() as u32;
                if SetupDiGetDeviceInterfaceDetailW(set, &interface, detail, needed, ptr::null_mut(), ptr::null_mut()) == 0 {
                    continue;
                }
                let start = (&raw const (*detail).DevicePath).cast::<u16>();
                let max = (needed as usize - 4) / 2;
                let len = (0..max).take_while(|&i| *start.add(i) != 0).count();
                let mut path = std::slice::from_raw_parts(start, len).to_vec();
                path.push(0);
                paths.push(path);
            }
            SetupDiDestroyDeviceInfoList(set);
        }
        paths
    }

    /// Every HID device with its name and the kind Windows lists it as (usage page, usage).
    #[cfg(test)]
    pub fn survey() -> Vec<String> {
        let controls = |all: Vec<Control>| all.iter().map(|c| format!("{:02x}/{:02x}", c.page, c.usage)).collect::<Vec<_>>().join(" ");
        device_paths()
            .iter()
            .filter_map(|path| Opened::open(path, 0))
            .map(|o| {
                let (inputs, outputs) = (o.buttons(HidP_Input, o.caps.NumberInputButtonCaps), o.buttons(HidP_Output, o.caps.NumberOutputButtonCaps));
                format!("{}: kind {:02x}/{:02x}, buttons in [{}], out [{}]", o.name(), o.caps.UsagePage, o.caps.Usage, controls(inputs), controls(outputs))
            })
            .collect()
    }

    pub fn describe() -> Vec<String> {
        let mut found = Vec::new();
        for path in device_paths() {
            let Some(opened) = Opened::open(&path, 0) else { continue };
            let controls = opened.controls();
            if controls.useful() {
                found.push(format!("{} ({})", opened.name(), controls.summary()));
            }
        }
        found.sort();
        found.dedup();
        found
    }

    /// The telephony buttons that are on in a report of the device.
    fn usages_on(opened: &Opened, report: &mut [u8]) -> Vec<u16> {
        let mut usages = [0u16; 32];
        let mut count = usages.len() as u32;
        // SAFETY: `count` is the room in `usages`, and the length given is that of `report`.
        let status = unsafe { HidP_GetUsages(HidP_Input, usage::PAGE_TELEPHONY, 0, usages.as_mut_ptr(), &mut count, opened.preparsed, report.as_mut_ptr(), report.len() as u32) };
        if status == HIDP_STATUS_SUCCESS { usages[..count as usize].to_vec() } else { Vec::new() }
    }

    /// A read that Windows completes when the device sends a report.
    struct Read {
        overlapped: OVERLAPPED,
        buffer: Vec<u8>,
        pending: bool,
    }

    /// A headset in use during a call.
    struct Device {
        path: Vec<u16>,
        opened: Opened,
        controls: Controls,
        /// Boxed, because Windows keeps pointers into it while a read is pending.
        read: Box<Read>,
        buttons: Buttons,
        /// What the device was last told.
        shown: Option<CallLights>,
    }

    impl Device {
        fn open(path: &[u16]) -> Option<Device> {
            let opened = Opened::open(path, GENERIC_READ | GENERIC_WRITE)?;
            let controls = opened.controls();
            if !controls.useful() {
                return None;
            }
            // SAFETY: an event without a name, closed in `drop`.
            let event = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
            if event.is_null() {
                return None;
            }
            // SAFETY: all zeroes is a valid start for this structure.
            let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
            overlapped.hEvent = event;
            let read = Box::new(Read { overlapped, buffer: vec![0; opened.caps.InputReportByteLength.max(1) as usize], pending: false });
            let mut buttons = Buttons { blind: !controls.light(usage::PAGE_LED, usage::LED_OFF_HOOK), ..Buttons::default() };
            // Where the hook switch stands now, if the device tells; otherwise it shows with
            // its first report.
            if let Some(hook) = controls.hook {
                let mut report = vec![0u8; read.buffer.len()];
                report[0] = hook.report_id;
                // SAFETY: the length given is that of `report`.
                if unsafe { HidD_GetInputReport(opened.handle, report.as_mut_ptr().cast(), report.len() as u32) } {
                    buttons.hook = usages_on(&opened, &mut report).contains(&usage::HOOK_SWITCH);
                }
            }
            Some(Device { path: path.to_vec(), opened, controls, read, buttons, shown: None })
        }

        /// The reports that arrived since the last call, as button presses. `Err` means that
        /// the device is gone.
        fn poll(&mut self, lights: CallLights) -> Result<Vec<Button>, ()> {
            let mut pressed = Vec::new();
            // A device that sends without pause must not keep the others waiting.
            for _ in 0..32 {
                let read = &mut *self.read;
                // SAFETY: buffer and structure live in a box that is kept until the read
                // has ended (see `drop`).
                unsafe {
                    if !read.pending {
                        let started = ReadFile(self.opened.handle, read.buffer.as_mut_ptr(), read.buffer.len() as u32, ptr::null_mut(), &mut read.overlapped);
                        if started == 0 && GetLastError() != ERROR_IO_PENDING {
                            return Err(());
                        }
                        read.pending = true;
                    }
                    let mut len = 0u32;
                    if GetOverlappedResult(self.opened.handle, &read.overlapped, &mut len, 0) == 0 {
                        return if GetLastError() == ERROR_IO_INCOMPLETE { Ok(pressed) } else { Err(()) };
                    }
                    read.pending = false;
                    let len = (len as usize).min(read.buffer.len());
                    if len == 0 {
                        continue;
                    }
                    let (id, on) = (read.buffer[0], usages_on(&self.opened, &mut read.buffer[..len]));
                    let value = |control: Option<Control>| control.filter(|c| c.report_id == id).map(|c| (on.contains(&c.usage), c.absolute));
                    pressed.extend(self.buttons.on_report(value(self.controls.hook), value(self.controls.mute), lights));
                }
            }
            Ok(pressed)
        }

        /// Shows the state of the call on the device.
        fn show(&mut self, lights: CallLights) {
            if self.shown == Some(lights) {
                return;
            }
            self.shown = Some(lights);
            let on = |c: &Control| match (c.page, c.usage) {
                (usage::PAGE_LED, usage::LED_RING) | (usage::PAGE_TELEPHONY, usage::RINGER) => lights.ringing,
                (usage::PAGE_LED, usage::LED_OFF_HOOK) => lights.off_hook,
                (usage::PAGE_LED, usage::LED_MUTE) => lights.muted && lights.off_hook,
                _ => false,
            };
            let mut ids: Vec<u8> = self.controls.lights.iter().map(|c| c.report_id).collect();
            ids.sort();
            ids.dedup();
            let len = self.opened.caps.OutputReportByteLength as usize;
            for id in ids {
                let mut report = vec![0u8; len.max(1)];
                // SAFETY: the report is as long as the device's output reports; one usage
                // is set at a time, from a list of one.
                unsafe {
                    if HidP_InitializeReportForID(HidP_Output, id, self.opened.preparsed, report.as_mut_ptr(), len as u32) != HIDP_STATUS_SUCCESS {
                        continue;
                    }
                    for control in self.controls.lights.iter().filter(|c| c.report_id == id && on(c)) {
                        let (mut usage, mut count) = (control.usage, 1u32);
                        HidP_SetUsages(HidP_Output, control.page, 0, &mut usage, &mut count, self.opened.preparsed, report.as_ptr(), len as u32);
                    }
                }
                self.write(&report);
            }
        }

        fn write(&self, report: &[u8]) {
            // SAFETY: the structure and the event live until the write has ended: it is
            // waited for, and cancelled if the device does not take it.
            unsafe {
                let event = CreateEventW(ptr::null(), 1, 0, ptr::null());
                if event.is_null() {
                    return;
                }
                let mut overlapped: OVERLAPPED = std::mem::zeroed();
                overlapped.hEvent = event;
                let mut written = 0u32;
                let mut ok = WriteFile(self.opened.handle, report.as_ptr(), report.len() as u32, ptr::null_mut(), &mut overlapped) != 0;
                if !ok && GetLastError() == ERROR_IO_PENDING {
                    ok = GetOverlappedResultEx(self.opened.handle, &overlapped, &mut written, 300, 0) != 0;
                    if !ok {
                        CancelIoEx(self.opened.handle, &overlapped);
                        GetOverlappedResult(self.opened.handle, &overlapped, &mut written, 1);
                    }
                }
                CloseHandle(event);
                if !ok {
                    // Some devices take their reports only this way.
                    HidD_SetOutputReport(self.opened.handle, report.as_ptr().cast::<c_void>(), report.len() as u32);
                }
            }
        }
    }

    impl Drop for Device {
        fn drop(&mut self) {
            // SAFETY: the pending read is cancelled and waited for before its buffer goes.
            unsafe {
                if self.read.pending {
                    let mut len = 0u32;
                    CancelIoEx(self.opened.handle, &self.read.overlapped);
                    GetOverlappedResult(self.opened.handle, &self.read.overlapped, &mut len, 1);
                }
                CloseHandle(self.read.overlapped.hEvent);
            }
        }
    }

    pub fn run(shared: Arc<Shared>, on_button: impl Fn(Button)) {
        let mut devices: Vec<Device> = Vec::new();
        let mut scanned: Option<Instant> = None;
        // Set when a button answered the call, until the program shows the call as answered.
        let mut answered: Option<Instant> = None;
        loop {
            let stop = shared.stop.load(Ordering::Relaxed);
            let mut lights = *shared.lights.lock().unwrap();
            if stop || lights.idle() {
                // The call is over: say so to the headsets and let go of them.
                for device in &mut devices {
                    device.show(CallLights::default());
                }
                devices.clear();
                (scanned, answered) = (None, None);
                if stop {
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
            match answered {
                Some(at) if lights.ringing && at.elapsed() < ANSWER_GRACE => lights = CallLights { ringing: false, off_hook: true, muted: lights.muted },
                _ => answered = None,
            }

            // Headsets are also found when plugged in during the call.
            if scanned.is_none_or(|at| at.elapsed() > Duration::from_secs(2)) {
                scanned = Some(Instant::now());
                for path in device_paths() {
                    if !devices.iter().any(|d| d.path == path) {
                        devices.extend(Device::open(&path));
                    }
                }
            }

            let mut gone = Vec::new();
            for (index, device) in devices.iter_mut().enumerate() {
                device.show(lights);
                match device.poll(lights) {
                    Ok(pressed) => {
                        for button in pressed {
                            if button == Button::Answer {
                                answered = Some(Instant::now());
                                lights = CallLights { ringing: false, off_hook: true, muted: lights.muted };
                                device.show(lights);
                            }
                            on_button(button);
                        }
                    }
                    Err(()) => gone.push(index),
                }
            }
            for index in gone.into_iter().rev() {
                devices.remove(index);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RINGING: CallLights = CallLights { ringing: true, off_hook: false, muted: false };
    const TALKING: CallLights = CallLights { ringing: false, off_hook: true, muted: false };
    const IDLE: CallLights = CallLights { ringing: false, off_hook: false, muted: false };

    #[test]
    fn hook_switch_answers_and_hangs_up() {
        let mut buttons = Buttons::default();
        let hook = |on: bool| Some((on, true));
        // Nothing rings: the button does nothing.
        assert_eq!(buttons.on_report(hook(true), None, IDLE), []);
        assert_eq!(buttons.on_report(hook(false), None, IDLE), []);
        // It rings and the button is pressed; the headset says so again once we confirmed.
        assert_eq!(buttons.on_report(hook(true), None, RINGING), [Button::Answer]);
        assert_eq!(buttons.on_report(hook(true), None, TALKING), []);
        // The button again ends the call; the report after we hung up means nothing.
        assert_eq!(buttons.on_report(hook(false), None, TALKING), [Button::HangUp]);
        assert_eq!(buttons.on_report(hook(false), None, IDLE), []);
    }

    #[test]
    fn reports_about_our_own_changes_are_no_presses() {
        let mut buttons = Buttons::default();
        // Answered in the window: the headset follows and reports the hook as lifted.
        assert_eq!(buttons.on_report(Some((true, true)), None, TALKING), []);
        // A report for another button, hook unchanged, does not end the call.
        assert_eq!(buttons.on_report(Some((true, true)), Some((true, false)), TALKING), [Button::ToggleMute]);
        // A headset that never reported the hook as lifted cannot hang up by a report of
        // "not lifted": that is what it says all the time.
        let mut buttons = Buttons::default();
        assert_eq!(buttons.on_report(Some((false, true)), None, TALKING), []);
        // While it still rings, putting the hook down is not a hang-up either.
        assert_eq!(buttons.on_report(Some((false, true)), None, RINGING), []);
    }

    #[test]
    fn buttons_that_only_say_pressed() {
        let mut buttons = Buttons::default();
        let pressed = Some((true, false));
        assert_eq!(buttons.on_report(pressed, None, RINGING), [Button::Answer]);
        assert_eq!(buttons.on_report(pressed, None, TALKING), [Button::HangUp]);
        assert_eq!(buttons.on_report(pressed, None, IDLE), []);
        assert_eq!(buttons.on_report(Some((false, false)), None, TALKING), []);
    }

    #[test]
    fn headset_without_lights_changes_its_hook_with_every_press() {
        // It was left "lifted" by an earlier press; the next press puts it down.
        let mut buttons = Buttons { blind: true, hook: true, ..Buttons::default() };
        assert_eq!(buttons.on_report(Some((true, true)), None, RINGING), [], "a report for another button");
        assert_eq!(buttons.on_report(Some((false, true)), None, RINGING), [Button::Answer]);
        assert_eq!(buttons.on_report(Some((false, true)), None, TALKING), []);
        assert_eq!(buttons.on_report(Some((true, true)), None, TALKING), [Button::HangUp]);
        assert_eq!(buttons.on_report(Some((false, true)), None, IDLE), []);
    }

    #[test]
    fn mute_button_toggles_once_per_press() {
        let mut buttons = Buttons::default();
        // As a state: only the press counts, not holding or letting go.
        assert_eq!(buttons.on_report(None, Some((true, true)), TALKING), [Button::ToggleMute]);
        assert_eq!(buttons.on_report(None, Some((true, true)), TALKING), []);
        assert_eq!(buttons.on_report(None, Some((false, true)), TALKING), []);
        assert_eq!(buttons.on_report(None, Some((true, true)), TALKING), [Button::ToggleMute]);
        // Without a call there is nothing to mute.
        assert_eq!(buttons.on_report(None, Some((true, false)), IDLE), []);
        assert_eq!(buttons.on_report(None, Some((true, false)), RINGING), []);
    }

    /// Shows a ringing call on the headsets for a few seconds and prints the buttons pressed
    /// meanwhile: `cargo test -p miphone watches_headsets -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn watches_headsets() {
        let headset = Headset::start(|button| println!("pressed: {button:?}"));
        headset.set_lights(RINGING);
        std::thread::sleep(Duration::from_secs(4));
        headset.set_lights(TALKING);
        std::thread::sleep(Duration::from_secs(4));
        headset.set_lights(IDLE);
        std::thread::sleep(Duration::from_millis(300));
    }

    /// Lists the headsets that are plugged in: `cargo test -p miphone lists_headsets -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn lists_headsets() {
        println!("{:#?}", describe());
        // To see that the search works at all: every HID device has a kind.
        for device in hid::survey() {
            println!("{device}");
        }
    }
}
