//! Softphone core: configuration, provisioning, SIP user agent and audio.
//! Front ends (command line, graphical) drive it through `ua::Command` and `ua::Event`.

pub mod config;
pub mod dns;
pub mod headset;
pub mod media;
pub mod micollab;
pub mod provision;
pub mod ringtone;
pub mod store;
pub mod ua;
pub mod update;
pub mod wsp;
