# miphone

A softphone for Mitel MiCollab systems, written in Rust. It signs in to a MiCollab server
with the user's own account, downloads the SIP account the same way the MiCollab PC client
does, registers with the phone system and makes and receives audio calls.

This is an independent project. It is not affiliated with, endorsed by or supported by
Mitel. "Mitel" and "MiCollab" are trademarks of their owner. The program contains no code or
assets from the original client; it talks to the server over the same network protocols.

Windows only. The user interface is in German.

## What it does

- **Sign-in like the original client**: server, user name and password; the SIP account
  comes from the server's deployment profile. Accounts with several extensions ask which one
  to use.
- **Office users and ACD agents**: the profile says which kind of account it is, and the
  softphone presents itself to the phone system accordingly.
- **Teleworker on or off**: registers through the border gateway (MBG) or directly at the
  phone system, as the profile says. If the profile leaves the choice to the user, it can be
  changed in the settings without signing in again.
- **Calls**: outgoing and incoming audio calls, hold and resume, blind transfer, mute, DTMF.
- **Audio**: Opus (wideband), G.711 A-law and µ-law; selectable microphone and speaker.
- **Hot desking**: follows the server's hot desk login and logout.
- **Presence**: shows and sets the own status, shows the status of contacts.
- **Phone book**: the corporate directory and the user's contact groups, with search.
- **Own contacts**: contacts the user creates, stored encrypted on the computer only.
- **Call history**, kept locally.
- **Local data is encrypted** with the Windows account (DPAPI) under `%APPDATA%\miphone`.
  The password is stored only if "stay signed in" is ticked.

Not implemented: attended transfer, conference and a second call, ringtone, echo
cancellation, video, chat, voicemail, SRTP, server lookup via DNS SRV, CloudLink and OIDC
sign-in.

## Building

Requirements: a current Rust toolchain (edition 2024) with the MSVC target, and CMake for
the bundled Opus library.

```
cargo build --release
```

This produces two programs in `target\release`:

| Program | Purpose |
|---|---|
| `miphone-gui.exe` | The softphone with its window. |
| `miphone.exe` | A command line version for testing, configured through a file. |

Run the tests with `cargo test --workspace`. They need no server.

## Using the window

Start `miphone-gui.exe` and enter the MiCollab server, user name and password. After
sign-in the window has four pages: phone, contacts, history and settings.

Only one softphone can be registered for an extension at a time. Switch the softphone of
the original client off before using this one.

`miphone-gui.exe --demo` opens the window with sample data and without any network
connection, which is useful when working on the layout. Variants: `--demo=call`,
`incoming`, `history`, `settings`, `status`, `contacts`, `numbers`, `own`, `newcontact`, `savenumber`,
`login`, `reset`.

## Using the command line version

Copy `config.example.toml` to `config.toml` and fill it in; the comments in the file explain
every option. `config.toml` is ignored by git.

```
miphone --config config.toml              # sign in, register, then type commands
miphone --config config.toml --provision-only   # only fetch and show the SIP account
miphone --verbose                         # also print the SIP messages (without credentials)
```

The MiCollab password is asked for at start, or read from `MIPHONE_MICOLLAB_PASSWORD`. A SIP
account can also be entered by hand in the `[sip]` section, without a MiCollab server.

## Layout

| Path | Contents |
|---|---|
| `crates/misip` | SIP messages, digest authentication, SDP, RTP, G.711. No I/O. |
| `crates/miphone` | Provisioning, the SIP user agent, audio, the MiCollab server API, the event channel, encrypted storage, and the command line program. |
| `crates/miphone-gui` | The window, built with egui. |

## Relation to the original client

This program contains neither keys nor other secrets of the original client and does not
need them. It does not read the original client's stored settings.

## License

MIT, see `LICENSE`.

## Third-party material

The window uses the Open Sans typeface, licensed under the SIL Open Font License 1.1 (see
`crates/miphone-gui/assets/fonts/OFL.txt`).
