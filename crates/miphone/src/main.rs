use anyhow::Result;
use miphone::ua::{Command, Event};
use miphone::{config, media, provision, ua};
use tokio::sync::mpsc;

const HELP: &str = "Befehle:
  call <nummer>   Anruf aufbauen
  answer          eingehenden Anruf annehmen
  hangup          auflegen / abweisen / Aufbau abbrechen
  hold | resume   Gespraech halten / fortsetzen
  transfer <nr>   Gespraech an eine Nummer vermitteln
  dtmf <ziffern>  Tonwahl im Gespraech senden
  mute | unmute   Mikrofon stumm schalten
  quit            abmelden und beenden";

fn parse_command(line: &str) -> Option<Command> {
    let line = line.trim();
    let (cmd, arg) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
    let arg = arg.trim();
    match cmd.to_ascii_lowercase().as_str() {
        "call" | "c" if !arg.is_empty() => Some(Command::Call(arg.to_string())),
        "answer" | "a" => Some(Command::Answer),
        "hangup" | "h" => Some(Command::Hangup),
        "dtmf" | "d" if !arg.is_empty() => Some(Command::Dtmf(arg.to_string())),
        "hold" => Some(Command::Hold),
        "resume" => Some(Command::Resume),
        "transfer" | "t" if !arg.is_empty() => Some(Command::Transfer(arg.to_string())),
        "mute" => Some(Command::Mute(true)),
        "unmute" => Some(Command::Mute(false)),
        "quit" | "q" | "exit" => Some(Command::Quit),
        _ => None,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut config_path = "config.toml".to_string();
    let mut verbose = false;
    let mut provision_only = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "-c" | "--config" => config_path = args.next().ok_or_else(|| anyhow::anyhow!("--config braucht einen Pfad"))?,
            "-v" | "--verbose" => verbose = true,
            "--provision-only" => provision_only = true,
            _ => {
                println!("miphone [--config <datei>] [--verbose] [--provision-only]\n\n  --provision-only  nur das SIP-Konto vom MiCollab-Server abrufen und anzeigen, nicht registrieren\n\n{HELP}");
                return Ok(());
            }
        }
    }
    let config = config::Config::load(&config_path)?;
    let mut cfg = config.sip;
    let mut password = cfg.password();
    if let Some(mc) = config.micollab.as_ref().filter(|_| password.is_none() || provision_only) {
        // The MiCollab password is only held in memory for the download.
        let login = match std::env::var("MIPHONE_MICOLLAB_PASSWORD") {
            Ok(p) if !p.is_empty() => p,
            _ => rpassword::prompt_password(format!("Kennwort fuer {} am MiCollab-Server {}: ", mc.user, mc.server))?,
        };
        println!("Rufe Bereitstellung von {} ab ...", mc.server);
        let profile = provision::fetch(mc, &login, verbose).await?;
        println!(
            "SIP-Konto: {} an {}:{}{} ({}{}{}{})",
            profile.account.user,
            profile.account.server,
            profile.account.port,
            profile.account.outbound_proxy.as_ref().map(|(host, port)| format!(" ueber {host}:{port}")).unwrap_or_default(),
            if profile.teleworker { "Teleworker, ueber MBG" } else { "direkt an der Anlage" },
            if profile.acd { ", ACD-Agent" } else { "" },
            profile.number.as_ref().map(|n| format!(", Nummer {n}")).unwrap_or_default(),
            match &profile.other {
                Some(other) => format!("; umschaltbar mit micollab.teleworker = {} auf {}", !profile.teleworker, other.server),
                None => String::new(),
            }
        );
        // Explicit [sip] settings win over the downloaded profile.
        let account = profile.account;
        if cfg.server.is_empty() {
            cfg.server = account.server;
            cfg.port = cfg.port.or(Some(account.port));
            if let (None, Some((host, port))) = (&cfg.outbound_proxy, account.outbound_proxy) {
                cfg.outbound_proxy = Some(host);
                cfg.outbound_proxy_port = Some(port);
            }
        }
        if cfg.user.is_empty() {
            cfg.user = account.user;
        }
        cfg.acd = cfg.acd || profile.acd;
        cfg.tls_ca_chain = cfg.tls_ca_chain.or(account.ca_chain);
        password = password.or(Some(account.password));
    }
    if provision_only {
        println!("SIP-Kennwort erhalten: {}", if password.is_some() { "ja" } else { "nein" });
        return Ok(());
    }
    let password = password
        .ok_or_else(|| anyhow::anyhow!("Kein SIP-Kennwort: [micollab] angeben, sip.password setzen oder MIPHONE_SIP_PASSWORD verwenden"))?;
    if cfg.server.is_empty() || cfg.user.is_empty() {
        anyhow::bail!("SIP-Server und SIP-Benutzer sind nicht bekannt");
    }
    let (tx, mut rx) = mpsc::channel::<Command>(16);
    std::thread::spawn(move || {
        for line in std::io::stdin().lines() {
            let Ok(line) = line else { break };
            if line.trim().is_empty() {
                continue;
            }
            match parse_command(&line) {
                Some(cmd) => {
                    if tx.blocking_send(cmd).is_err() {
                        break;
                    }
                }
                None => println!("{HELP}"),
            }
        }
        // End of input: tx is dropped here, which ends the program like `quit`.
    });

    println!("{HELP}\n");
    let (events, mut log) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(event) = log.recv().await {
            if let Event::Log(line) = event {
                println!("{line}");
            }
        }
    });
    let audio = media::AudioSettings::default();
    loop {
        match ua::run(&cfg, &password, verbose, Some(audio.clone()), &events, &mut rx).await {
            Ok(()) => return Ok(()),
            Err(e) => {
                eprintln!("Verbindung verloren: {e:#}. Neuer Versuch in 5 s.");
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_commands() {
        assert!(matches!(parse_command("call 860027"), Some(Command::Call(n)) if n == "860027"));
        assert!(matches!(parse_command("  A "), Some(Command::Answer)));
        assert!(matches!(parse_command("dtmf 12#"), Some(Command::Dtmf(d)) if d == "12#"));
        assert!(matches!(parse_command("unmute"), Some(Command::Mute(false))));
        assert!(parse_command("call").is_none());
        assert!(parse_command("foo").is_none());
    }
}
