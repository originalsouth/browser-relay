mod blocklist;
mod browser;
use browser_relay::domain_list;
mod ct_transport;
mod http;
mod inspect;
mod inspector_ui;
mod list_cache;
use browser_relay::qr;
mod relay;
mod reputation;
mod tranco;
mod ui;
mod whois;

use relay::{Action, executable, execute};

use std::env;
use std::io::{self, IsTerminal, Write};
use std::process::{Command, ExitCode};

const HELP: &str = "browser-relay — choose a browser or copy a link

Usage: browser-relay [--terminal] [--] URL [URL ...]
       browser-relay --prompt

Shows a desktop dialog with browsers, clipboard, QR code, and link inspection.
The terminal and Zenity choosers offer browsers and clipboard only.
Multiple URLs open together or copy as newline-separated text.
Cancel closes the dialog without opening anything.

Options:
  --prompt    Ask for a link when launched without one
  --update-ct-logs  Download and authenticate CT log keys
  --update-lists  Download OISD and Tranco (including subdomains)
  --update-tranco  Download the Tranco popularity index
  --update-blocklists  Download OISD Big and NSFW for local inspection
  --terminal  Choose using stdin instead of a desktop dialog
  -h, --help  Show this help
  --version   Show the version

Requires GTK 4 for the dialog; wl-copy (Wayland) or xclip/xsel (X11)
for clipboard support. Browsers are discovered from desktop registrations,
with a PATH fallback for Chromium and Firefox.
Run ./install.sh to register this app as your default browser.
";

type Result<T> = std::result::Result<T, String>;

fn action(value: &str, browsers: &[browser::Browser]) -> Result<Action> {
    let value = value.trim();
    if matches!(value, "" | "q" | "Q") {
        return Ok(Action::Cancel);
    }
    if matches!(value, "c" | "C" | "Copy to clipboard") {
        return Ok(Action::Copy);
    }
    if let Ok(index) = value.parse::<usize>() {
        if index == browsers.len() + 1 {
            return Ok(Action::Copy);
        }
        if let Some(browser) = index.checked_sub(1).and_then(|i| browsers.get(i)) {
            return Ok(Action::Browser(browser.clone()));
        }
    }
    let mut matches = browsers.iter().filter(|b| {
        b.name == value || terminal_text(&b.name) == value || format!("{:?}", b.name) == value
    });
    if let Some(browser) = matches.next()
        && matches.next().is_none()
    {
        return Ok(Action::Browser(browser.clone()));
    }
    Err(format!(
        "Choose 1–{}, c to copy, or q to cancel.",
        browsers.len() + 1
    ))
}

fn terminal_text(value: &str) -> String {
    browser_relay::display_text::escaped(value)
}

fn escape_markup(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn choose(urls: &[String], terminal: bool) -> Result<Action> {
    if terminal && !io::stdin().is_terminal() {
        return Err("--terminal needs an interactive terminal.".into());
    }
    let browsers = browser::discover();
    if terminal {
        // Debug formatting keeps control characters in input from affecting the terminal.
        for url in urls {
            eprintln!("{url:?}");
        }
        loop {
            for (i, browser) in browsers.iter().enumerate() {
                eprintln!("{}) {}", i + 1, terminal_text(&browser.name));
            }
            eprint!(
                "{}) Copy to clipboard (c)  q) Cancel\nChoice: ",
                browsers.len() + 1
            );
            io::stderr().flush().map_err(|e| e.to_string())?;
            let mut input = String::new();
            io::stdin()
                .read_line(&mut input)
                .map_err(|e| e.to_string())?;
            match action(&input, &browsers) {
                Ok(choice) => return Ok(choice),
                Err(error) => eprintln!("{error}"),
            }
        }
    }

    let zenity =
        executable(&["zenity"]).ok_or("Install zenity for the chooser, or use --terminal.")?;
    let preview = urls
        .iter()
        .take(4)
        .map(|url| {
            let short: String = url.chars().take(180).collect();
            escape_markup(&short) + if url.chars().count() > 180 { "…" } else { "" }
        })
        .collect::<Vec<_>>()
        .join("\n");
    let suffix = if urls.len() > 4 {
        format!("\n… and {} more", urls.len() - 4)
    } else {
        String::new()
    };
    let output = Command::new(zenity)
        .args([
            "--list",
            "--title=Browser Relay",
            "--width=640",
            "--height=320",
            "--column=ID",
            "--column=Open with",
            "--hide-column=1",
            "--print-column=1",
            "--hide-header",
            "--ok-label=Choose",
            "--cancel-label=Cancel",
        ])
        .arg(format!("--text={preview}{suffix}"))
        .arg("--")
        .args(
            browsers
                .iter()
                .enumerate()
                .flat_map(|(i, b)| [(i + 1).to_string(), b.name.clone()]),
        )
        .args([(browsers.len() + 1).to_string(), "Copy to clipboard".into()])
        .output()
        .map_err(|e| format!("Could not start the chooser: {e}"))?;
    if output.status.code() == Some(1) {
        return Ok(Action::Cancel);
    }
    if !output.status.success() {
        return Err(format!(
            "Chooser failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    action(&String::from_utf8_lossy(&output.stdout), &browsers)
}

fn run() -> Result<()> {
    let mut terminal = false;
    let mut prompt = false;
    let mut literal = false;
    let mut urls = Vec::new();
    for arg in env::args().skip(1) {
        if !literal {
            match arg.as_str() {
                "--" => {
                    literal = true;
                    continue;
                }
                "--prompt" => {
                    prompt = true;
                    continue;
                }
                "--terminal" => {
                    terminal = true;
                    continue;
                }
                "--update-lists" | "--update-tranco" => {
                    let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                    if arg == "--update-tranco" {
                        println!("{}", tranco::update(&cancel)?);
                    } else {
                        let (message, failed) = reputation::update(&cancel);
                        if failed {
                            return Err(message);
                        }
                        println!("{message}");
                    }
                    return Ok(());
                }
                "--update-ct-logs" => {
                    let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                    println!("{}", ct_transport::update_logs(&cancel)?);
                    return Ok(());
                }
                "--update-blocklists" => {
                    let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                    println!("{}", blocklist::update(&cancel)?);
                    return Ok(());
                }
                "--help" | "-h" => {
                    print!("{HELP}");
                    return Ok(());
                }
                "--version" => {
                    println!("browser-relay {}", env!("CARGO_PKG_VERSION"));
                    return Ok(());
                }
                _ if arg.starts_with('-') => return Err(format!("Unknown option: {arg}")),
                _ => {}
            }
        }
        validate_link(&arg)?;
        urls.push(arg);
    }
    if urls.is_empty() && prompt {
        let Some(link) = ui::prompt()? else {
            return Ok(());
        };
        validate_link(&link)?;
        urls.push(link);
    }
    if urls.is_empty() {
        print!("{HELP}");
        return Ok(());
    }
    if !terminal && env::var("BROWSER_RELAY_DIALOG").as_deref() != Ok("zenity") {
        return ui::run(&urls);
    }
    execute(choose(&urls, terminal)?, &urls)
}

fn validate_link(link: &str) -> Result<()> {
    if link.is_empty() || link.starts_with('-') || link.chars().any(char::is_control) {
        return Err(
            "Links must be nonempty, contain no control characters, and not start with '-'.".into(),
        );
    }
    Ok(())
}

fn main() -> ExitCode {
    // SAFETY: first operation in the executable, before GTK/GIO or any workers
    // are initialized. No other thread can be reading the process environment.
    unsafe {
        env::set_var("PATH", relay::safe_path(env::var_os("PATH").as_deref()));
    }

    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("browser-relay: {error}");
            if !env::args().any(|arg| {
                matches!(
                    arg.as_str(),
                    "--update-blocklists"
                        | "--update-tranco"
                        | "--update-lists"
                        | "--update-ct-logs"
                )
            }) && (env::var_os("WAYLAND_DISPLAY").is_some() || env::var_os("DISPLAY").is_some())
                && let Some(zenity) = executable(&["zenity"])
            {
                let _ = Command::new(zenity)
                    .args(["--error", "--title=Browser Relay", "--no-markup"])
                    .arg(format!("--text={error}"))
                    .status();
            }
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_names_are_readable_without_control_sequences() {
        assert_eq!(terminal_text("Firefox"), "Firefox");
        assert_eq!(terminal_text("Work Browser"), "Work Browser");
        let escaped = terminal_text("Bad\n\x1b[31m\u{202e}");
        assert!(!escaped.chars().any(char::is_control));
        assert!(!escaped.contains('\u{202e}'));
    }

    #[test]
    fn choices_and_cancel() {
        assert_eq!(action("1\n", &[]), Ok(Action::Copy));
        assert_eq!(action("Copy to clipboard\n", &[]), Ok(Action::Copy));
        assert_eq!(action("c", &[]), Ok(Action::Copy));
        assert_eq!(action("", &[]), Ok(Action::Cancel));
        assert!(action("0", &[]).is_err());
        assert!(action("2", &[]).is_err());
        assert!(action("unexpected", &[]).is_err());
    }

    #[test]
    fn links_cannot_inject_dialog_markup() {
        assert_eq!(
            escape_markup("https://example.org/<b>?x=1&y=2"),
            "https://example.org/&lt;b&gt;?x=1&amp;y=2"
        );
    }
}
