mod ui;

use std::env;
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};

const HELP: &str = "browser-relay — choose where a link goes

Usage: browser-relay [--terminal] [--] URL [URL ...]

Shows a desktop dialog with Chromium, Firefox, and Copy to clipboard.
Multiple URLs open together or copy as newline-separated text.
Cancel closes the dialog without opening anything.

Options:
  --prompt    Ask for a link when launched without one
  --terminal  Choose using stdin instead of a desktop dialog
  -h, --help  Show this help
  --version   Show the version

Requires GTK 4 for the dialog; wl-copy (Wayland) or xclip/xsel (X11)
for clipboard support. Browser executables are discovered on PATH.
Run ./install.sh to register this app as your default browser.
";

type Result<T> = std::result::Result<T, String>;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Action {
    Chromium,
    Firefox,
    Copy,
    Cancel,
}

fn action(value: &str) -> Result<Action> {
    match value.trim() {
        "1" | "Chromium" => Ok(Action::Chromium),
        "2" | "Firefox" => Ok(Action::Firefox),
        "3" | "Copy to clipboard" => Ok(Action::Copy),
        "" | "q" | "Q" => Ok(Action::Cancel),
        _ => Err("Choose 1, 2, 3, or q.".into()),
    }
}

fn executable(names: &[&str]) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let path = env::var_os("PATH")?;
    names.iter().find_map(|name| {
        env::split_paths(&path).find_map(|dir| {
            let candidate = dir.join(name);
            let metadata = candidate.metadata().ok()?;
            (metadata.is_file() && metadata.permissions().mode() & 0o111 != 0).then_some(candidate)
        })
    })
}

fn escape_markup(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn choose(urls: &[String], terminal: bool) -> Result<Action> {
    if terminal {
        if !io::stdin().is_terminal() {
            return Err("--terminal needs an interactive terminal.".into());
        }
        // Debug formatting keeps control characters in input from affecting the terminal.
        for url in urls {
            eprintln!("{url:?}");
        }
        loop {
            eprint!("1) Chromium  2) Firefox  3) Copy to clipboard  q) Cancel\nChoice: ");
            io::stderr().flush().map_err(|e| e.to_string())?;
            let mut input = String::new();
            io::stdin()
                .read_line(&mut input)
                .map_err(|e| e.to_string())?;
            match action(&input) {
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
            "--column=Open with",
            "--hide-header",
            "--ok-label=Choose",
            "--cancel-label=Cancel",
        ])
        .arg(format!("--text={preview}{suffix}"))
        .args(["Chromium", "Firefox", "Copy to clipboard"])
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
    action(&String::from_utf8_lossy(&output.stdout))
}

fn open_browser(names: &[&str], urls: &[String]) -> Result<()> {
    let program = executable(names)
        .ok_or_else(|| format!("Could not find {} on PATH.", names.join(" or ")))?;
    // Never invoke a shell or xdg-open here: that would risk injection or recursion.
    let mut child = Command::new(program)
        .arg("--")
        .args(urls)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("Could not launch {}: {e}", names[0]))?;
    // Reap immediate launcher failures without waiting for a whole browser session.
    std::thread::sleep(std::time::Duration::from_millis(150));
    if let Some(status) = child.try_wait().map_err(|e| e.to_string())?
        && !status.success()
    {
        return Err(format!("{} exited with {status}.", names[0]));
    }
    Ok(())
}

fn copy(urls: &[String]) -> Result<()> {
    let mut candidates: Vec<(&str, &[&str])> = Vec::new();
    if env::var_os("WAYLAND_DISPLAY").is_some() {
        candidates.push(("wl-copy", &["--type", "text/plain;charset=utf-8"]));
    }
    if env::var_os("DISPLAY").is_some() {
        candidates.push(("xclip", &["-selection", "clipboard"]));
        candidates.push(("xsel", &["--clipboard", "--input"]));
    }
    let text = urls.join("\n");
    let mut errors = Vec::new();
    for (name, args) in candidates {
        let Some(program) = executable(&[name]) else {
            continue;
        };
        let result = (|| -> Result<()> {
            // Clipboard helpers detach to keep owning the selection after we exit.
            // Null outputs prevent their background process from holding a pipe open.
            let mut child = Command::new(program)
                .args(args)
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|e| e.to_string())?;
            let written = child
                .stdin
                .take()
                .ok_or("Missing clipboard input pipe")?
                .write_all(text.as_bytes());
            let status = child.wait().map_err(|e| e.to_string())?;
            written.map_err(|e| e.to_string())?;
            if status.success() {
                Ok(())
            } else {
                Err(status.to_string())
            }
        })();
        match result {
            Ok(()) => return Ok(()),
            Err(error) => errors.push(format!("{name}: {error}")),
        }
    }
    Err(format!(
        "Could not copy. Use wl-copy on Wayland or xclip/xsel on X11, in an active desktop session. {}",
        errors.join("; ")
    ))
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

fn execute(action: Action, urls: &[String]) -> Result<()> {
    match action {
        Action::Chromium => open_browser(&["chromium", "chromium-browser"], urls),
        Action::Firefox => open_browser(&["firefox", "firefox-esr"], urls),
        Action::Copy => copy(urls),
        Action::Cancel => Ok(()),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("browser-relay: {error}");
            if (env::var_os("WAYLAND_DISPLAY").is_some() || env::var_os("DISPLAY").is_some())
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
    fn choices_and_cancel() {
        assert_eq!(action("Chromium\n"), Ok(Action::Chromium));
        assert_eq!(action("2\n"), Ok(Action::Firefox));
        assert_eq!(action("Copy to clipboard\n"), Ok(Action::Copy));
        assert_eq!(action(""), Ok(Action::Cancel));
        assert!(action("unexpected").is_err());
    }

    #[test]
    fn links_cannot_inject_dialog_markup() {
        assert_eq!(
            escape_markup("https://example.org/<b>?x=1&y=2"),
            "https://example.org/&lt;b&gt;?x=1&amp;y=2"
        );
    }
}
