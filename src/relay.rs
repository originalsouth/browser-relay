use crate::Result;
use std::env;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum Action {
    Chromium,
    Firefox,
    Copy,
    Cancel,
}

pub(crate) fn executable(names: &[&str]) -> Option<PathBuf> {
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

pub(crate) fn execute(action: Action, urls: &[String]) -> Result<()> {
    match action {
        Action::Chromium => open_browser(&["chromium", "chromium-browser"], urls),
        Action::Firefox => open_browser(&["firefox", "firefox-esr"], urls),
        Action::Copy => copy(urls),
        Action::Cancel => Ok(()),
    }
}
