use crate::Result;
use std::env;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Action {
    Browser(crate::browser::Browser),
    Copy,
    Cancel,
}

/// Also sanitize the process environment before GIO starts: it resolves desktop
/// Exec/TryExec itself, and wrappers inherit PATH when launching the browser.
pub(crate) fn safe_path(path: Option<&std::ffi::OsStr>) -> std::ffi::OsString {
    let dirs: Vec<_> = search_directories(path).collect();
    if dirs.is_empty() {
        // Empty PATH itself means cwd to execvp/GLib. This absolute non-directory
        // guarantees that an intentionally empty search cannot find anything.
        "/dev/null".into()
    } else {
        env::join_paths(dirs).expect("split PATH components contain no separator")
    }
}

fn search_directories(path: Option<&std::ffi::OsStr>) -> impl Iterator<Item = PathBuf> + '_ {
    let path = path.unwrap_or_else(|| std::ffi::OsStr::new("/usr/local/bin:/usr/bin:/bin"));
    env::split_paths(path).filter(|dir| dir.is_absolute())
}

pub(crate) fn executable(names: &[&str]) -> Option<PathBuf> {
    executable_in(names, env::var_os("PATH").as_deref())
}

fn executable_in(names: &[&str], path: Option<&std::ffi::OsStr>) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;

    let runnable = |candidate: PathBuf| {
        candidate
            .metadata()
            .ok()
            .filter(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            .map(|_| candidate)
    };
    names.iter().find_map(|name| {
        let candidate = std::path::Path::new(name);
        if candidate.is_absolute() {
            return runnable(candidate.to_owned());
        }
        if candidate.components().count() != 1 {
            return None;
        }
        search_directories(path).find_map(|dir| runnable(dir.join(candidate)))
    })
}

pub(crate) fn open_browser(program: &std::path::Path, name: &str, urls: &[String]) -> Result<()> {
    // Never invoke a shell or xdg-open here: that would risk injection or recursion.
    let mut child = Command::new(program)
        .arg("--")
        .args(urls)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("Could not launch {}: {e}", name))?;
    // Reap immediate launcher failures without waiting for a whole browser session.
    std::thread::sleep(std::time::Duration::from_millis(150));
    if let Some(status) = child.try_wait().map_err(|e| e.to_string())?
        && !status.success()
    {
        return Err(format!("{} exited with {status}.", name));
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
        Action::Browser(browser) => browser.launch(urls),
        Action::Copy => copy(urls),
        Action::Cancel => Ok(()),
    }
}

/// GUI launches retain GDK's activation context; clipboard helpers run off-thread.
pub(crate) async fn execute_gui(action: Action, urls: Vec<String>) -> Result<()> {
    match action {
        Action::Browser(browser) => browser.launch_gui(urls).await,
        action => gtk::gio::spawn_blocking(move || execute(action, &urls))
            .await
            .map_err(|_| "The action did not complete. Please try again.")?,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    #[test]
    fn path_search_excludes_empty_and_relative_directories() {
        for path in ["", ".", "bin", ":", ".:bin:", "/dev/null:", ":/dev/null"] {
            assert_eq!(executable_in(&["Cargo.toml"], Some(OsStr::new(path))), None);
            assert_eq!(safe_path(Some(OsStr::new(path))), OsStr::new("/dev/null"));
        }
        assert_eq!(
            safe_path(Some(OsStr::new(".:/usr/bin::bin:/bin:"))),
            OsStr::new("/usr/bin:/bin")
        );
        assert_eq!(safe_path(None), OsStr::new("/usr/local/bin:/usr/bin:/bin"));
    }
}
