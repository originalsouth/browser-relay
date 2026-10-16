//! Installed web handlers, discovered and launched through GIO's desktop registry.
use crate::{Result, relay::executable};
use gtk::{gdk, gio, glib, prelude::*};
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, PartialEq, Eq)]
enum Launcher {
    Desktop(String),
    Executable(PathBuf),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Browser {
    pub name: String,
    pub icon: String,
    launcher: Launcher,
}

fn indirect_name(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|s| s.to_str()),
        Some(
            "browser-relay"
                | "xdg-open"
                | "sensible-browser"
                | "x-www-browser"
                | "gio"
                | "gnome-open"
                | "kde-open"
                | "kde-open5"
                | "kde-open6"
        )
    )
}

fn indirect_launcher(path: &Path) -> bool {
    let resolved = path.canonicalize().ok();
    indirect_name(path)
        || resolved.as_deref().is_some_and(indirect_name)
        || resolved.as_ref().is_some_and(|resolved| {
            static OWN_PATH: std::sync::OnceLock<Option<PathBuf>> = std::sync::OnceLock::new();
            OWN_PATH
                .get_or_init(|| {
                    std::env::current_exe()
                        .ok()
                        .and_then(|p| p.canonicalize().ok())
                })
                .as_ref()
                == Some(resolved)
        })
}

struct LegacyBrowser {
    name: &'static str,
    aliases: &'static [&'static str],
    icon: &'static str,
    desktop_ids: &'static [&'static str],
}
const LEGACY_BROWSERS: &[LegacyBrowser] = &[
    LegacyBrowser {
        name: "Chromium",
        aliases: &["chromium", "chromium-browser"],
        icon: "chromium",
        desktop_ids: &[
            "chromium.desktop",
            "chromium-browser.desktop",
            "org.chromium.Chromium.desktop",
            "chromium_chromium.desktop",
        ],
    },
    LegacyBrowser {
        name: "Firefox",
        aliases: &["firefox", "firefox-esr"],
        icon: "firefox",
        desktop_ids: &[
            "firefox.desktop",
            "firefox-esr.desktop",
            "org.mozilla.firefox.desktop",
            "firefox_firefox.desktop",
        ],
    },
];

fn web_program(app: &gio::AppInfo) -> Option<(PathBuf, Vec<std::ffi::OsString>)> {
    if !app.should_show()
        || !app.supports_uris()
        || app.id().is_none_or(|id| id == "browser-relay.desktop")
        || !app.supported_types().iter().any(|t| {
            matches!(
                t.as_str(),
                "x-scheme-handler/http" | "x-scheme-handler/https"
            )
        })
    {
        return None;
    }
    // Parse once per candidate. Cheap registry checks above reject non-browsers
    // before touching executables or resolving symlinks.
    let command = app.commandline()?;
    let args = glib::shell_parse_argv(&command).ok()?;
    let program = executable(&[args.first()?.to_str()?])?;
    if indirect_launcher(&program)
        || args.iter().skip(1).any(|arg| {
            let Some(arg) = arg.to_str() else {
                return false;
            };
            // Wrapper commands may name the relay, including a symlink on PATH.
            !arg.starts_with('-')
                && !arg.contains(['%', '='])
                && (indirect_name(Path::new(arg))
                    || executable(&[arg]).is_some_and(|path| indirect_launcher(&path)))
        })
    {
        return None;
    }
    let canonical = program.canonicalize().unwrap_or_else(|_| program.clone());
    let command = std::iter::once(canonical.into_os_string())
        .chain(
            args.into_iter()
                .skip(1)
                .filter(|arg| arg != "%u" && arg != "%U"),
        )
        .collect();
    Some((program, command))
}

fn hidden_registration(id: &str) -> bool {
    // Only the highest-precedence registration controls visibility. A broken
    // Exec or absent MIME declaration must not hide a working PATH installation.
    for dir in std::iter::once(glib::user_data_dir()).chain(glib::system_data_dirs()) {
        let path = dir.join("applications").join(id);
        if !path.exists() {
            continue;
        }
        let keys = glib::KeyFile::new();
        if keys.load_from_file(&path, glib::KeyFileFlags::NONE).is_ok()
            && ["Hidden", "NoDisplay"]
                .iter()
                .any(|key| keys.boolean("Desktop Entry", key).unwrap_or(false))
        {
            return true;
        }
        return gio_unix::DesktopAppInfo::from_filename(&path)
            .is_some_and(|app| !app.should_show());
    }
    false
}

pub(crate) fn discover() -> Vec<Browser> {
    let mut browsers = Vec::new();
    let mut commands = HashSet::new();
    let mut programs = HashSet::new();
    let mut accepted_ids = HashSet::new();
    // MIME queries omit valid user desktop files until update-desktop-database
    // has run. Enumerate once on the discovery worker to retain those handlers.
    let mut apps: Vec<_> = gio::AppInfo::all()
        .into_iter()
        .filter_map(|app| web_program(&app).map(|(program, command)| (app, program, command)))
        .collect();
    let default_id = gio::AppInfo::default_for_uri_scheme("https").and_then(|a| a.id());
    // Stable order also makes duplicate desktop entries deterministic.
    apps.sort_by_key(|(a, _, _)| (a.id() != default_id, a.id().map(|id| id.to_string())));
    for (app, program, command) in apps {
        accepted_ids.insert(app.id().unwrap().to_string());
        if !commands.insert(command) {
            continue;
        }
        programs.insert(program.canonicalize().unwrap_or(program));
        browsers.push(Browser {
            name: app.display_name().to_string(),
            icon: app
                .icon()
                .and_then(|i| i.to_string())
                .map(|s| s.to_string())
                .unwrap_or_else(|| "web-browser-symbolic".into()),
            launcher: Launcher::Desktop(app.id().unwrap().to_string()),
        });
    }
    // Retain support for the original standalone/PATH-only installations.
    for legacy in LEGACY_BROWSERS {
        let LegacyBrowser {
            name,
            aliases,
            icon,
            desktop_ids,
        } = legacy;
        if desktop_ids.iter().any(|id| accepted_ids.contains(*id))
            || desktop_ids.iter().any(|id| hidden_registration(id))
        {
            continue;
        }
        if let Some(program) = executable(aliases) {
            let canonical = program.canonicalize().unwrap_or_else(|_| program.clone());
            if !indirect_launcher(&program)
                && !programs.contains(&canonical)
                && !browsers.iter().any(|b| b.name.eq_ignore_ascii_case(name))
            {
                browsers.push(Browser {
                    name: (*name).into(),
                    icon: (*icon).into(),
                    launcher: Launcher::Executable(program),
                });
            }
        }
    }
    browsers.sort_by_key(|b| b.name.to_lowercase());
    browsers
}

/// Recovery when desktop discovery is unavailable. No registry scan or xdg-open.
pub(crate) fn fallback() -> Option<Browser> {
    LEGACY_BROWSERS.iter().find_map(|legacy| {
        if legacy.desktop_ids.iter().any(|id| hidden_registration(id)) {
            return None;
        }
        let program = executable(legacy.aliases)?;
        (!indirect_launcher(&program)).then(|| Browser {
            name: legacy.name.into(),
            icon: legacy.icon.into(),
            launcher: Launcher::Executable(program),
        })
    })
}

/// Prefer the current HTTPS handler, then the saved pre-relay handler, then
/// Chromium/Firefox. The popover always names the selected browser explicitly.
pub(crate) fn preferred(browsers: &[Browser]) -> Option<Browser> {
    let mut ids = Vec::new();
    if let Some(id) = gio::AppInfo::default_for_uri_scheme("https").and_then(|app| app.id()) {
        ids.push(id.to_string());
    }
    use std::io::Read;
    let state = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| glib::home_dir().join(".local/state"));
    if let Ok(file) = std::fs::File::open(state.join("browser-relay/previous-defaults")) {
        let mut saved = String::new();
        if file.take(16 * 1024).read_to_string(&mut saved).is_ok() {
            for kind in ["x-scheme-handler/https", "browser"] {
                ids.extend(
                    saved
                        .lines()
                        .filter_map(|line| line.split_once('\t'))
                        .filter(|(key, _)| *key == kind)
                        .map(|(_, id)| id.to_owned()),
                );
            }
        }
    }
    for id in ids {
        if let Some(browser) = browsers
            .iter()
            .find(|b| b.launcher == Launcher::Desktop(id.clone()))
        {
            return Some(browser.clone());
        }
    }
    for legacy in LEGACY_BROWSERS {
        if let Some(browser) = browsers.iter().find(|b| match &b.launcher {
            Launcher::Desktop(id) => legacy.desktop_ids.contains(&id.as_str()),
            Launcher::Executable(path) => path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|name| legacy.aliases.contains(&name)),
        }) {
            return Some(browser.clone());
        }
    }
    browsers.first().cloned()
}

// Existing local files take precedence over ambiguous domain-like names. An
// explicit URL always keeps its meaning; never disclose a local name as a host.
fn browser_argument(input: &str) -> Result<String> {
    if url::Url::parse(input).is_err() {
        match std::fs::symlink_metadata(input) {
            Ok(_) => return file_uri(input),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(format!(
                    "Could not determine whether the input is a local file: {e}"
                ));
            }
        }
    }
    if !input.starts_with('/')
        && !input.starts_with("./")
        && !input.starts_with("../")
        && let Ok(url) = url::Url::parse(&format!("https://{input}"))
        && url.username().is_empty()
        && url.password().is_none()
        && url.host_str().is_some_and(browser_relay::link::public_name)
    {
        return Ok(format!("https://{input}"));
    }
    Ok(input.into())
}

// GIO needs local paths adapted to its URI interface.
fn desktop_argument(input: &str) -> Result<String> {
    let path = Path::new(input);
    if path.is_absolute()
        || input.starts_with("./")
        || input.starts_with("../")
        || (url::Url::parse(input).is_err() && path.exists())
    {
        return file_uri(input);
    }
    Ok(input.into())
}

fn file_uri(input: &str) -> Result<String> {
    let path = Path::new(input);
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join(path)
    };
    url::Url::from_file_path(absolute)
        .map(|url| url.to_string())
        .map_err(|_| "Invalid local file path.".into())
}

impl Browser {
    pub fn launch(&self, urls: &[String]) -> Result<()> {
        let context = glib::MainContext::new();
        context
            .with_thread_default(|| context.block_on(self.launch_with_context(urls, None)))
            .map_err(|e| format!("Could not initialize browser launch: {e}"))?
    }

    /// Keep the display's activation context on the GTK thread throughout the
    /// asynchronous launch. The compositor decides whether to grant focus.
    pub async fn launch_gui(&self, urls: Vec<String>) -> Result<()> {
        if matches!(self.launcher, Launcher::Executable(_)) {
            let browser = self.clone();
            return gio::spawn_blocking(move || browser.launch(&urls))
                .await
                .map_err(|_| "Browser launch did not complete.")?;
        }
        let display = gdk::Display::default().ok_or("No desktop display available.")?;
        let context = display.app_launch_context();
        context.set_timestamp(gdk::CURRENT_TIME);
        context.set_icon(gio::Icon::for_string(&self.icon).ok().as_ref());
        self.launch_with_context(&urls, Some(context.upcast_ref()))
            .await
    }

    async fn launch_with_context(
        &self,
        urls: &[String],
        context: Option<&gio::AppLaunchContext>,
    ) -> Result<()> {
        let urls = urls
            .iter()
            .map(|input| browser_argument(input))
            .collect::<Result<Vec<_>>>()?;
        match &self.launcher {
            Launcher::Executable(program) => crate::relay::open_browser(program, &self.name, &urls),
            Launcher::Desktop(id) => {
                let app = gio_unix::DesktopAppInfo::new(id)
                    .map(|app| app.upcast::<gio::AppInfo>())
                    .filter(|app| web_program(app).is_some())
                    .ok_or_else(|| {
                        format!(
                            "{} is no longer available. Reopen the chooser to refresh.",
                            self.name
                        )
                    })?;
                let uris = urls
                    .iter()
                    .map(|input| desktop_argument(input))
                    .collect::<Result<Vec<_>>>()?;
                // Await completion so D-Bus activation is sent before we exit.
                app.launch_uris_future(
                    &uris.iter().map(String::as_str).collect::<Vec<_>>(),
                    context,
                )
                .await
                .map_err(|e| format!("Could not launch {}: {e}", self.name))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn report_browser_respects_defaults_before_legacy_preference() {
        if let Ok(expected) = std::env::var("RELAY_PREFERRED_FIXTURE") {
            let browsers = discover();
            assert_eq!(preferred(&browsers).unwrap().name, expected);
            assert!(preferred(&[]).is_none());
            return;
        }
        let root = std::env::temp_dir().join(format!("relay-preferred-{}", std::process::id()));
        let apps = root.join("data/applications");
        std::fs::create_dir_all(&apps).unwrap();
        std::fs::create_dir_all(root.join("config")).unwrap();
        std::fs::create_dir_all(root.join("state/browser-relay")).unwrap();
        for (id, name) in [
            ("alpha", "Alpha"),
            ("chromium", "Chromium"),
            ("firefox", "Firefox"),
            ("browser-relay", "Browser Relay"),
        ] {
            std::fs::write(apps.join(format!("{id}.desktop")), format!("[Desktop Entry]\nType=Application\nName={name}\nExec=/bin/true --{id} %U\nMimeType=x-scheme-handler/https;\n")).unwrap();
        }
        for (default, saved, expected) in [
            ("firefox", "", "Firefox"),
            ("browser-relay", "browser\tfirefox.desktop\n", "Firefox"),
            ("browser-relay", "", "Chromium"),
        ] {
            std::fs::write(
                root.join("config/mimeapps.list"),
                format!("[Default Applications]\nx-scheme-handler/https={default}.desktop;\n"),
            )
            .unwrap();
            std::fs::write(root.join("state/browser-relay/previous-defaults"), saved).unwrap();
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "browser::tests::report_browser_respects_defaults_before_legacy_preference",
                    "--nocapture",
                ])
                .env("RELAY_PREFERRED_FIXTURE", expected)
                .env("PATH", &root)
                .env("XDG_CONFIG_HOME", root.join("config"))
                .env("XDG_CONFIG_DIRS", root.join("config"))
                .env("XDG_DATA_HOME", root.join("data"))
                .env("XDG_DATA_DIRS", root.join("system"))
                .env("XDG_STATE_HOME", root.join("state"))
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn desktop_discovery_without_path() {
        if std::env::var_os("RELAY_NO_PATH_FIXTURE").is_some() {
            assert!(std::env::var_os("PATH").is_none());
            let browsers = discover();
            assert!(browsers.iter().any(|b| b.name == "Absolute Browser"));
            assert!(!browsers.iter().any(|b| b.name == "Cwd Browser"));
            let cwd = std::env::current_dir().unwrap();
            for name in ["zenity", "firefox", "chromium", "relay-cwd-browser"] {
                assert_ne!(executable(&[name]), Some(cwd.join(name)));
            }
            assert_eq!(executable(&["relay-cwd-browser"]), None);
            assert_eq!(
                executable(&[cwd.join("firefox").to_str().unwrap()]),
                Some(cwd.join("firefox"))
            );
            return;
        }
        let root = std::env::temp_dir().join(format!("relay-no-path-{}", std::process::id()));
        std::fs::create_dir_all(root.join("applications")).unwrap();
        std::fs::write(root.join("applications/fixture.desktop"), "[Desktop Entry]\nType=Application\nName=Absolute Browser\nExec=/bin/true %U\nMimeType=x-scheme-handler/https;\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        for name in ["zenity", "firefox", "chromium", "relay-cwd-browser"] {
            let path = root.join(name);
            std::fs::write(&path, "#!/bin/sh\nexit 99\n").unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        std::fs::write(root.join("applications/cwd.desktop"), "[Desktop Entry]\nType=Application\nName=Cwd Browser\nExec=relay-cwd-browser %U\nMimeType=x-scheme-handler/https;\n").unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .current_dir(&root)
            .args([
                "--exact",
                "browser::tests::desktop_discovery_without_path",
                "--nocapture",
            ])
            .env_remove("PATH")
            .env("RELAY_NO_PATH_FIXTURE", "1")
            .env("XDG_DATA_HOME", &root)
            .env("XDG_DATA_DIRS", root.join("system"))
            .output()
            .unwrap();
        std::fs::remove_dir_all(root).unwrap();
        assert!(output.status.success(), "{output:?}");
    }
}
