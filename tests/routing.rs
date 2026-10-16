use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Sandbox(PathBuf);

impl Sandbox {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "browser-relay-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::create_dir_all(path.join("data/applications")).unwrap();
        fs::create_dir_all(path.join("system/applications")).unwrap();
        let sandbox = Self(path);
        sandbox.script("zenity", "if [ \"$1\" = --error ]; then exit 0; fi\nprintf '%s\\0' \"$@\" > \"$CAPTURE.menu\"\nprintf '%s\\n' \"$CHOICE\"\nexit \"${DIALOG_EXIT:-0}\"\n");
        sandbox
    }

    fn script(&self, name: &str, body: &str) {
        let path = self.0.join(name);
        fs::write(&path, format!("#!/bin/sh\n{body}")).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn run(&self, choice: &str, urls: &[&str], extra: &[(&str, &str)]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_browser-relay"))
            .args(urls)
            .current_dir(&self.0)
            .env_clear()
            .env("PATH", &self.0)
            .env("HOME", &self.0)
            .env("XDG_DATA_HOME", self.0.join("data"))
            .env("XDG_DATA_DIRS", self.0.join("system"))
            .env("XDG_CONFIG_HOME", self.0.join("config"))
            .env("XDG_CURRENT_DESKTOP", "KDE")
            .env("CHOICE", choice)
            .env("BROWSER_RELAY_DIALOG", "zenity")
            .env("WAYLAND_DISPLAY", "test")
            .env("DISPLAY", ":test")
            .env("CAPTURE", self.0.join("capture"))
            .envs(extra.iter().copied())
            .output()
            .unwrap()
    }

    fn captured(&self) -> Vec<u8> {
        // GIO reports a successful spawn before a desktop launcher finishes.
        for _ in 0..100 {
            if let Ok(data) = fs::read(self.0.join("capture"))
                && !data.is_empty()
            {
                return data;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("No browser capture");
    }

    fn desktop(&self, id: &str, name: &str, exec: &str, extra: &str) {
        fs::write(self.0.join("data/applications").join(id), format!(
            "[Desktop Entry]\nType=Application\nName={name}\nExec={exec}\nIcon=web-browser\nMimeType=x-scheme-handler/http;x-scheme-handler/https;\n{extra}\n"
        )).unwrap();
    }

    fn menu(&self) -> Vec<String> {
        let output = self.run("", &["https://example.org"], &[("DIALOG_EXIT", "1")]);
        assert!(output.status.success(), "{output:?}");
        fs::read(self.0.join("capture.menu"))
            .unwrap()
            .split(|b| *b == 0)
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect()
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn browsers_receive_exact_arguments_without_shell_evaluation() {
    for (choice, binary) in [
        ("Chromium", "chromium"),
        ("Firefox", "firefox"),
        ("Chromium", "chromium-browser"),
        ("Firefox", "firefox-esr"),
    ] {
        let s = Sandbox::new();
        s.script(binary, "printf '%s\\0' \"$@\" > \"$CAPTURE\"\n");
        let links = [
            "https://example.org/a b?x=';&y=$(touch nope)",
            "https://example.org/é#anchor",
        ];
        let result = s.run(choice, &links, &[]);
        assert!(result.status.success(), "{:?}", result);
        assert_eq!(
            s.captured(),
            format!("--\0{}\0{}\0", links[0], links[1]).as_bytes()
        );
    }
}

#[test]
fn copy_keeps_full_urls_and_joins_with_newlines() {
    let s = Sandbox::new();
    s.script("wl-copy", "/bin/cat > \"$CAPTURE\"\n");
    let long = format!("https://example.org/{}?a=1&b=2", "x".repeat(500));
    let result = s.run(
        "Copy to clipboard",
        &[&long, "https://example.org/two"],
        &[],
    );
    assert!(result.status.success());
    assert_eq!(
        s.captured(),
        format!("{long}\nhttps://example.org/two").as_bytes()
    );
}

#[test]
fn failed_wayland_copy_falls_back_to_x11() {
    let s = Sandbox::new();
    s.script("wl-copy", "exit 1\n");
    s.script(
        "xclip",
        "printf '%s\\n' \"$@\" > \"$CAPTURE.args\"\n/bin/cat > \"$CAPTURE\"\n",
    );
    assert!(
        s.run("Copy to clipboard", &["https://example.org"], &[])
            .status
            .success()
    );
    assert_eq!(s.captured(), b"https://example.org");
    assert_eq!(
        fs::read_to_string(s.0.join("capture.args")).unwrap(),
        "-selection\nclipboard\n"
    );
}

#[test]
fn xsel_is_supported_without_wayland_helper_or_xclip() {
    let s = Sandbox::new();
    s.script("xsel", "/bin/cat > \"$CAPTURE\"\n");
    assert!(
        s.run("Copy to clipboard", &["https://example.org"], &[])
            .status
            .success()
    );
    assert_eq!(s.captured(), b"https://example.org");
}

#[test]
fn cancel_never_launches_a_browser() {
    let s = Sandbox::new();
    s.script("firefox", "printf launched > \"$CAPTURE\"\n");
    assert!(
        s.run("Firefox", &["https://example.org"], &[("DIALOG_EXIT", "1")])
            .status
            .success()
    );
    assert!(!s.0.join("capture").exists());
}

#[test]
fn missing_browser_and_failed_dialog_are_errors() {
    let s = Sandbox::new();
    assert!(
        !s.run("Firefox", &["https://example.org"], &[])
            .status
            .success()
    );
    assert!(
        !s.run("", &["https://example.org"], &[("DIALOG_EXIT", "2")])
            .status
            .success()
    );
}

#[test]
fn rejects_browser_flags_even_after_double_dash() {
    let s = Sandbox::new();
    assert!(
        !s.run("Chromium", &["--", "--remote-debugging-port=9222"], &[])
            .status
            .success()
    );
}

#[test]
fn no_links_shows_help_without_a_dialog() {
    let s = Sandbox::new();
    let result = s.run("", &[], &[("DIALOG_EXIT", "2")]);
    assert!(result.status.success());
    assert!(String::from_utf8_lossy(&result.stdout).contains("Usage:"));
}

#[test]
fn discovers_desktop_browsers_and_excludes_non_browsers_and_relays() {
    let s = Sandbox::new();
    for binary in [
        "brave",
        "vivaldi",
        "hidden",
        "not-web",
        "browser-relay",
        "xdg-open",
    ] {
        s.script(binary, "printf '%s\\0' \"$@\" > \"$CAPTURE\"\n");
    }
    std::os::unix::fs::symlink(s.0.join("browser-relay"), s.0.join("relay-alias")).unwrap();
    s.desktop("alias.desktop", "Relay alias", "relay-alias %U", "");
    s.desktop("brave.desktop", "Brave", "brave %U", "");
    s.desktop("vivaldi.desktop", "Vivaldi", "vivaldi %u", "");
    s.desktop("duplicate.desktop", "Duplicate Brave", "brave %U", "");
    s.desktop(
        "browser-relay.desktop",
        "Browser Relay",
        "browser-relay %U",
        "",
    );
    s.desktop("another-relay.desktop", "Indirect", "xdg-open %U", "");
    s.desktop(
        "wrapper.desktop",
        "Wrapper",
        "/usr/bin/env browser-relay %U",
        "",
    );
    s.desktop("hidden.desktop", "Hidden", "hidden %U", "Hidden=true");
    s.desktop(
        "no-display.desktop",
        "No display",
        "hidden --private %U",
        "NoDisplay=true",
    );
    s.desktop(
        "other-desktop.desktop",
        "Other desktop",
        "hidden --other %U",
        "OnlyShowIn=GNOME;",
    );
    s.desktop("missing.desktop", "Missing", "absent-browser %U", "");
    s.desktop(
        "try-exec.desktop",
        "Missing TryExec",
        "hidden --try %U",
        "TryExec=absent-browser",
    );
    s.desktop(
        "not-web.desktop",
        "Editor",
        "not-web %U",
        "MimeType=text/plain;",
    );
    s.desktop("no-uri.desktop", "No URI support", "hidden", "");
    let menu = s.menu();
    for name in ["Brave", "Vivaldi", "Copy to clipboard"] {
        assert!(menu.iter().any(|m| m == name), "{menu:?}");
    }
    for name in [
        "Relay alias",
        "Duplicate Brave",
        "Browser Relay",
        "Indirect",
        "Wrapper",
        "Hidden",
        "No display",
        "Other desktop",
        "Missing",
        "Missing TryExec",
        "Editor",
        "No URI support",
    ] {
        assert!(!menu.iter().any(|m| m == name), "{menu:?}");
    }
    assert!(
        !s.0.join("capture").exists(),
        "Discovery must not launch anything"
    );
}

#[test]
fn desktop_exec_preserves_quoted_arguments_and_urls() {
    let s = Sandbox::new();
    s.script("custom browser", "printf '%s\\0' \"$@\" > \"$CAPTURE\"\n");
    s.desktop(
        "custom.desktop",
        "Custom Browser",
        &format!(
            "\"{}\" --profile \"Work profile\" %U",
            s.0.join("custom browser").display()
        ),
        "",
    );
    let urls = [
        "https://example.org/a?literal=$(touch nope);&quote='",
        "https://example.org/é%20space#anchor",
    ];
    let result = s.run("1", &urls, &[]);
    assert!(result.status.success(), "{result:?}");
    assert_eq!(
        s.captured(),
        format!("--profile\0Work profile\0{}\0{}\0", urls[0], urls[1]).as_bytes()
    );
    assert!(!s.0.join("nope").exists());
}

#[test]
fn desktop_single_url_field_launches_each_link_and_local_files() {
    let s = Sandbox::new();
    s.script("custom", "printf '%s\\n' \"$@\" >> \"$CAPTURE\"\n");
    s.desktop("custom.desktop", "Custom", "custom %u", "");
    let file = s.0.join("local file.html");
    fs::write(&file, "").unwrap();
    let output = s.run(
        "Custom",
        &["https://example.org/", file.to_str().unwrap()],
        &[],
    );
    assert!(output.status.success(), "{output:?}");
    for _ in 0..100 {
        let captured = String::from_utf8(s.captured()).unwrap();
        let lines: Vec<_> = captured.lines().collect();
        if lines.len() == 2 {
            assert!(lines.contains(&"https://example.org/"));
            assert!(lines.contains(&file.to_str().unwrap()), "{captured}");
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    panic!("Both links must be launched");
}

#[test]
fn user_hidden_registration_overrides_system_and_path_fallback() {
    let s = Sandbox::new();
    s.script("firefox", "exit 0\n");
    s.desktop("firefox.desktop", "Firefox", "firefox %U", "");
    fs::rename(
        s.0.join("data/applications/firefox.desktop"),
        s.0.join("system/applications/firefox.desktop"),
    )
    .unwrap();
    fs::write(
        s.0.join("data/applications/firefox.desktop"),
        "[Desktop Entry]\nHidden=true\n",
    )
    .unwrap();
    assert!(!s.menu().iter().any(|m| m == "Firefox"));
}

#[test]
fn desktop_registration_deduplicates_path_fallback() {
    let s = Sandbox::new();
    s.script("firefox", "exit 0\n");
    s.desktop("firefox.desktop", "Firefox", "firefox %U", "");
    assert_eq!(s.menu().iter().filter(|m| *m == "Firefox").count(), 1);
}

#[test]
fn packaged_browser_exec_keeps_wrapper_arguments() {
    let s = Sandbox::new();
    s.script("flatpak", "printf '%s\\0' \"$@\" > \"$CAPTURE\"\n");
    s.desktop(
        "org.example.Browser.desktop",
        "Packaged Browser",
        "flatpak run --branch=stable org.example.Browser -- @@u %U @@",
        "",
    );
    let result = s.run("Packaged Browser", &["https://example.org/"], &[]);
    assert!(result.status.success(), "{result:?}");
    assert_eq!(
        s.captured(),
        b"run\0--branch=stable\0org.example.Browser\0--\0@@u\0https://example.org/\0@@\0"
    );
}

#[test]
fn snap_registrations_do_not_add_path_fallbacks() {
    let s = Sandbox::new();
    for (binary, id, name) in [
        ("firefox", "firefox_firefox.desktop", "Mozilla Firefox"),
        (
            "chromium",
            "chromium_chromium.desktop",
            "Chromium Web Browser",
        ),
    ] {
        s.script(binary, "exit 0\n");
        s.desktop(
            id,
            name,
            &format!("/usr/bin/env SNAP_NAME={binary} {binary} %U"),
            "",
        );
    }
    let menu = s.menu();
    assert!(menu.iter().any(|m| m == "Mozilla Firefox"));
    assert!(menu.iter().any(|m| m == "Chromium Web Browser"));
    assert!(!menu.iter().any(|m| m == "Firefox" || m == "Chromium"));
}

#[test]
fn dbus_browser_service() {
    use gtk::{gio, glib, prelude::*};
    let Some(root) = std::env::var_os("RELAY_DBUS_FIXTURE") else {
        return;
    };
    let app = gio::Application::new(
        Some("org.example.RelayFixture"),
        gio::ApplicationFlags::HANDLES_OPEN | gio::ApplicationFlags::IS_SERVICE,
    );
    app.connect_open(move |app, files, _| {
        // A delayed activation exposes the old early-exit race.
        std::thread::sleep(std::time::Duration::from_millis(200));
        fs::write(
            PathBuf::from(&root).join("dbus-capture"),
            files
                .iter()
                .map(|f| f.uri().to_string())
                .collect::<Vec<_>>()
                .join("\n"),
        )
        .unwrap();
        let app = app.clone();
        glib::timeout_add_local_once(std::time::Duration::from_millis(100), move || app.quit());
    });
    let weak = app.downgrade();
    glib::timeout_add_local_once(std::time::Duration::from_secs(10), move || {
        if let Some(app) = weak.upgrade() {
            app.quit();
        }
    });
    app.run_with_args(&["relay-fixture"]);
}

#[test]
fn dbus_activation_waits_for_delivery() {
    if let Some(root) = std::env::var_os("RELAY_DBUS_FIXTURE") {
        let s = std::mem::ManuallyDrop::new(Sandbox(PathBuf::from(root)));
        let bus = std::env::var("DBUS_SESSION_BUS_ADDRESS").unwrap();
        let output = s.run(
            "D-Bus Browser",
            &["https://example.org/private?exact=1#fragment"],
            &[("DBUS_SESSION_BUS_ADDRESS", &bus)],
        );
        assert!(output.status.success(), "{output:?}");
        assert_eq!(
            fs::read_to_string(s.0.join("dbus-capture")).unwrap(),
            "https://example.org/private?exact=1#fragment"
        );
        return;
    }
    let s = Sandbox::new();
    s.desktop(
        "org.example.RelayFixture.desktop",
        "D-Bus Browser",
        "/bin/false %U",
        "DBusActivatable=true",
    );
    let services = s.0.join("data/dbus-1/services");
    fs::create_dir_all(&services).unwrap();
    fs::write(services.join("org.example.RelayFixture.service"), format!("[D-BUS Service]\nName=org.example.RelayFixture\nExec={} --exact dbus_browser_service --nocapture\n", std::env::current_exe().unwrap().display())).unwrap();
    let output = Command::new("dbus-run-session")
        .arg("--")
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "dbus_activation_waits_for_delivery",
            "--nocapture",
        ])
        .env("RELAY_DBUS_FIXTURE", &s.0)
        .env("XDG_DATA_HOME", s.0.join("data"))
        .env("XDG_DATA_DIRS", s.0.join("system"))
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
}

#[test]
fn plain_browser_arguments_keep_browser_interpretation() {
    for desktop in [false, true] {
        let s = Sandbox::new();
        s.script("firefox", "printf '%s\\0' \"$@\" > \"$CAPTURE\"\n");
        if desktop {
            s.desktop("firefox.desktop", "Firefox", "firefox -- %U", "");
        }
        let inputs = [
            "example.com",
            "example.com:8080/path?x=1#part",
            "example.com:abc",
            "some search terms",
            "index.html",
            "https://",
            "mailto:user@example.com",
        ];
        let output = s.run("Firefox", &inputs, &[]);
        assert!(output.status.success(), "{output:?}");
        assert_eq!(
            s.captured(),
            b"--\0https://example.com\0https://example.com:8080/path?x=1#part\0example.com:abc\0some search terms\0index.html\0https://\0mailto:user@example.com\0"
        );
        fs::remove_file(s.0.join("capture")).unwrap();
        fs::write(s.0.join("index.html"), "local page").unwrap();
        fs::write(s.0.join("local page.html"), "local page").unwrap();
        let output = s.run("Firefox", &["index.html", "local page.html"], &[]);
        assert!(output.status.success(), "{output:?}");
        let expected = if desktop {
            format!(
                "--\0{}\0{}\0",
                s.0.join("index.html").display(),
                s.0.join("local page.html").display()
            )
        } else {
            format!(
                "--\0{}\0{}\0",
                url::Url::from_file_path(s.0.join("index.html")).unwrap(),
                url::Url::from_file_path(s.0.join("local page.html")).unwrap()
            )
        };
        assert_eq!(s.captured(), expected.as_bytes());
    }
}

#[test]
fn rejected_desktop_entries_do_not_suppress_working_path_browsers() {
    for extra in [
        "MimeType=text/html;",
        "Exec=missing-browser %U",
        "TryExec=missing-browser",
    ] {
        for binary in ["firefox", "chromium"] {
            let s = Sandbox::new();
            s.script(binary, "printf '%s\\0' \"$@\" > \"$CAPTURE\"\n");
            s.desktop(
                &format!("{binary}.desktop"),
                "Rejected registration",
                &format!("{binary} %U"),
                extra,
            );
            let name = if binary == "firefox" {
                "Firefox"
            } else {
                "Chromium"
            };
            assert!(s.menu().iter().any(|m| m == name), "{binary}: {extra}");
            assert!(s.run(name, &["https://example.org"], &[]).status.success());
            assert_eq!(s.captured(), b"--\0https://example.org\0");
        }
    }
}

#[test]
fn relative_path_entries_cannot_hijack_desktop_launches() {
    for path in [".", "", "bin", ":.", "/dev/null:"] {
        let s = Sandbox::new();
        let trusted = s.0.join("trusted");
        fs::create_dir(&trusted).unwrap();
        fs::create_dir(s.0.join("bin")).unwrap();
        s.script("firefox", "printf hijacked > \"$CAPTURE\"\n");
        s.script("bin/firefox", "printf hijacked > \"$CAPTURE\"\n");
        s.script("trusted/firefox", "printf trusted > \"$CAPTURE\"\n");
        // A trusted zenity must be found after the ignored relative directories.
        fs::copy(s.0.join("zenity"), trusted.join("zenity")).unwrap();
        s.desktop("firefox.desktop", "Firefox", "firefox %U", "");
        let search = format!("{path}:{}", trusted.display());
        let result = s.run("Firefox", &["https://example.org"], &[("PATH", &search)]);
        assert!(result.status.success(), "{path}: {result:?}");
        assert_eq!(s.captured(), b"trusted", "{path}");
    }
}

#[test]
fn entirely_relative_path_cannot_launch_cwd_helpers() {
    for path in ["", ".", ":", "bin:.", "/dev/null:"] {
        let s = Sandbox::new();
        let result = s.run("Firefox", &["https://example.org"], &[("PATH", path)]);
        assert!(!result.status.success(), "{path}: {result:?}");
        assert!(
            !s.0.join("capture.menu").exists(),
            "cwd zenity ran for {path}"
        );
    }
}

#[test]
fn terminal_without_tty_fails_before_registry_access() {
    let s = Sandbox::new();
    // If discovery opens this desktop file, it blocks indefinitely. A fast
    // validation failure must not touch it at all.
    let status = Command::new("mkfifo")
        .arg(s.0.join("data/applications/firefox.desktop"))
        .status()
        .unwrap();
    assert!(status.success());
    let mut child = Command::new(env!("CARGO_BIN_EXE_browser-relay"))
        .args(["--terminal", "https://example.org"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .env_clear()
        .env("PATH", &s.0)
        .env("XDG_DATA_HOME", s.0.join("data"))
        .env("XDG_DATA_DIRS", s.0.join("system"))
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while child.try_wait().unwrap().is_none() {
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("Noninteractive terminal choice reached browser discovery");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("interactive terminal"));
}

#[test]
fn quoted_terminal_browser_names_are_accepted() {
    let s = Sandbox::new();
    s.script("firefox", "printf '%s\\0' \"$@\" > \"$CAPTURE\"\n");
    assert!(
        s.run("\"Firefox\"", &["https://example.org"], &[])
            .status
            .success()
    );
    assert_eq!(s.captured(), b"--\0https://example.org\0");
}

#[test]
fn existing_local_names_are_never_rewritten_as_remote_hosts() {
    for desktop in [false, true] {
        let s = Sandbox::new();
        s.script("firefox", "printf '%s\\0' \"$@\" > \"$CAPTURE\"\n");
        if desktop {
            s.desktop("firefox.desktop", "Firefox", "firefox -- %U", "");
        }
        for name in ["github.com", "notes.md", "invoice.zip"] {
            fs::write(s.0.join(name), "private local file").unwrap();
        }
        fs::create_dir(s.0.join("example.org")).unwrap();
        std::os::unix::fs::symlink("missing-target", s.0.join("dangling.zip")).unwrap();
        let local = [
            "github.com",
            "notes.md",
            "invoice.zip",
            "example.org",
            "dangling.zip",
        ];
        assert!(s.run("Firefox", &local, &[]).status.success());
        let expected: Vec<_> = local
            .iter()
            .map(|name| {
                if desktop {
                    s.0.join(name).to_str().unwrap().to_owned()
                } else {
                    url::Url::from_file_path(s.0.join(name))
                        .unwrap()
                        .to_string()
                }
            })
            .collect();
        assert_eq!(
            s.captured(),
            format!("--\0{}\0", expected.join("\0")).as_bytes()
        );
        fs::remove_file(s.0.join("capture")).unwrap();
        assert!(
            s.run(
                "Firefox",
                &[
                    "https://github.com",
                    "https://notes.md",
                    "https://invoice.zip"
                ],
                &[]
            )
            .status
            .success()
        );
        assert_eq!(
            s.captured(),
            b"--\0https://github.com\0https://notes.md\0https://invoice.zip\0"
        );
    }
}

#[test]
fn canonical_launches_deduplicate_without_merging_browser_profiles() {
    let s = Sandbox::new();
    s.script("firefox-real", "exit 0\n");
    std::os::unix::fs::symlink(s.0.join("firefox-real"), s.0.join("firefox")).unwrap();
    s.desktop("a.desktop", "Firefox", "firefox %u", "");
    s.desktop(
        "b.desktop",
        "Duplicate",
        &format!("{} %U", s.0.join("firefox-real").display()),
        "",
    );
    s.desktop(
        "work.desktop",
        "Work Firefox",
        "firefox --profile work %U",
        "",
    );
    s.desktop(
        "private.desktop",
        "Private Firefox",
        "firefox --private-window %u",
        "",
    );
    s.script("flatpak", "exit 0\n");
    s.desktop(
        "one.desktop",
        "Packaged One",
        "flatpak run org.example.One %U",
        "",
    );
    s.desktop(
        "two.desktop",
        "Packaged Two",
        "flatpak run org.example.Two %U",
        "",
    );
    let menu = s.menu();
    for name in [
        "Firefox",
        "Work Firefox",
        "Private Firefox",
        "Packaged One",
        "Packaged Two",
    ] {
        assert_eq!(
            menu.iter().filter(|entry| *entry == name).count(),
            1,
            "{menu:?}"
        );
    }
    assert!(!menu.iter().any(|name| name == "Duplicate"), "{menu:?}");
}
