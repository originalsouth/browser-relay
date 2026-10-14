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
        let sandbox = Self(path);
        sandbox.script("zenity", "if [ \"$1\" = --error ]; then exit 0; fi\nprintf '%s\\n' \"$CHOICE\"\nexit \"${DIALOG_EXIT:-0}\"\n");
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
            .env_clear()
            .env("PATH", &self.0)
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
        fs::read(self.0.join("capture")).unwrap()
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
