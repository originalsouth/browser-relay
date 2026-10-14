# Browser Relay

A small Linux browser chooser written in Rust with GTK 4. When
`xdg-open` opens a link, a styled native chooser offers **Chromium**, **Firefox**, or
**Copy to clipboard**. Cancel does nothing. Multiple links open together or copy
as newline-separated text.

## Build and install

Requires Rust/Cargo, Bash, `pkg-config`, GTK 4 development libraries,
`xdg-utils`, and your browsers on `PATH`. For example, GTK development files
are in `libgtk-4-dev` on Debian/Ubuntu or `gtk4` on Arch.
Clipboard support uses `wl-copy` from `wl-clipboard` on Wayland, or `xclip`/`xsel`
on X11. If Wayland copying fails and X11 is available, it tries X11.

```sh
cd ~/Projects/browser-relay
./install.sh
xdg-open 'https://example.com'
```

The installer builds a release binary, installs it at
`~/.local/bin/browser-relay`, creates a desktop entry under
`${XDG_DATA_HOME:-~/.local/share}/applications`, and selects it as the default
browser for HTTP/HTTPS. This is a desktop-wide preference: other applications
that honor your default browser will also show the chooser. Applications that
explicitly launch a browser bypass it. A `BROWSER` environment variable may also
override desktop preferences in some `xdg-open` environments.

Previous defaults are recorded once under
`${XDG_STATE_HOME:-~/.local/state}/browser-relay/previous-defaults`. Reinstalling
updates the binary without overwriting that record. To install without changing
the default, use `./install.sh --no-default`.

## Plasma desktop shortcut

Run `./install.sh --no-default --desktop` to add an executable Browser Relay
shortcut to your configured desktop folder. Launching it (or the application
menu entry) asks you to paste a link, then opens the chooser. Dropped/passed URLs
skip the input step. Uninstall removes the desktop shortcut too.

## The chooser

A custom violet relay icon, dark palette, browser icons, and large single-click
buttons. Hover and press states give feedback; Tab and Enter provide keyboard
navigation. Press **1** for Chromium, **2** for Firefox, **3** to copy, or **Esc**
to dismiss. Missing browsers are disabled. Copying shows a brief confirmation;
errors stay in the chooser so you can retry or choose another destination.
The URL preview truncates visually and exposes the full links in its tooltip.

The SVG icon and CSS are in `assets/` and embedded into the Rust binary. The
installer also installs the icon into the desktop icon theme. Zenity is optional:
`BROWSER_RELAY_DIALOG=zenity browser-relay URL` uses the original simple chooser.

## Direct use

```sh
cargo run -- 'https://example.com'
cargo run -- 'https://example.com/one' 'https://example.com/two'
cargo run -- --terminal 'https://example.com'
cargo run -- --help
```

The desktop dialog needs an active graphical session. `--terminal` provides an
interactive numbered chooser; clipboard copying still needs a desktop session.
Browser detection tries `chromium` then `chromium-browser`, and `firefox` then
`firefox-esr`. URLs are passed as individual arguments without shell evaluation.
Local HTML paths and `file:` URLs are also supported. Controls and arguments
beginning with `-` are rejected. Long links are shortened only in the preview;
the full original link is opened or copied.

## Uninstall

```sh
./uninstall.sh
```

Restores recorded defaults still assigned to Browser Relay and preserves browser
choices changed since installation. Associations that originally had no default
fall back to the desktop's available handlers after the desktop entry is removed.
The source directory is retained.

## Checks

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
shellcheck install.sh uninstall.sh
cargo build --release --locked
python3 tests/install.py
# Optional native GUI checks (Xvfb, xdotool, ImageMagick):
xvfb-run -a -s "-screen 0 1280x1024x24" python3 tests/gui.py
```

Routing integration tests use the Zenity fallback with fake dialog, browser,
and clipboard executables; they do not
open browsers, display dialogs, or change your clipboard. The Python installer
test uses a temporary home and fake XDG commands to verify installation,
reinstallation, and restoration without changing desktop preferences.

Desktop integration follows the [freedesktop Exec specification](https://specifications.freedesktop.org/desktop-entry-spec/latest/exec-variables.html).
