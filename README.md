# Browser Relay

A Linux link handler written in Rust and GTK 4. It asks whether to open a link
in Chromium or Firefox, or copy it to the clipboard.

[![Browser Relay preview](assets/preview.png)](https://github.com/originalsouth/browser-relay)

## Install

Build dependencies: Rust/Cargo, `pkg-config`, and GTK 4 development files
(`libgtk-4-dev` on Debian/Ubuntu; `gtk4` on Arch).

Runtime dependencies: GTK 4, `xdg-utils`, and the browsers you want to use.
Clipboard support requires `wl-copy` on Wayland or `xclip`/`xsel` on X11.
The installer uses Bash.

```sh
git clone https://github.com/originalsouth/browser-relay.git
cd browser-relay
./install.sh
xdg-open 'https://example.com'
```

This installs to `~/.local/bin` and registers Browser Relay as the desktop's
HTTP/HTTPS handler. It affects applications that use the default browser,
including `xdg-open`. Applications that launch a browser directly bypass it;
`BROWSER` can also override desktop preferences.

Installer options:

- `--no-default`: install without changing browser preferences.
- `--desktop`: also add a shortcut to the configured desktop directory.

The desktop shortcut and application-menu entry ask for a link when opened.

## Use

```sh
browser-relay 'https://example.com'
browser-relay --terminal 'https://example.com'
browser-relay --prompt
```

Choose a button, press **1**, **2**, or **3**, or use **Tab** and **Enter**.
**Esc** cancels. The chooser uses a dark theme with violet accents. Missing browsers are disabled;
a failed action leaves the chooser open so you can try another option.

Multiple links are opened together or copied as newline-separated text. Local
file paths and `file:` URLs work too. Links are passed as separate arguments,
without a shell. The clipboard needs a graphical session even in terminal mode.

Browser lookup uses `PATH`: `chromium` or `chromium-browser`, and `firefox` or
`firefox-esr`. The optional `BROWSER_RELAY_DIALOG=zenity` setting uses a basic
Zenity chooser instead of the GTK window.

## Uninstall

Run `./uninstall.sh`. Saved defaults are restored where Browser Relay is still
selected. Later browser choices are preserved. The installed binary, icon, and
shortcuts are removed; the source directory remains.

Desktop files and icons use `XDG_DATA_HOME` (default `~/.local/share`). The
original browser associations are saved once in
`${XDG_STATE_HOME:-~/.local/state}/browser-relay/previous-defaults`.

## Development

`src/main.rs` handles arguments and terminal/Zenity interaction. `src/relay.rs`
launches browsers and clipboard helpers. `src/ui.rs` contains the GTK interface.

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
shellcheck install.sh uninstall.sh
cargo build --release --locked
python3 tests/install.py
```

The routing tests use fake executables; the installer tests use a temporary
home and fake XDG tools. Native GUI tests additionally need Xvfb, xdotool, and
ImageMagick:

```sh
xvfb-run -a -s '-screen 0 1280x1024x24' python3 tests/gui.py
```

These checks do not open your browsers or modify your desktop preferences or
clipboard. The GUI test captures its windows under `/tmp/browser-relay-*.png`.

Licensed under the [MIT license](LICENSE).
