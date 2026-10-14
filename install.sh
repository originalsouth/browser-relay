#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
make_default=true
desktop_shortcut=false
for arg in "$@"; do
    case "$arg" in
        --no-default) make_default=false ;;
        --desktop) desktop_shortcut=true ;;
        *) echo "Usage: ./install.sh [--no-default] [--desktop]" >&2; exit 2 ;;
    esac
done
for tool in cargo pkg-config xdg-settings xdg-mime; do
    command -v "$tool" >/dev/null || { echo "Missing dependency: $tool" >&2; exit 1; }
done
pkg-config --exists gtk4 || { echo "Missing GTK 4 development libraries." >&2; exit 1; }
bin="$HOME/.local/bin/browser-relay"
applications="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
state="${XDG_STATE_HOME:-$HOME/.local/state}/browser-relay"
icons="${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor"
for path in "$bin" "$applications" "$state"; do
    if [[ $path != /* || $path == *$'\n'* || $path == *$'\r'* || $path == *$'\t'* || $path == *=* ]]; then
        echo "Installation paths must be absolute and contain no newlines, tabs, or '='." >&2
        exit 1
    fi
done
cargo build --release --locked
mkdir -p -- "$(dirname -- "$bin")" "$applications" "$state"
# Save once, so reinstalling never replaces the original preferences with ourselves.
if [[ $make_default == true && ! -f "$state/previous-defaults" ]]; then
    backup=$(mktemp "$state/previous-defaults.XXXXXX")
    trap 'rm -f -- "${backup:-}"' EXIT
    browser=$(xdg-settings get default-web-browser)
    if [[ $browser == browser-relay.desktop ]]; then
        echo "Already the default, but no restoration record exists. Select another browser first." >&2
        exit 1
    fi
    printf 'browser\t%s\n' "$browser" > "$backup"
    for mime in x-scheme-handler/http x-scheme-handler/https text/html application/xhtml+xml x-scheme-handler/about x-scheme-handler/unknown; do
        previous=$(xdg-mime query default "$mime")
        printf '%s\t%s\n' "$mime" "$previous" >> "$backup"
    done
    mv -- "$backup" "$state/previous-defaults"
fi
# Replace atomically, including when an older copy is still running.
tmp_bin=$(mktemp "${bin}.XXXXXX")
trap 'rm -f -- "${tmp_bin:-}" "${backup:-}"' EXIT
install -m 755 target/release/browser-relay "$tmp_bin"
mv -f -- "$tmp_bin" "$bin"
# Apply both Exec quoting and desktop-entry string escaping.
exec_path=${bin//\\/\\\\}
exec_path=${exec_path//\"/\\\"}
exec_path=${exec_path//\`/\\\`}
exec_path=${exec_path//\$/\\\$}
exec_path=${exec_path//\\/\\\\}
exec_path=${exec_path//%/%%}
cat > "$applications/browser-relay.desktop" <<EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Browser Relay
Comment=Choose Chromium, Firefox, or copy a link
Exec="$exec_path" --prompt -- %U
Icon=browser-relay
StartupWMClass=browser-relay
Terminal=false
Categories=Network;WebBrowser;
MimeType=x-scheme-handler/http;x-scheme-handler/https;text/html;application/xhtml+xml;
StartupNotify=false
EOF
if [[ $desktop_shortcut == true ]]; then
    desktop_dir=$(xdg-user-dir DESKTOP 2>/dev/null || printf '%s/Desktop' "$HOME")
    if [[ $desktop_dir != /* || $desktop_dir == "$HOME" ]]; then
        echo "No dedicated desktop directory configured." >&2
        exit 1
    fi
    install -Dm755 "$applications/browser-relay.desktop" "$desktop_dir/browser-relay.desktop"
    printf '%s\n' "$desktop_dir/browser-relay.desktop" > "$state/desktop-shortcut"
    echo "Desktop shortcut: $desktop_dir/browser-relay.desktop"
fi
install -Dm644 assets/browser-relay.svg "$icons/scalable/apps/browser-relay.svg"
if command -v gtk-update-icon-cache >/dev/null; then
    gtk-update-icon-cache -f -t "$icons" >/dev/null 2>&1 || true
fi
if command -v desktop-file-validate >/dev/null; then
    desktop-file-validate "$applications/browser-relay.desktop"
fi
if command -v update-desktop-database >/dev/null; then
    update-desktop-database "$applications"
fi
if [[ $make_default == true ]]; then
    xdg-settings set default-web-browser browser-relay.desktop
    xdg-mime default browser-relay.desktop x-scheme-handler/http x-scheme-handler/https
    for mime in x-scheme-handler/http x-scheme-handler/https; do
        [[ $(xdg-mime query default "$mime") == browser-relay.desktop ]] || {
            echo "Desktop did not accept the default for $mime. Select Browser Relay in System Settings." >&2
            exit 1
        }
    done
    echo "Browser Relay is now your default browser. Previous defaults saved in $state/previous-defaults"
else
    echo "Installed without changing your default browser."
fi
printf 'Try: xdg-open https://example.com\nUninstall: %s/uninstall.sh\n' "$PWD"
