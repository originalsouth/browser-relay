#!/usr/bin/env bash
set -euo pipefail
state="${XDG_STATE_HOME:-$HOME/.local/state}/browser-relay"
applications="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
if [[ -f "$state/previous-defaults" ]]; then
    # Snapshot current associations before xdg-settings modifies several at once.
    declare -A current
    while IFS=$'\t' read -r kind previous; do
        if [[ $kind == browser ]]; then
            current[$kind]=$(xdg-settings get default-web-browser)
        else
            current[$kind]=$(xdg-mime query default "$kind")
        fi
    done < "$state/previous-defaults"
    while IFS=$'\t' read -r kind previous; do
        if [[ $kind == browser && ${current[$kind]} == browser-relay.desktop && -n $previous && $previous != browser-relay.desktop ]]; then
            xdg-settings set default-web-browser "$previous"
        fi
    done < "$state/previous-defaults"
    while IFS=$'\t' read -r kind previous; do
        [[ $kind == browser ]] && continue
        # Preserve preferences changed by the user after installation, even if
        # restoring the browser above changed those MIME associations again.
        restore=${current[$kind]}
        if [[ $restore == browser-relay.desktop ]]; then restore=$previous; fi
        if [[ -n $restore && $restore != browser-relay.desktop ]]; then
            xdg-mime default "$restore" "$kind"
        fi
    done < "$state/previous-defaults"
    rm -- "$state/previous-defaults"
fi
if [[ -f "$state/desktop-shortcut" ]]; then
    IFS= read -r shortcut < "$state/desktop-shortcut"
    rm -f -- "$shortcut" "$state/desktop-shortcut"
fi
rm -f -- "$applications/browser-relay.desktop" "$HOME/.local/bin/browser-relay"
icons="${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor"
rm -f -- "$icons/scalable/apps/browser-relay.svg"
if command -v gtk-update-icon-cache >/dev/null; then
    gtk-update-icon-cache -f -t "$icons" >/dev/null 2>&1 || true
fi
if command -v update-desktop-database >/dev/null; then
    update-desktop-database "$applications"
fi
rmdir -- "$state" 2>/dev/null || true
echo "Browser Relay removed. Saved defaults restored where Browser Relay was still selected."
