"""Exercise installation/restoration in a temporary home with fake XDG tools."""
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
with tempfile.TemporaryDirectory(prefix="browser-relay-install-") as directory:
    base = Path(directory)
    home = base / 'home with spaces'
    home.mkdir()
    fake = base / 'tools'
    fake.mkdir()
    state = base / 'settings.json'
    original = {
        'browser': 'firefox.desktop',
        'x-scheme-handler/http': 'firefox.desktop',
        'x-scheme-handler/https': 'chromium.desktop',
        'text/html': 'editor.desktop',
        'application/xhtml+xml': 'firefox.desktop',
        'x-scheme-handler/about': '',
        'x-scheme-handler/unknown': '',
    }
    state.write_text(json.dumps(original))
    helper = f'''#!/usr/bin/python3
import json, pathlib, sys
p = pathlib.Path({str(state)!r})
s = json.loads(p.read_text())
a = sys.argv[1:]
if pathlib.Path(sys.argv[0]).name == 'xdg-settings':
    if a[0] == 'get': print(s['browser'])
    else:
        s['browser'] = a[2]
        for key in ['x-scheme-handler/http', 'x-scheme-handler/https', 'text/html']:
            s[key] = a[2]
else:
    if a[0] == 'query': print(s.get(a[2], ''))
    else:
        for key in a[2:]: s[key] = a[1]
p.write_text(json.dumps(s))
'''
    for name in ['xdg-settings', 'xdg-mime']:
        path = fake / name
        path.write_text(helper)
        path.chmod(0o755)
    # The real build is checked separately; avoid depending on Cargo's HOME here.
    cargo = fake / 'cargo'
    cargo.write_text('#!/bin/sh\nexit 0\n')
    cargo.chmod(0o755)
    env = dict(os.environ, HOME=str(home), PATH=f'{fake}:{os.environ["PATH"]}',
               XDG_DATA_HOME=str(home / 'data'), XDG_STATE_HOME=str(home / 'state'))
    def run(script, *args):
        subprocess.run([str(ROOT / script), *args], cwd=ROOT, env=env, check=True)
    def settings():
        return json.loads(state.read_text())
    desktop_tool = fake / 'xdg-user-dir'
    desktop_tool.write_text('#!/bin/sh\nprintf \'%s/Desktop\\n\' "$HOME"\n')
    desktop_tool.chmod(0o755)
    run('install.sh', '--no-default', '--desktop')
    shortcut = home / 'Desktop/browser-relay.desktop'
    assert shortcut.is_file() and os.access(shortcut, os.X_OK)
    assert settings() == original
    desktop = home / 'data/applications/browser-relay.desktop'
    assert f'Exec="{home}/.local/bin/browser-relay" --prompt -- %U' in desktop.read_text()
    icon = home / 'data/icons/hicolor/scalable/apps/browser-relay.svg'
    assert icon.read_bytes() == (ROOT / 'assets/browser-relay.svg').read_bytes()
    assert 'Icon=browser-relay' in desktop.read_text()
    run('install.sh')
    assert settings()['browser'] == 'browser-relay.desktop'
    saved = home / 'state/browser-relay/previous-defaults'
    backup = saved.read_bytes()
    run('install.sh')
    assert saved.read_bytes() == backup
    # A user's later change must survive the multi-MIME effects of xdg-settings.
    changed = settings()
    changed['x-scheme-handler/https'] = 'other-browser.desktop'
    state.write_text(json.dumps(changed))
    run('uninstall.sh')
    expected = dict(original, **{'x-scheme-handler/https': 'other-browser.desktop'})
    assert settings() == expected, (settings(), expected)
    assert not desktop.exists()
    assert not shortcut.exists()
    assert not icon.exists()
    assert not (home / '.local/bin/browser-relay').exists()
    assert not saved.exists()
    print('Installation, reinstall, paths with spaces, and restoration passed.')
