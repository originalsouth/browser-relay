"""Native chooser smoke test. Run with: xvfb-run -a -s "-screen 0 1280x1024x24" python3 tests/gui.py"""
import os
from pathlib import Path
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
BINARY = ROOT / 'target/debug/browser-relay'
with tempfile.TemporaryDirectory(prefix='browser-relay-ui-') as temp:
    folder = Path(temp)
    capture = folder / 'capture'
    for name in ('chromium', 'firefox'):
        p = folder / name
        p.write_text('#!/bin/sh\nprintf "%s\\0" "$@" > "$CAPTURE"\nexit "${BROWSER_EXIT:-0}"\n')
        p.chmod(0o755)
    p = folder / 'xclip'
    p.write_text('#!/bin/sh\ncat > "$CAPTURE"\n')
    p.chmod(0o755)
    env = dict(os.environ, PATH=f'{folder}:/usr/bin', GDK_BACKEND='x11',
               GSK_RENDERER='cairo', CAPTURE=str(capture), GTK_A11Y='none')
    env.pop('WAYLAND_DISPLAY', None)
    env.pop('BROWSER_RELAY_DIALOG', None)
    link = 'https://github.com/originalsouth/browser-relay'

    def start(extra=None, links=None):
        proc = subprocess.Popen([str(BINARY), *(links or [link])], env=env | (extra or {}),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            found = subprocess.run(['xdotool', 'search', '--onlyvisible', '--pid', str(proc.pid),
                                    '--name', '^Browser Relay$'], capture_output=True, text=True)
            if found.returncode == 0:
                window = found.stdout.strip().splitlines()[0]
                subprocess.run(['xdotool', 'windowfocus', '--sync', window], check=True)
                time.sleep(.2)
                return proc, window
            if proc.poll() is not None:
                raise AssertionError(proc.communicate())
            time.sleep(.05)
        proc.kill()
        raise AssertionError('Chooser did not become visible')

    def key(value):
        subprocess.run(['xdotool', 'key', '--clearmodifiers', value], check=True)

    def finish(proc):
        out, err = proc.communicate(timeout=5)
        assert proc.returncode == 0, (out, err)
        assert b'CSS' not in err and b'CRITICAL' not in err, err

    proc, window = start()
    subprocess.run(['import', '-window', window, '/tmp/browser-relay-preview.png'], check=True)
    key('Escape')
    finish(proc)
    assert not capture.exists()

    for shortcut in ('1', '2'):
        proc, _ = start()
        key(shortcut)
        finish(proc)
        assert capture.read_bytes() == f'--\0{link}\0'.encode()
        capture.unlink()

    proc, window = start(links=[link, 'https://example.org/second'])
    key('3')
    time.sleep(.2)
    subprocess.run(['import', '-window', window, '/tmp/browser-relay-copied.png'], check=True)
    finish(proc)
    assert capture.read_text() == link + '\nhttps://example.org/second'
    capture.unlink()

    proc, window = start({'BROWSER_EXIT': '1'})
    key('1')
    time.sleep(.5)
    assert proc.poll() is None, 'An action failure should keep the chooser open'
    key('3')
    finish(proc)
    assert capture.read_text() == link
    capture.unlink()
    proc, _ = start(links=['--prompt'])
    key('Escape')
    finish(proc)
    assert not capture.exists()
    proc, _ = start(links=['--prompt'])
    subprocess.run(['xdotool', 'type', '--clearmodifiers', link], check=True)
    key('Return')
    time.sleep(.3)
    found = subprocess.check_output(['xdotool', 'search', '--onlyvisible', '--pid', str(proc.pid),
                                     '--name', '^Browser Relay$'], text=True).strip().splitlines()[0]
    subprocess.run(['xdotool', 'windowfocus', '--sync', found], check=True)
    key('3')
    finish(proc)
    assert capture.read_text() == link
    print('Desktop launcher input and cancellation passed.')
    print('Native UI: cancellation, browser shortcuts, clipboard, and error recovery passed.')
