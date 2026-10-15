"""Native chooser smoke test. Run with: xvfb-run -a -s "-screen 0 1280x1024x24" python3 tests/gui.py"""
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
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

    def find_window(proc, name):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            found = subprocess.run(['xdotool', 'search', '--all', '--onlyvisible', '--pid', str(proc.pid),
                                    '--name', name], capture_output=True, text=True)
            if found.returncode == 0:
                window = found.stdout.strip().splitlines()[0]
                subprocess.run(['xdotool', 'windowfocus', '--sync', window], check=True)
                time.sleep(.2)
                return window
            if proc.poll() is not None:
                raise AssertionError(proc.communicate())
            time.sleep(.05)
        proc.kill()
        raise AssertionError('Window did not become visible: ' + name)

    def start(extra=None, links=None):
        proc = subprocess.Popen([str(BINARY), *(links or [link])], env=env | (extra or {}),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return proc, find_window(proc, '^Browser Relay$')

    def reveal_qr(proc):
        key('4')
        return find_window(proc, '^Link QR code$')

    def hide_qr(proc, parent, close_key='Escape'):
        key(close_key)
        time.sleep(.2)
        found = subprocess.run(['xdotool', 'search', '--all', '--onlyvisible', '--pid', str(proc.pid),
                                '--name', '^Link QR code$'], capture_output=True)
        assert found.returncode != 0, 'QR popup must disappear when dismissed'
        assert proc.poll() is None, 'Dismissing the QR must keep the chooser open'
        subprocess.run(['xdotool', 'windowfocus', '--sync', parent], check=True)
        time.sleep(.1)

    def key(value):
        subprocess.run(['xdotool', 'key', '--clearmodifiers', value], check=True)

    def finish(proc):
        out, err = proc.communicate(timeout=5)
        assert proc.returncode == 0, (out, err)
        assert b'CSS' not in err and b'CRITICAL' not in err, err

    def decode_qr(path):
        result = subprocess.run(['zbarimg', '--quiet', '--raw', '--nodbus', path],
                                capture_output=True, text=True)
        assert result.returncode in (0, 4), result.stderr
        return result.stdout.rstrip('\n')

    proc, window = start()
    subprocess.run(['import', '-window', window, '/tmp/browser-relay-preview.png'], check=True)
    assert decode_qr('/tmp/browser-relay-preview.png') == ''
    popup = reveal_qr(proc)
    subprocess.run(['import', '-window', popup, '/tmp/browser-relay-qr.png'], check=True)
    assert decode_qr('/tmp/browser-relay-qr.png') == link
    hide_qr(proc, window)
    subprocess.run(['import', '-window', window, '/tmp/browser-relay-qr-hidden.png'], check=True)
    assert decode_qr('/tmp/browser-relay-qr-hidden.png') == ''
    reveal_qr(proc)
    hide_qr(proc, window, close_key='Return')
    key('Escape')
    finish(proc)
    assert not capture.exists()

    # Inspection is opt-in; use a local destination, with no external services.
    requests = []
    class Handler(BaseHTTPRequestHandler):
        def do_HEAD(self):
            requests.append((self.path, dict(self.headers)))
            self.send_response(200)
            self.end_headers()
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    inspect_link = f'http://127.0.0.1:{server.server_port}/private?token=secret#fragment'
    proc, window = start(links=[inspect_link])
    time.sleep(.2)
    assert requests == [], 'Displaying the chooser must not inspect the URL'
    key('5')
    popup = find_window(proc, '^Inspect link$')
    deadline = time.monotonic() + 5
    while not requests and time.monotonic() < deadline:
        time.sleep(.05)
    assert len(requests) == 1, requests
    assert requests[0][0] == '/private?token=secret'
    assert not any(key.lower() in ('cookie', 'authorization', 'referer') for key in requests[0][1])
    time.sleep(.5)
    subprocess.run(['import', '-window', popup, '/tmp/browser-relay-inspect-local.png'], check=True)
    geometry = subprocess.check_output(['xdotool', 'getwindowgeometry', '--shell', popup], text=True)
    size = dict(line.split('=', 1) for line in geometry.splitlines() if '=' in line)
    assert int(size['WIDTH']) == 800 and int(size['HEIGHT']) == 720, size
    # Measure the actual popover, not its parent window: a wrapped TextView
    # can otherwise collapse to one character wide while open/close still works.
    def visible_windows():
        return set(subprocess.check_output(
            ['xdotool', 'search', '--onlyvisible', '--pid', str(proc.pid)], text=True).split())
    before = visible_windows()
    subprocess.run(['xdotool', 'mousemove', '--window', popup, '100', '683', 'click', '1'], check=True)
    time.sleep(.2)
    opened = visible_windows() - before
    assert len(opened) == 1, opened
    details_window = opened.pop()
    geometry = subprocess.check_output(['xdotool', 'getwindowgeometry', '--shell', details_window], text=True)
    details_size = dict(line.split('=', 1) for line in geometry.splitlines() if '=' in line)
    assert 580 <= int(details_size['WIDTH']) <= 800, details_size
    assert int(details_size['HEIGHT']) >= 300, details_size
    subprocess.run(['import', '-window', details_window, '/tmp/browser-relay-inspect-details.png'], check=True)
    subprocess.run(['xdotool', 'mousemove', '--window', details_window, '300', '180',
                    'click', '--repeat', '12', '--delay', '25', '5'], check=True)
    time.sleep(.2)
    subprocess.run(['import', '-window', details_window, '/tmp/browser-relay-inspect-details-scrolled.png'], check=True)
    key('Escape')
    time.sleep(.2)
    visible = subprocess.run(['xdotool', 'search', '--all', '--onlyvisible', '--pid', str(proc.pid),
                              '--name', '^Inspect link$'], capture_output=True)
    assert visible.returncode == 0, 'Closing details must keep the dashboard open'
    assert len(requests) == 1, 'Viewing details must not make extra requests'
    key('Escape')
    time.sleep(.2)
    assert proc.poll() is None
    subprocess.run(['xdotool', 'windowfocus', '--sync', window], check=True)
    key('3')
    finish(proc)
    assert capture.read_text() == inspect_link
    capture.unlink()
    server.shutdown()
    server.server_close()

    # The densest permitted code must still decode from the actual rendered UI.
    boundary_link = 'https://example.com/' + 'x' * (106 - len('https://example.com/'))
    proc, window = start(links=[boundary_link])
    popup = reveal_qr(proc)
    subprocess.run(['import', '-window', popup, '/tmp/browser-relay-qr-limit.png'], check=True)
    assert decode_qr('/tmp/browser-relay-qr-limit.png') == boundary_link
    hide_qr(proc, window)
    key('Escape')
    finish(proc)

    # Beyond the limit, no partial QR is displayed and Copy keeps the full URL.
    long_link = boundary_link + 'x'
    proc, window = start(links=[long_link])
    popup = reveal_qr(proc)
    subprocess.run(['import', '-window', popup, '/tmp/browser-relay-qr-warning.png'], check=True)
    assert decode_qr('/tmp/browser-relay-qr-warning.png') == ''
    hide_qr(proc, window)
    key('3')
    finish(proc)
    assert capture.read_text() == long_link
    capture.unlink()

    for shortcut in ('1', '2'):
        proc, _ = start()
        key(shortcut)
        finish(proc)
        assert capture.read_bytes() == f'--\0{link}\0'.encode()
        capture.unlink()

    proc, window = start(links=[link, 'https://example.org/second'])
    popup = reveal_qr(proc)
    subprocess.run(['import', '-window', popup, '/tmp/browser-relay-qr-multiple.png'], check=True)
    assert decode_qr('/tmp/browser-relay-qr-multiple.png') == link
    hide_qr(proc, window)
    key('3')
    time.sleep(.2)
    subprocess.run(['import', '-window', window, '/tmp/browser-relay-copied.png'], check=True)
    finish(proc)
    assert decode_qr('/tmp/browser-relay-copied.png') == ''
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
    found = subprocess.check_output(['xdotool', 'search', '--all', '--onlyvisible', '--pid', str(proc.pid),
                                     '--name', '^Browser Relay$'], text=True).strip().splitlines()[0]
    subprocess.run(['xdotool', 'windowfocus', '--sync', found], check=True)
    key('3')
    finish(proc)
    assert capture.read_text() == link
    print('QR hidden by default; explicit reveal, dismiss, decoding, length limit and multiple links passed.')
    print('Desktop launcher input and cancellation passed.')
    print('Native UI: cancellation, browser shortcuts, clipboard, and error recovery passed.')
