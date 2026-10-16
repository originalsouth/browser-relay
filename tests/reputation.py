"""Offline GTK regression: exact/parent ranks, OISD warnings, and update consent.
Run with xvfb-run; requires xdotool, ImageMagick, Tesseract.
A local proxy stub answers HEAD directly and never forwards requests.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import os
import csv
import io
import struct
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parent.parent

def command(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.DEVNULL)

def window(proc, title):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        result = subprocess.run(['xdotool', 'search', '--all', '--onlyvisible', '--pid', str(proc.pid), '--name', title], capture_output=True, text=True)
        if result.returncode == 0:
            found = result.stdout.splitlines()[0]
            command('xdotool', 'windowfocus', '--sync', found)
            time.sleep(.15)
            return found
        assert proc.poll() is None, proc.communicate()
        time.sleep(.05)
    raise AssertionError('Missing window: ' + title)

def key(name): command('xdotool', 'key', '--clearmodifiers', name)
def u32(n): return struct.pack('<I', n)
def packed_list(names, date):
    domains = sorted(name.encode() for name in names)
    data, offsets = b'', [0]
    for name in domains:
        data += name
        offsets.append(len(data))
    return u32(len(date)) + u32(len(domains)) + u32(len(data)) + date + b''.join(u32(i) for i in offsets) + data

def screenshot(popup, image):
    command('import', '-window', popup, str(image))
    enlarged = image.with_name('ocr.png')
    command('convert', str(image), '-resize', '300%', str(enlarged))
    return command('tesseract', str(enlarged), 'stdout', '--psm', '11')

with tempfile.TemporaryDirectory(prefix='relay-insights-test-') as temp:
    folder = Path(temp)
    requests = []
    class Proxy(BaseHTTPRequestHandler):
        def do_HEAD(self):
            requests.append(self.path)
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
        def log_message(self, *args): pass
    proxy = ThreadingHTTPServer(('127.0.0.1', 0), Proxy)
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    now = int(time.time())
    date = time.strftime('%Y-%m-%dT00:00:00Z', time.gmtime(now)).encode()
    (folder / 'oisd.bin').write_bytes(b'BR-OISD\x01' + struct.pack('<Q', now) + packed_list(['example.com'], date) + packed_list(['adult.invalid'], date))
    rank_cache = b'BR-RANK\x02' + u32(2) + struct.pack('<Q', now) + u32(4) + b'TEST' + packed_list(['child.example.com', 'example.com'], date) + u32(2) + u32(1)
    (folder / 'tranco.bin').write_bytes(rank_cache)
    env = dict(os.environ, GDK_BACKEND='x11', GSK_RENDERER='cairo', GTK_A11Y='none', BROWSER_RELAY_OISD_DIR=str(folder), BROWSER_RELAY_TRANCO_DIR=str(folder))
    for name in ('WAYLAND_DISPLAY','BROWSER_RELAY_DIALOG','HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy','NO_PROXY','no_proxy'):
        env.pop(name, None)
    env['http_proxy'] = f'http://127.0.0.1:{proxy.server_port}'
    cases = [
        ('child.example.com', '#2', 'Exact', 'Listed', '#FF8995'),
        ('tenant.example.com', 'Unranked', 'Parent #1', 'Listed', '#FF8995'),
        ('adult.invalid', 'Unranked', 'Outside', 'Adult match', '#FFC27D'),
        ('clean.invalid', 'Unranked', 'Outside', 'No match', '#8CDDA5'),
    ]
    for host, rank, caption, state, color in cases:
        proc = subprocess.Popen([str(ROOT / 'target/debug/browser-relay'), f'http://{host}/'], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            parent = window(proc, '^Browser Relay$')
            key('ctrl+i')
            popup = window(proc, '^Inspect link$')
            # The proxy disclosure adds a banner; give that extra content space.
            command('xdotool', 'windowsize', popup, '800', '800')
            time.sleep(.6)
            image = folder / 'dashboard.png'
            text = screenshot(popup, image)
            assert rank in text and caption in text and state in text and 'No match' in text, text
            assert 'Details & privacy' in text, text
            # No vertical movement should be possible when all cards fit.
            command('xdotool', 'mousemove', '--window', popup, '500', '600', 'click', '--repeat', '12', '--delay', '20', '5')
            time.sleep(.2)
            after = folder / 'scrolled.png'
            screenshot(popup, after)
            comparison = subprocess.run(['compare', '-metric', 'AE', str(image), str(after), 'null:'], capture_output=True, text=True)
            assert comparison.returncode == 0, 'Unnecessary dashboard scrolling: ' + comparison.stderr
            before = len(requests)
            data = command('tesseract', str(folder / 'ocr.png'), 'stdout', '--psm', '11', 'tsv')
            row = next(row for row in csv.DictReader(io.StringIO(data), delimiter='\t') if row['text'] == 'DOMAIN')
            header_y = (int(row['top']) + int(row['height']) // 2) // 3
            # Check the actual OISD tiles, excluding other dashboard colors and the popularity bar.
            colors = command('convert', str(image), '-crop', f'450x85+290+{header_y + 15}', '-format', '%c', 'histogram:info:-').upper()
            assert color in colors, f'{host}: missing status color {color}'
            assert '#8CDDA5' in colors, f'{host}: no-match result must be green'
            windows = lambda: set(command('xdotool', 'search', '--onlyvisible', '--pid', str(proc.pid)).split())
            visible_before = windows()
            command('xdotool', 'mousemove', '--window', popup, '744', str(header_y), 'click', '1')
            time.sleep(.2)
            assert windows() - visible_before, 'Update disclosure did not open'
            assert len(requests) == before, 'Opening update disclosure must not download lists'
            key('Escape')
            key('Escape')
            command('xdotool', 'windowfocus', '--sync', parent)
            key('Escape')
            out, err = proc.communicate(timeout=5)
            assert proc.returncode == 0 and b'CRITICAL' not in err and b'CSS' not in err, (out, err)
            assert b'reported min width' not in err and b'reported min height' not in err, err
        finally:
            if proc.poll() is None: proc.kill(); proc.wait()
    assert requests == [f'http://{case[0]}/' for case in cases], requests
    assert (folder / 'tranco.bin').read_bytes() == rank_cache
    proxy.shutdown()
    proxy.server_close()
print('Exact/parent ranks, red OISD matches, orange adult matches, green no-matches, compact layout and update consent passed.')
