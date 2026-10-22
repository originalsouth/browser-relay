"""Local TLS/redirect GUI regressions. Needs openssl, tesseract, xdotool, ImageMagick.
Run: xvfb-run -a -s '-screen 0 1280x1024x24' python3 tests/inspection.py
Set RELAY_SCREENSHOTS=<dir> to keep the before/after captures for review.
No external destinations or third-party lookup services are contacted.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import os
import csv
import io
import re
import shutil
import socket
import ssl
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
    raise AssertionError('Window missing: ' + title)

def key(name):
    command('xdotool', 'key', '--clearmodifiers', name)

def capture_text(popup, destination):
    command('import', '-window', popup, str(destination))
    return command('tesseract', str(destination), 'stdout')

with tempfile.TemporaryDirectory(prefix='relay-inspection-test-') as temp:
    folder = Path(temp)
    ca, ca_key, leaf, leaf_key, csr, ext = [folder / name for name in ('ca.pem','ca.key','leaf.pem','leaf.key','leaf.csr','ext.cnf')]
    command('openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-keyout',str(ca_key),'-out',str(ca),'-subj','/CN=Relay Test CA')
    command('openssl','req','-new','-newkey','rsa:2048','-nodes','-keyout',str(leaf_key),'-out',str(csr),'-subj','/CN=Relay Test Server')
    ext.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n')
    command('openssl','x509','-req','-in',str(csr),'-CA',str(ca),'-CAkey',str(ca_key),'-CAcreateserial','-days','1','-out',str(leaf),'-extfile',str(ext))
    env = dict(os.environ, GDK_BACKEND='x11', GSK_RENDERER='cairo', GTK_A11Y='none', SSL_CERT_FILE=str(ca), BROWSER_RELAY_OISD_DIR=str(folder))
    for name in ('WAYLAND_DISPLAY','BROWSER_RELAY_DIALOG','HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy'):
        env.pop(name, None)
    shots = os.environ.get('RELAY_SCREENSHOTS')
    if shots:
        Path(shots).mkdir(parents=True, exist_ok=True)
    requests = []
    class SecureHandler(BaseHTTPRequestHandler):
        def do_HEAD(self):
            requests.append(self.path)
            if self.path == '/broken':
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
                return
            self.send_response(302 if self.path == '/start' else 200)
            if self.path == '/start':
                self.send_header('Location', '/broken')
            self.send_header('Content-Length','0')
            self.end_headers()
        def log_message(self, *args): pass
    secure = ThreadingHTTPServer(('127.0.0.1',0), SecureHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(leaf, leaf_key)
    secure.socket = context.wrap_socket(secure.socket,server_side=True)
    threading.Thread(target=secure.serve_forever,daemon=True).start()
    class RedirectHandler(BaseHTTPRequestHandler):
        def do_HEAD(self):
            self.send_response(302)
            self.send_header('Location',f'https://127.0.0.1:{secure.server_port}/final')
            self.end_headers()
        def log_message(self,*args): pass
    plain = ThreadingHTTPServer(('127.0.0.1',0), RedirectHandler)
    threading.Thread(target=plain.serve_forever,daemon=True).start()
    for link, follows_redirect in [(f'https://127.0.0.1:{secure.server_port}/start',False), (f'http://127.0.0.1:{plain.server_port}/original',True)]:
        proc = subprocess.Popen([str(ROOT/'target/debug/browser-relay'),link],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            parent = window(proc,'^Browser Relay$')
            key('ctrl+i')
            popup = window(proc,'^Inspect link$')
            time.sleep(1.5)
            before = capture_text(popup,folder/'before.png')
            assert 'Inspection incomplete' in before, before
            assert 'Verified HTTPS' not in before, before
            assert 'RISK FACTORS' in before, before
            assert 'Local network address' not in before, 'Routine notices should start collapsed'
            data = command('tesseract', str(folder/'before.png'), 'stdout', 'tsv')
            row = next(row for row in csv.DictReader(io.StringIO(data), delimiter='\t') if row['text'] == 'RISK')
            risk_y = int(row['top']) + int(row['height']) // 2
            command('xdotool', 'mousemove', '--window', popup, '150', str(risk_y), 'click', '1')
            time.sleep(.2)
            evidence = capture_text(popup, folder/'evidence.png')
            assert 'Local network address' in evidence, evidence
            assert 'Details & privacy' in evidence, evidence
            command('xdotool', 'mousemove', '--window', popup, '150', str(risk_y), 'click', '1')
            time.sleep(.2)
            assert not re.search(r'\bsafe\b', before, re.I), before
            if follows_redirect:
                assert '/final' not in requests, 'Destination contacted before consent'
                command('xdotool','mousemove','--window',popup,'650','135','click','1')
                time.sleep(.2)
                key('Return')
                time.sleep(1.5)
                assert window(proc,'^Inspect link$') == popup, 'Redirect must preserve the same report'
                after = capture_text(popup,folder/'after.png')
                assert 'Route includes HTTP' in after and 'Last HTTPS' in after, after
                assert requests.count('/final') == 1
            else:
                assert requests == ['/start','/broken'], requests
            if shots:
                for name in ('before.png', 'after.png'):
                    if (folder/name).exists():
                        shutil.copy(folder/name, Path(shots)/f"{'redirect' if follows_redirect else 'tls'}-{name}")
            key('Escape')
            command('xdotool','windowfocus','--sync',parent)
            key('Escape')
            out, err = proc.communicate(timeout=5)
            assert proc.returncode == 0 and b'CRITICAL' not in err, (out,err)
            assert b'reported min width' not in err and b'reported min height' not in err, err
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()
    plain.shutdown(); plain.server_close()
    secure.shutdown(); secure.server_close()
print('TLS failure stays amber; redirect consent preserves the report and earlier HTTP hop.')
