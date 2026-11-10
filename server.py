#!/usr/bin/env python3
"""Backend for the CoC upgrade tracker.

Serves the app behind a login and stores each user's villages and item names as JSON files on disk.
Standard library only, so it runs on a stock Debian VM.

  python3 server.py                                  # run the server
  python3 server.py adduser NAME                     # create or reset a user (prompts for password)
  echo pw | python3 server.py adduser NAME --password-stdin

Usernames and passwords are case-insensitive. Files live in $DATA_DIR (default ./data):
  users.json            username -> salted PBKDF2 hash
  sessions.json         sha256(session token) -> {user, exp}
  users/<name>.json     {"villages": {...}, "names": {...}}
"""
import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import threading
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get('DATA_DIR', os.path.join(ROOT, 'data'))
HOST = os.environ.get('HOST', '127.0.0.1')
PORT = int(os.environ.get('PORT', '8080'))
COOKIE_SECURE = os.environ.get('COOKIE_SECURE', '1') == '1'
SESSION_SECONDS = 30 * 86400
MAX_BODY = 2_000_000
PBKDF2_ITER = 300_000
LOGIN_WINDOW, LOGIN_MAX_FAILS = 15 * 60, 10
USERNAME_RE = re.compile(r'^[a-z0-9_.-]{1,32}$')

lock = threading.Lock()
login_fails = {}  # ip -> [timestamps]


# ---------- storage ----------
def data_path(*parts):
    return os.path.join(DATA_DIR, *parts)


def read_json(p, default):
    try:
        with open(p) as f:
            return json.load(f)
    except FileNotFoundError:
        return default


def write_json(p, obj):
    os.makedirs(os.path.dirname(p), mode=0o700, exist_ok=True)
    tmp = f'{p}.{os.getpid()}.tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(obj, f)
    os.replace(tmp, p)


def user_file(user):
    return data_path('users', f'{user}.json')


def load_user_data(user):
    d = read_json(user_file(user), {})
    return {'villages': d.get('villages', {}), 'names': d.get('names', {})}


def app_version():
    """Changes whenever a deploy changes the app page, so open tabs know to reload."""
    h = hashlib.sha256()
    for name in ('index.html', 'game-names.json'):
        with open(os.path.join(ROOT, name), 'rb') as f:
            h.update(f.read())
    return h.hexdigest()[:12]


# ---------- auth ----------
def hash_password(password, salt_hex):
    return hashlib.pbkdf2_hmac('sha256', password.lower().encode(), bytes.fromhex(salt_hex), PBKDF2_ITER).hex()


def add_user(name, password):
    user = name.strip().lower()
    if not USERNAME_RE.match(user):
        raise SystemExit('Username may only use letters, numbers, dot, dash and underscore (max 32).')
    if not password:
        raise SystemExit('Password cannot be empty.')
    salt = secrets.token_hex(16)
    with lock:
        users = read_json(data_path('users.json'), {})
        users[user] = {'display': name.strip(), 'salt': salt, 'hash': hash_password(password, salt)}
        write_json(data_path('users.json'), users)
    print(f'Saved user {user!r} in {DATA_DIR}')


def check_password(username, password):
    users = read_json(data_path('users.json'), {})
    u = users.get(username.strip().lower())
    if not u:
        hash_password(password, '00' * 16)  # spend the same time so unknown users aren't detectable
        return None
    return username.strip().lower() if hmac.compare_digest(hash_password(password, u['salt']), u['hash']) else None


def token_key(token):
    return hashlib.sha256(token.encode()).hexdigest()


def new_session(user):
    token = secrets.token_urlsafe(32)
    with lock:
        sessions = read_json(data_path('sessions.json'), {})
        t = time.time()
        sessions = {k: v for k, v in sessions.items() if v['exp'] > t}
        sessions[token_key(token)] = {'user': user, 'exp': t + SESSION_SECONDS}
        write_json(data_path('sessions.json'), sessions)
    return token


def session_user(token):
    if not token:
        return None
    s = read_json(data_path('sessions.json'), {}).get(token_key(token))
    return s['user'] if s and s['exp'] > time.time() else None


def end_session(token):
    with lock:
        sessions = read_json(data_path('sessions.json'), {})
        if sessions.pop(token_key(token), None):
            write_json(data_path('sessions.json'), sessions)


def too_many_fails(ip):
    t = time.time()
    recent = [x for x in login_fails.get(ip, []) if t - x < LOGIN_WINDOW]
    login_fails[ip] = recent
    return len(recent) >= LOGIN_MAX_FAILS


# ---------- HTTP ----------
class Handler(BaseHTTPRequestHandler):
    server_version = 'coc-timer'

    def log_message(self, fmt, *args):
        sys.stderr.write(f'{self.client_ip()} {self.command} {urlsplit(self.path).path} {args[1] if len(args) > 1 else ""}\n')

    def client_ip(self):
        # Caddy sets X-Forwarded-For; the server only listens on localhost behind it.
        fwd = self.headers.get('X-Forwarded-For')
        return fwd.split(',')[-1].strip() if fwd else self.client_address[0]

    def token(self):
        c = SimpleCookie(self.headers.get('Cookie', ''))
        return c['session'].value if 'session' in c else None

    def user(self):
        return session_user(self.token())

    def send(self, code, body=b'', ctype='application/json', headers=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'same-origin')
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def err(self, code, msg):
        self.send(code, {'error': msg})

    def redirect(self, to):
        self.send(302, b'', 'text/plain', {'Location': to})

    def page(self, name):
        with open(os.path.join(ROOT, name), 'rb') as f:
            self.send(200, f.read(), 'text/html; charset=utf-8')

    def body(self):
        n = int(self.headers.get('Content-Length') or 0)
        if n > MAX_BODY:
            raise ValueError('Request too large')
        if 'application/json' not in self.headers.get('Content-Type', ''):
            raise ValueError('Expected JSON')  # also blocks cross-site form posts
        return json.loads(self.rfile.read(n) or b'null')

    def route(self):
        parts = [unquote(p) for p in urlsplit(self.path).path.split('/') if p]
        return parts

    def cookie(self, value, max_age):
        flags = f'Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}' + ('; Secure' if COOKIE_SECURE else '')
        return {'Set-Cookie': f'session={value}; {flags}'}

    # -- methods --
    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        p = self.route()
        user = self.user()
        if p == []:
            return self.page('index.html') if user else self.redirect('/login')
        if p == ['login']:
            return self.redirect('/') if user else self.page('login.html')
        if p == ['game-names.json']:
            if not user:
                return self.err(401, 'Not signed in')
            with open(os.path.join(ROOT, 'game-names.json'), 'rb') as f:
                return self.send(200, f.read())
        if p and p[0] == 'api':
            if not user:
                return self.err(401, 'Not signed in')
            if p == ['api', 'state']:
                return self.send(200, {**load_user_data(user), 'version': app_version()})
            if p == ['api', 'me']:
                users = read_json(data_path('users.json'), {})
                return self.send(200, {'user': user, 'display': users.get(user, {}).get('display', user)})
        self.err(404, 'Not found')

    def do_POST(self):
        p = self.route()
        try:
            if p == ['api', 'login']:
                ip = self.client_ip()
                if too_many_fails(ip):
                    return self.err(429, 'Too many attempts. Try again in a few minutes.')
                b = self.body() or {}
                user = check_password(str(b.get('username', '')), str(b.get('password', '')))
                if not user:
                    login_fails.setdefault(ip, []).append(time.time())
                    return self.err(401, 'Wrong username or password')
                login_fails.pop(ip, None)
                return self.send(200, {'ok': True}, headers=self.cookie(new_session(user), SESSION_SECONDS))
            if p == ['api', 'logout']:
                if self.token():
                    end_session(self.token())
                return self.send(200, {'ok': True}, headers=self.cookie('', 0))
        except ValueError as e:
            return self.err(400, str(e))
        self.err(404, 'Not found')

    def mutate(self, fn):
        user = self.user()
        if not user:
            return self.err(401, 'Not signed in')
        try:
            body = self.body() if self.command == 'PUT' else None
            with lock:
                d = load_user_data(user)
                res = fn(d, body)
                if isinstance(res, tuple):
                    return self.err(*res)
                write_json(user_file(user), d)
            self.send(200, {'ok': True})
        except ValueError as e:
            self.err(400, str(e))

    def do_PUT(self):
        p = self.route()
        if len(p) == 3 and p[:2] == ['api', 'villages']:
            def put_village(d, v):
                if not isinstance(v, dict) or v.get('tag') != p[2]:
                    return (400, 'Village tag does not match')
                d['villages'][p[2]] = v
            return self.mutate(put_village)
        if len(p) == 3 and p[:2] == ['api', 'names']:
            def put_name(d, b):
                name = str((b or {}).get('name', '')).strip()[:80]
                if not name:
                    return (400, 'Name is empty')
                d['names'][p[2]] = name
            return self.mutate(put_name)
        self.err(404, 'Not found')

    def do_DELETE(self):
        p = self.route()
        if len(p) == 3 and p[:2] == ['api', 'villages']:
            return self.mutate(lambda d, _: d['villages'].pop(p[2], None) and None)
        if len(p) == 3 and p[:2] == ['api', 'names']:
            return self.mutate(lambda d, _: d['names'].pop(p[2], None) and None)
        self.err(404, 'Not found')


def main():
    args = sys.argv[1:]
    if args[:1] == ['adduser'] and len(args) >= 2:
        if '--password-stdin' in args:
            pw = sys.stdin.readline().rstrip('\n')
        else:
            pw = getpass.getpass('Password: ')
            if pw != getpass.getpass('Repeat: '):
                raise SystemExit('Passwords do not match.')
        return add_user(args[1], pw)
    if args:
        raise SystemExit(__doc__)
    os.makedirs(DATA_DIR, mode=0o700, exist_ok=True)
    if not read_json(data_path('users.json'), {}):
        print('No users yet. Create one with: python3 server.py adduser NAME', file=sys.stderr)
    print(f'Listening on http://{HOST}:{PORT} (data in {DATA_DIR})', file=sys.stderr)
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()


if __name__ == '__main__':
    main()
