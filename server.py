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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get('DATA_DIR', os.path.join(ROOT, 'data'))
HOST = os.environ.get('HOST', '127.0.0.1')
PORT = int(os.environ.get('PORT', '8080'))
COOKIE_SECURE = os.environ.get('COOKIE_SECURE', '1') == '1'
SESSION_SECONDS = 30 * 86400
MAX_BODY = 8_000_000  # a village PUT carries the whole export as an escaped string
PBKDF2_ITER = 300_000
LOGIN_WINDOW, LOGIN_MAX_FAILS = 15 * 60, 10
USERNAME_RE = re.compile(r'^[a-z0-9_.-]{1,32}$')

lock = threading.Lock()
login_fails = {}  # ip -> [timestamps]


# ---------- storage ----------
def data_path(*parts):
    return os.path.join(DATA_DIR, *parts)


def read_json(p, default):
    """Missing file -> default. A corrupted file is moved aside (kept for recovery) and treated as
    missing, so one bad file can't take the whole site down."""
    try:
        with open(p) as f:
            data = json.load(f)
        return data if isinstance(data, type(default)) else default
    except FileNotFoundError:
        return default
    except (ValueError, OSError) as e:
        bad = f'{p}.corrupt-{int(time.time())}'
        try:
            os.replace(p, bad)
        except OSError:
            pass
        sys.stderr.write(f'WARNING: unreadable {p} ({e}); moved to {bad}\n')
        return default


def write_json(p, obj):
    os.makedirs(os.path.dirname(p), mode=0o700, exist_ok=True)
    tmp = f'{p}.{os.getpid()}.{threading.get_ident()}.tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(obj, f)
        f.flush()
        os.fsync(f.fileno())
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
        sessions = read_json(data_path('sessions.json'), {})
        kept = {k: v for k, v in sessions.items() if v.get('user') != user}
        if len(kept) != len(sessions):
            write_json(data_path('sessions.json'), kept)
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


fails_lock = threading.Lock()


def note_attempt(ip):
    """Records a login attempt and says whether this IP is over the limit. Counting happens before the
    password check so parallel requests can't slip past it; a success removes the attempt again."""
    t = time.time()
    with fails_lock:
        if len(login_fails) > 10_000:  # forget stale IPs
            for k in [k for k, v in login_fails.items() if not v or t - v[-1] > LOGIN_WINDOW]:
                del login_fails[k]
        recent = [x for x in login_fails.get(ip, []) if t - x < LOGIN_WINDOW]
        blocked = len(recent) >= LOGIN_MAX_FAILS
        if not blocked:
            recent.append(t)
        login_fails[ip] = recent
        return blocked


def forget_attempt(ip):
    with fails_lock:
        if login_fails.get(ip):
            login_fails[ip].pop()


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
        for part in self.headers.get('Cookie', '').split(';'):
            k, _, v = part.strip().partition('=')
            if k == 'session' and v:
                return v
        return None

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
        try:
            n = int(self.headers.get('Content-Length') or 0)
        except ValueError:
            raise ValueError('Bad Content-Length')
        if n < 0 or n > MAX_BODY:
            raise ValueError('Request too large' if n > 0 else 'Bad Content-Length')
        if 'application/json' not in self.headers.get('Content-Type', ''):
            raise ValueError('Expected JSON')  # also blocks cross-site form posts
        data = json.loads(self.rfile.read(n) or b'{}')
        if not isinstance(data, dict):
            raise ValueError('Expected a JSON object')
        return data

    def route(self):
        parts = [unquote(p) for p in urlsplit(self.path).path.split('/') if p]
        return parts

    def cookie(self, value, max_age):
        flags = f'Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}' + ('; Secure' if COOKIE_SECURE else '')
        return {'Set-Cookie': f'session={value}; {flags}'}

    # -- methods --
    def handle_one_request(self):
        try:
            super().handle_one_request()
        except (BrokenPipeError, ConnectionResetError):
            pass

    def guarded(fn):
        def run(self):
            try:
                fn(self)
            except Exception as e:  # never drop the connection without an answer
                sys.stderr.write(f'ERROR {self.command} {urlsplit(self.path).path}: {e!r}\n')
                try:
                    self.err(500, 'Server error')
                except Exception:
                    pass
        return run

    def do_HEAD(self):
        self.do_GET()

    @guarded
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

    @guarded
    def do_POST(self):
        p = self.route()
        try:
            if p == ['api', 'login']:
                ip = self.client_ip()
                b = self.body()
                if note_attempt(ip):
                    return self.err(429, 'Too many attempts. Try again in a few minutes.')
                user = check_password(str(b.get('username', '')), str(b.get('password', '')))
                if not user:
                    return self.err(401, 'Wrong username or password')
                forget_attempt(ip)
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
            self.send(200, {'ok': True, **(res or {})})
        except ValueError as e:
            self.err(400, str(e))

    @guarded
    def do_PUT(self):
        p = self.route()
        if len(p) == 3 and p[:2] == ['api', 'villages']:
            def put_village(d, v):
                if v.get('tag') != p[2]:
                    return (400, 'Village tag does not match')
                cur = d['villages'].get(p[2])
                # Every save says which revision it was based on; if another device saved since, refuse
                # (409) and let the client reload before changing anything.
                if cur is not None and (v.get('rev') or 0) != cur.get('rev', 0):
                    return (409, 'Changed on another device')
                v['rev'] = (cur or {}).get('rev', 0) + 1
                d['villages'][p[2]] = v
                return {'rev': v['rev']}
            return self.mutate(put_village)
        if len(p) == 3 and p[:2] == ['api', 'names']:
            def put_name(d, b):
                name = str((b or {}).get('name', '')).strip()[:80]
                if not name:
                    return (400, 'Name is empty')
                d['names'][p[2]] = name
            return self.mutate(put_name)
        self.err(404, 'Not found')

    @guarded
    def do_DELETE(self):
        p = self.route()
        if len(p) == 3 and p[:2] == ['api', 'villages']:
            return self.mutate(lambda d, _: (d['villages'].pop(p[2], None), None)[1])
        if len(p) == 3 and p[:2] == ['api', 'names']:
            return self.mutate(lambda d, _: (d['names'].pop(p[2], None), None)[1])
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
