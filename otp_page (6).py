"""
============================================================
 Read OTP — standalone single-file app (Python / Flask)
 API: https://mailgen.shop (public, no key needed)
 শুধু এই একটা ফাইল run করলেই চলবে।

 Install :  pip install flask requests
 Run     :  python otp_page.py          (http://localhost:5000)
 Prod    :  SECRET_KEY=xxxx gunicorn -w 2 -b 0.0.0.0:8000 otp_page:app
============================================================
"""
import hashlib
import hmac
import html as _html
import json
import math
import os
import re
import secrets
import struct
import tempfile
import time
import zlib
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import unquote_plus

import requests
from flask import Flask, Response, request, session

MAILGEN_BASE = 'https://mailgen.shop'
RATE_PER_MIN = 30  # per-IP per minute

BD_TZ = timezone(timedelta(hours=6))  # Bangladesh time (UTC+6)


def bd_time(v) -> str:
    """Convert an API date (ISO-8601 / RFC-2822 / unix timestamp, treated as UTC if no zone) to BD time, 12-hour AM/PM."""
    raw = str(v or '').strip()
    if not raw:
        return ''
    dt = None
    try:
        if re.fullmatch(r'\d{10,13}(\.\d+)?', raw):
            n = float(raw)
            dt = datetime.fromtimestamp(n / 1000 if n > 1e11 else n, tz=timezone.utc)
        else:
            iso = raw.replace('Z', '+00:00').replace('z', '+00:00')
            iso = re.sub(r'(\.\d{6})\d+', r'\1', iso)          # trim >6 fractional digits
            iso = re.sub(r'\s*UTC$', '+00:00', iso, flags=re.I)
            try:
                dt = datetime.fromisoformat(iso)
            except ValueError:
                dt = parsedate_to_datetime(raw)                  # e.g. "Fri, 06 Nov 2026 10:15:00 +0000"
    except Exception:
        return raw
    if dt is None:
        return raw
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    t = dt.astimezone(BD_TZ)
    hour = t.hour % 12 or 12
    return '%d %s %d, %d:%02d %s' % (t.day, t.strftime('%b'), t.year, hour, t.minute, 'AM' if t.hour < 12 else 'PM')


def mail_ts(v) -> int:
    # epoch seconds of an API date (0 when unknown) - feeds the live "x min ago" label
    raw = str(v or '').strip()
    if not raw:
        return 0
    try:
        if re.fullmatch(r'\d{10,13}(\.\d+)?', raw):
            n = float(raw)
            return int(n / 1000 if n > 1e11 else n)
        iso = raw.replace('Z', '+00:00').replace('z', '+00:00')
        iso = re.sub(r'(\.\d{6})\d+', r'\1', iso)
        iso = re.sub(r'\s*UTC$', '+00:00', iso, flags=re.I)
        try:
            dt = datetime.fromisoformat(iso)
        except ValueError:
            dt = parsedate_to_datetime(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
    except Exception:
        return 0


BULK_MAX_LINES = 1000   # max accounts processed in one bulk read
BULK_CHUNK_MAX = 30     # max lines per live-progress request
BULK_CHUNK_RATE = 120   # separate per-IP per-minute budget for those chunk requests
BULK_WORKERS = 12       # parallel requests to the upstream API


# ─── secret key (needed for Flask session / CSRF) ───
def _load_secret() -> str:
    env = os.environ.get('SECRET_KEY')
    if env:
        return env
    path = os.path.join(tempfile.gettempdir(), 'otp_page_secret_key')
    try:
        with open(path, 'r') as fh:
            val = fh.read().strip()
            if val:
                return val
    except OSError:
        pass
    val = secrets.token_hex(32)
    try:
        with open(path, 'w') as fh:
            fh.write(val)
        os.chmod(path, 0o600)
    except OSError:
        pass
    return val


app = Flask(__name__)
app.secret_key = _load_secret()
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax')


# ─── tiny helpers ───
def e(s) -> str:
    return _html.escape('' if s is None else str(s), quote=True)


_ICONS = {
    'bell':   '<path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10.3 21a1.94 1.94 0 0 0 3.4 0"/>',
    'bell-off': '<path d="M8.7 3A6 6 0 0 1 18 8c0 2.7.5 4.8 1.2 6.3"/><path d="M17 17H3s3-2 3-9a4.67 4.67 0 0 1 .3-1.7"/><path d="M10.3 21a1.94 1.94 0 0 0 3.4 0"/><path d="m2 2 20 20"/>',
    'mail':   '<rect width="20" height="16" x="2" y="4" rx="2"/><path d="m22 7-10 6L2 7"/>',
    'send':   '<path d="m22 2-7 20-4-9-9-4z"/><path d="M22 2 11 13"/>',
    'shield': '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
    'copy':   '<rect width="14" height="14" x="8" y="8" rx="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/>',
    'key':    '<circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6"/><path d="m15.5 7.5 3 3L22 7l-3-3"/>',
    'inbox':  '<polyline points="22 12 16 12 14 15 10 15 8 12 2 12"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/>',
    'sun':    '<circle cx="12" cy="12" r="4"/><path d="M12 2v2"/><path d="M12 20v2"/><path d="m4.93 4.93 1.41 1.41"/><path d="m17.66 17.66 1.41 1.41"/><path d="M2 12h2"/><path d="M20 12h2"/><path d="m6.34 17.66-1.41 1.41"/><path d="m19.07 4.93-1.41 1.41"/>',
    'moon':   '<path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/>',
    'search': '<circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>',
    'x':      '<path d="M18 6 6 18"/><path d="m6 6 12 12"/>',
    'download': '<path d="M12 3v12"/><path d="m7 10 5 5 5-5"/><path d="M5 21h14"/>',
    'qr':     '<rect width="5" height="5" x="3" y="3" rx="1"/><rect width="5" height="5" x="16" y="3" rx="1"/><rect width="5" height="5" x="3" y="16" rx="1"/><path d="M21 16h-3a2 2 0 0 0-2 2v3"/><path d="M21 21v.01"/><path d="M12 7v3a2 2 0 0 1-2 2H7"/><path d="M3 12h.01"/><path d="M12 3h.01"/><path d="M12 16v.01"/><path d="M16 12h1"/><path d="M21 12v.01"/><path d="M12 21v-1"/>',
    'clock':  '<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>',
    'refresh': '<path d="M21 12a9 9 0 0 0-9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/><path d="M3 12a9 9 0 0 0 9 9 9.75 9.75 0 0 0 6.74-2.74L21 16"/><path d="M16 16h5v5"/>',
}


def scrub(s) -> str:
    """Hide the upstream provider name from anything shown to the user."""
    return re.sub(r'mail\s*gen(\.shop)?', 'server', str(s), flags=re.I)


def icon(n: str) -> str:
    return '<svg class="i" viewBox="0 0 24 24" aria-hidden="true">' + _ICONS.get(n, '') + '</svg>'


# ─── sender / service detection ───
# key, label, background, text colour, regex (searched in the sender first, then the subject)
SERVICES = [
    ('instagram', 'Instagram', '#e1306c', '#ffffff', r'instagram'),
    ('facebook',  'Facebook',  '#1877f2', '#ffffff', r'facebook|facebookmail|fb\.com'),
    ('binance',   'Binance',   '#f0b90b', '#1e2329', r'binance'),
    ('google',    'Google',    '#ea4335', '#ffffff', r'google|gmail|youtube'),
    ('telegram',  'Telegram',  '#229ed9', '#ffffff', r'telegram'),
    ('x',         'X (Twitter)', '#0f1419', '#ffffff', r'twitter|\bx\.com|\bx corp'),
    ('whatsapp',  'WhatsApp',  '#25d366', '#06351a', r'whatsapp'),
    ('tiktok',    'TikTok',    '#111827', '#ffffff', r'tiktok'),
    ('microsoft', 'Microsoft', '#0078d4', '#ffffff', r'microsoft|xbox|live\.com'),
    ('amazon',    'Amazon',    '#ff9900', '#231f20', r'amazon'),
    ('paypal',    'PayPal',    '#003087', '#ffffff', r'paypal'),
    ('apple',     'Apple',     '#555555', '#ffffff', r'apple|icloud'),
    ('discord',   'Discord',   '#5865f2', '#ffffff', r'discord'),
    ('netflix',   'Netflix',   '#e50914', '#ffffff', r'netflix'),
    ('linkedin',  'LinkedIn',  '#0a66c2', '#ffffff', r'linkedin'),
    ('github',    'GitHub',    '#24292f', '#ffffff', r'github'),
    ('spotify',   'Spotify',   '#1db954', '#052e14', r'spotify'),
    ('steam',     'Steam',     '#1b2838', '#ffffff', r'steam'),
    ('openai',    'OpenAI',    '#10a37f', '#ffffff', r'openai|chatgpt'),
]
SERVICE_MAP = {k: (lab, bg, fg) for k, lab, bg, fg, _ in SERVICES}
_SERVICE_RES = [(k, re.compile(rx, re.I)) for k, _l, _b, _f, rx in SERVICES]


def service_of(frm, subject='') -> str:
    """Return the service key for a message ('' when unknown)."""
    for text in (str(frm or ''), str(subject or '')):
        if not text:
            continue
        for k, rx in _SERVICE_RES:
            if rx.search(text):
                return k
    return ''


def sv_badge(key: str) -> str:
    s_ = SERVICE_MAP.get(key)
    if not s_:
        return ''
    return '<span class="sv" style="--c:%s;--t:%s">%s</span>' % (s_[1], s_[2], e(s_[0]))


def mc_open(m: dict) -> str:
    """Opening tag of a mail card, tagged with its service."""
    k = service_of(m.get('from'), m.get('subject'))
    return '<div class="mc" data-svc="%s" data-ts="%d">%s' % (k, mail_ts(m.get('date')), ('<div class="sv-row">%s</div>' % sv_badge(k)) if k else '')


def date_line(d, cls: str, ts=0) -> str:
    """Small 'clock + BD date/time' line. d must already be BD-formatted text."""
    if not d:
        return ''
    ago = ('<span class="ago" data-ts="%d"></span>' % ts) if ts else ''
    return '<div class="%s">%s<span>%s</span>%s</div>' % (cls, icon('clock'), e(d), ago)


def otp_svg(p: str) -> str:
    return '<svg class="i" viewBox="0 0 24 24" aria-hidden="true">' + p + '</svg>'


_EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")


def valid_email(s: str) -> bool:
    return bool(_EMAIL_RE.match(s))


# ─── TOTP (local, no API) ───
_B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'


def base32_decode_raw(s: str):
    s = re.sub(r'[\s=\-]+', '', s).upper()
    if not re.fullmatch(r'[A-Z2-7]+', s):
        return None
    bits = ''.join(format(_B32.index(c), '05b') for c in s)
    out = bytearray()
    for i in range(0, len(bits) - len(bits) % 8, 8):
        out.append(int(bits[i:i + 8], 2))
    return bytes(out) if out else None


def totp_code(secret: str):
    # accept otpauth:// URL
    m = re.search(r'secret=([^&\s]+)', secret, re.I)
    if m:
        secret = unquote_plus(m.group(1))
    key = base32_decode_raw(secret)
    if key is None:
        return None
    h = hmac.new(key, struct.pack('>Q', int(time.time()) // 30), hashlib.sha1).digest()
    o = h[19] & 15
    n = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3]
    return str(n % 1000000).zfill(6)


def totp_remaining() -> int:
    return 30 - (int(time.time()) % 30)


# ─── rate limiter (tmp-file, no DB needed) ───
def rate_ok(bucket: str = '', limit: int = RATE_PER_MIN) -> bool:
    fwd = request.headers.get('X-Forwarded-For') or request.remote_addr or 'x'
    ip = fwd.split(',')[0].strip()
    f = os.path.join(tempfile.gettempdir(), 'otp_rl_' + hashlib.md5((ip + bucket).encode()).hexdigest())
    now = int(time.time())
    a = []
    try:
        with open(f, 'r') as fh:
            for x in fh.read().split(','):
                x = x.strip()
                if x.isdigit() and int(x) > now - 60:
                    a.append(int(x))
    except OSError:
        pass
    if len(a) >= limit:
        return False
    a.append(now)
    try:
        with open(f, 'w') as fh:
            fh.write(','.join(map(str, a)))
    except OSError:
        pass
    return True


# ─── MailGen API call ───
def mg_call(endpoint: str, payload: dict) -> dict:
    url = MAILGEN_BASE.rstrip('/') + '/' + endpoint.lstrip('/')
    try:
        resp = requests.post(
            url,
            data=json.dumps(payload),
            headers={'Content-Type': 'application/json', 'Accept': 'application/json'},
            timeout=(10, 45),
        )
    except requests.RequestException as ex:
        return {'_http': 0, 'error': 'Connection failed. Please try again.'}

    code = resp.status_code
    raw = resp.text
    if raw == '':
        return {'_http': 0, 'error': 'Connection failed. Please try again.'}

    try:
        j = json.loads(raw)
    except ValueError:
        j = None
    if isinstance(j, list):
        j = {}
    if not isinstance(j, dict):
        return {'_http': code, 'error': 'Bad response (HTTP %d)' % code}

    j['_http'] = code
    return j


# ─── extract code from a single message dict ───
def otp_pick_code(m: dict):
    c = _otp_pick_code(m)
    return None if (c and re.fullmatch(r'0+', c)) else c


def _otp_pick_code(m: dict):
    # prefer the API's own code field (it's already extracted for us)
    c = m.get('code')
    if c and isinstance(c, str) and re.fullmatch(r'\d{4,8}', c.strip(), re.A) and not re.fullmatch(r'0+', c.strip()):
        return c.strip()

    # fallback: parse subject + preview/message text
    body = ''
    for k in ('message', 'text', 'body', 'preview', 'snippet'):
        v = m.get(k)
        if v and isinstance(v, str):
            body = v
            break
    texts = [str(m.get('subject') or ''), body]
    for t in texts:
        if t.strip() == '':
            continue
        x = re.search(r'\b(?:code|otp|pin|passcode|token)\b[^0-9\n]{0,30}?\b(\d{4,8})\b', t, re.I | re.A)
        if x:
            return x.group(1)
        x = re.search(r'\b(\d{4,8})\b(?=\s+(?:is|as)\s+your)', t, re.I | re.A)
        if x:
            return x.group(1)
        x = re.search(r'\b(\d{3})[-\s](\d{3})\b', t, re.A)
        if x:
            return x.group(1) + x.group(2)
        x = re.search(r'\b(\d{6})\b', t, re.A)
        if x:
            return x.group(1)
        for n in re.findall(r'\b(\d{4,8})\b', t, re.A):
            if not (len(n) == 4 and 1900 <= int(n) <= 2100):
                return n
    return None


# ─── get body text for "Full mail" viewer ───
_HTML_TAG_RE = re.compile(r'</?(html|body|div|p|table|br|span|a|img|td|h[1-6])\b', re.I)


def otp_mail_body(m: dict):
    for k in ('html', 'htmlBody', 'message', 'text', 'body', 'preview', 'snippet'):
        v = m.get(k)
        if not isinstance(v, str) or v.strip() == '':
            continue
        v = v[:400000]
        return v, bool(_HTML_TAG_RE.search(v))
    return '', False


# ─── run one OTP request ───
def otp_run(tab: str, raw: str) -> dict:
    r = {'err': '', 'apiErr': '', 'messages': [], 'found': None, 'totp': None, 'empty': False}

    # grab first non-empty line
    first = ''
    for l in re.split(r'\r\n|\r|\n', raw):
        l = l.strip()
        if l != '':
            first = l
            break
    if first == '':
        r['err'] = 'Please enter your details first.'
        return r
    if len(first.encode('utf-8')) > 2000:
        r['err'] = 'Input is too long.'
        return r

    # ── TOTP (no API call) ──
    if tab == 'totp':
        code = totp_code(first)
        if code is None:
            r['err'] = 'Invalid 2FA key. Use a Base32 key such as JBSWY3DPEHPK3PXP.'
        else:
            r['totp'] = {'code': code, 'rem': totp_remaining()}
        return r

    # ── Edu mail ──
    if tab == 'email':
        email = first.lower()
        if not valid_email(email):
            r['err'] = 'Invalid email address.'
            return r
        # POST /api/edu-mail   { "email": "..." }
        res = mg_call('/api/edu-mail', {'email': email})
        return otp_parse_response(r, res)

    # ── Hotmail / Outlook (OAuth2) ──
    if tab == 'hotmail':
        parts = [p.strip() for p in first.split('|')]
        if len(parts) < 4 or not valid_email(parts[0]):
            r['err'] = 'Invalid format. Use: email|refresh_token|client_id|client_secret'
            return r
        # POST /api/get-inbox   { "data": "...", "mode": "oauth" }
        res = mg_call('/api/get-inbox', {'data': first, 'mode': 'oauth'})
        return otp_parse_response(r, res)

    # ── Roundcube ──
    if tab == 'roundcube':
        parts = [p.strip() for p in first.split('|')]
        if len(parts) < 2 or not valid_email(parts[0]):
            r['err'] = 'Invalid format. Use: user@wmhotmail.com|password'
            return r
        # POST /api/get-inbox   { "data": "...", "mode": "roundcube" }
        res = mg_call('/api/get-inbox', {'data': first, 'mode': 'roundcube'})
        return otp_parse_response(r, res)

    r['err'] = 'Unknown tab.'
    return r


def otp_parse_response(r: dict, res: dict) -> dict:
    # rate limit
    if res.get('_http', 0) == 429:
        wait = res.get('retry_after') or '?'
        r['apiErr'] = 'Rate limit exceeded. Try again in %s seconds.' % wait
        return r
    # messages array
    msgs = res.get('messages')
    if msgs and isinstance(msgs, list):
        r['messages'] = msgs
        for m in msgs:
            if not isinstance(m, dict):
                continue
            c = otp_pick_code(m)
            if c:
                r['found'] = {'code': c}
                break
        return r
    # explicit error
    if res.get('error'):
        err = res['error']
        r['apiErr'] = err if isinstance(err, str) else json.dumps(err, ensure_ascii=False)
        return r
    st = res.get('status')
    if st and isinstance(st, str) and st.lower() != 'success':
        r['apiErr'] = st
        return r
    r['empty'] = True
    return r


# ─── bulk Hotmail/Outlook read (one request fetches up to 1000 accounts) ───
_LINE_SPLIT_RE = re.compile(r'\r\n|\r|\n')


def parse_hotmail_line(line: str):
    parts = [p.strip() for p in line.split('|')]
    if len(parts) < 4 or not valid_email(parts[0]):
        return None
    return parts[0], parts[1], parts[2], parts[3]


def fetch_hotmail_account(line: str) -> dict:
    """Fetch the latest inbox code for ONE 'email|refresh_token|client_id|client_secret' line."""
    parsed = parse_hotmail_line(line)
    if parsed is None:
        shown = (line.split('|', 1)[0].strip() or line.strip())[:60]
        return {'email': shown, 'ok': False, 'code': None, 'subject': '', 'date': '',
                'err': 'Invalid format. Use: email|refresh_token|client_id|client_secret'}

    email = parsed[0].lower()
    res = mg_call('/api/get-inbox', {'data': line, 'mode': 'oauth'})
    base = {'err': '', 'apiErr': '', 'messages': [], 'found': None, 'totp': None, 'empty': False}
    r = otp_parse_response(base, res)

    if r['apiErr']:
        return {'email': email, 'ok': False, 'code': None, 'subject': '', 'date': '', 'err': r['apiErr']}

    if r['messages']:
        m = r['messages'][0] if isinstance(r['messages'][0], dict) else {}
        svcs = []
        for mm in r['messages'][:15]:
            if isinstance(mm, dict):
                k = service_of(mm.get('from'), mm.get('subject'))
                if k and k not in svcs:
                    svcs.append(k)
        return {
            'email': email, 'ok': True,
            'code': otp_pick_code(m) if m else None,
            'subject': str(m.get('subject') or '(no subject)'),
            'date': bd_time(m.get('date')),
            'svc': service_of(m.get('from'), m.get('subject')),
            'svcs': svcs,
            'ts': mail_ts(m.get('date')),
            'err': '',
        }
    return {'email': email, 'ok': True, 'code': None, 'subject': '', 'date': '', 'svc': '', 'svcs': [], 'err': ''}


def otp_run_bulk(raw: str, limit: int = BULK_MAX_LINES, offset: int = 0) -> list:
    """Process every non-empty line as its own account, in parallel, up to BULK_MAX_LINES."""
    lines = []
    for l in _LINE_SPLIT_RE.split(raw):
        l = l.strip()
        if l:
            lines.append(l)
        if len(lines) >= limit:
            break
    if not lines:
        return []

    results = [None] * len(lines)
    with ThreadPoolExecutor(max_workers=BULK_WORKERS) as ex:
        futs = {ex.submit(fetch_hotmail_account, l): i for i, l in enumerate(lines)}
        for fut in as_completed(futs):
            i = futs[fut]
            try:
                results[i] = fut.result()
            except Exception:
                shown = (lines[i].split('|', 1)[0].strip() or lines[i])[:60]
                results[i] = {'email': shown, 'ok': False, 'code': None, 'subject': '',
                               'date': '', 'err': 'Request failed.'}

    for i, r in enumerate(results):
        r['idx'] = offset + i
        r['line'] = lines[i]
    return results


def row_status(a: dict) -> str:
    if a.get('err'):
        return 'err'
    if a.get('code'):
        return 'ok'
    return 'pending'


def row_sig(a: dict) -> str:
    # identity of the latest code (code + mail time) - the browser compares it to spot a NEW code
    return ('%s|%s' % (a['code'], a.get('ts') or 0)) if a.get('code') else ''


def bulk_status_html(total: int, ok: int, pending: int, err: int, prog_total: int = 0) -> str:
    o = ['<div class="bk-status" data-total="%d">' % total]
    o.append('<div class="bk-stat total"><b>%d</b><span>Accounts</span></div>' % total)
    o.append('<div class="bk-stat ok"><b>%d</b><span>Code found</span></div>' % ok)
    o.append('<div class="bk-stat pending"><b>%d</b><span>Waiting</span></div>' % pending)
    o.append('<div class="bk-stat err"><b>%d</b><span>Error</span></div>' % err)
    o.append(
        '<button type="button" class="bk-auto" data-act="autoall" aria-pressed="false">'
        '<span class="dot"></span>%s<span class="lbl">Auto-refresh: OFF</span></button>' % icon('refresh')
    )
    if prog_total:
        o.append('<div class="bk-prog"><div class="bk-prog-bar"><i></i></div>'
                 '<span class="bk-prog-txt">0 / %d</span>'
                 '<button type="button" class="bk-stop">Stop</button></div>' % prog_total)
    o.append('</div>')
    return ''.join(o)


def bulk_row_html(a: dict) -> str:
    idx = a['idx']
    o = ['<div class="bk-row" data-idx="%d" data-status="%s" data-svc="%s" data-sig="%s">'
         % (idx, row_status(a), ' '.join(a.get('svcs') or []), e(row_sig(a)))]
    o.append(
        '<div class="bk-top"><span class="bk-no" title="Serial">%d</span><div class="bk-mail">%s'
        '<button type="button" class="mcp bk-ecp" data-code="%s" aria-label="Copy email" title="Copy email">%s</button></div>'
        '<div class="bk-btns">'
        '<button type="button" class="bk-full" data-idx="%d" aria-label="Full latest mail">%s<span>Full mail</span></button>'
        '<button type="button" class="bk-all" data-idx="%d" aria-label="See all messages">%s<span>See all</span></button>'
        '<button type="button" class="bk-ref" data-idx="%d" aria-label="Refresh">%s<span>Refresh</span></button>'
        '</div></div>'
        % (idx + 1, e(a.get('email') or '(unknown)'), e(a.get('email') or ''), icon('copy'), idx, icon('mail'), idx, icon('inbox'), idx, icon('refresh'))
    )
    o.append('<div class="bk-body">')
    o.append(_bk_body_html(a))
    o.append('</div></div>')
    return ''.join(o)


def bulk_shell_html(total: int) -> str:
    # empty status bar (with progress) + empty list; rows are appended chunk by chunk
    return bulk_status_html(total, 0, 0, 0, prog_total=total) + '<div class="bk-list"></div>'


def otp_bulk_html(accounts: list) -> str:
    if not accounts:
        return ('<div class="otp-box otp-none"><div class="em">\U0001F4ED</div><b>No accounts</b>'
                '<p>Paste at least one account line.</p></div>')
    ok = sum(1 for a in accounts if row_status(a) == 'ok')
    err = sum(1 for a in accounts if row_status(a) == 'err')
    pending = len(accounts) - ok - err
    return (bulk_status_html(len(accounts), ok, pending, err)
            + '<div class="bk-list">' + ''.join(bulk_row_html(a) for a in accounts) + '</div>')


def _messages_cards_html(messages: list) -> str:
    """Render the full inbox (all messages) of ONE bulk-row account, with a Full mail button each."""
    if not messages:
        return ('<div class="otp-box otp-none" style="margin-top:8px"><div class="em">📭</div>'
                '<b>No messages found</b></div>')
    o = []
    for i, m in enumerate(messages[:15]):
        if not isinstance(m, dict):
            continue
        code = otp_pick_code(m)
        o.append(mc_open(m))
        if code:
            o.append(
                '<div class="mc-top"><div class="mc-code">%s</div>'
                '<button type="button" class="mc-cp" data-code="%s" aria-label="Copy" title="Copy code">%s</button></div>'
                % (e(code), e(code), icon('copy'))
            )
        else:
            o.append('<div class="mc-top"><button type="button" class="mc-code mc-vd" data-i="%d">View details</button></div>' % i)
        subj = m.get('subject') or '(no subject)'
        frm = m.get('from')
        frm = 'Unknown' if frm is None or frm == '' else str(frm)
        o.append('<div class=\"mc-sub\">%s</div>' % e(subj))
        o.append('<div class=\"mc-meta\">%s</div>' % e(frm))
        o.append(date_line(bd_time(m.get('date')), 'mc-date', mail_ts(m.get('date'))))
        o.append('<button type="button" class="mc-full" data-i="%d">Full mail</button>' % i)
        o.append('</div>')
    return ''.join(o)


def _bk_badge(a: dict) -> str:
    b = sv_badge(a.get('svc') or '')
    return ('<div class="sv-row">%s</div>' % b) if b else ''


def _bk_body_html(a: dict) -> str:
    if a.get('err'):
        return '<div class="bk-code bk-err">%s</div>' % e(a['err'])
    if a.get('code'):
        sub = ('<div class="bk-sub">%s</div>' % e(a['subject'])) if a.get('subject') else ''
        return ('<div class="bk-top2"><div class="bk-code">%s</div>'
                '<button type="button" class="bk-cp" data-code="%s" aria-label="Copy">%s</button></div>%s%s%s'
                % (e(a['code']), e(a['code']), icon('copy'), sub, _bk_badge(a), date_line(a.get('date'), 'bk-date', a.get('ts'))))
    if a.get('subject'):
        box = '<button type="button" class="bk-code bk-vd"><span>View details</span></button>'
    else:
        box = '<div class="bk-code bk-dim">No mail yet</div>'
    return box + _bk_badge(a) + date_line(a.get('date'), 'bk-date', a.get('ts'))


# ─── HTML for result area (used by AJAX) ───
def otp_out_html(r: dict) -> str:
    o = []
    if r['err']:
        o.append('<div class="otp-err">' + e(r['err']) + '</div>')
    if r['apiErr']:
        o.append('<div class="otp-err"><b>Error:</b> ' + e(scrub(r['apiErr'])) + '</div>')

    if r['totp']:
        c = r['totp']['code']
        pretty = c[:3] + ' ' + c[3:]
        rem = int(r['totp']['rem'])
        o.append(
            '<div class="otp-result" data-totp data-rem="%d">'
            '<div class="lb">%s 2FA code</div>'
            '<div class="code">%s</div>'
            '<div class="tm"><span class="bar"><i></i></span><b class="sec">%ds</b></div>'
            '<button type="button" class="cp" data-code="%s">%s<span>Copy code</span></button>'
            '</div>' % (rem, icon('shield'), e(pretty), rem, e(c), icon('copy'))
        )

    if r['messages']:
        lst = r['messages'][:15]
        o.append('<div class="otp-found">%d email(s) found</div>' % len(lst))
        for i, m in enumerate(lst):
            if not isinstance(m, dict):
                continue
            code = otp_pick_code(m)
            o.append(mc_open(m))
            if code:
                o.append(
                    '<div class="mc-top">'
                    '<div class="mc-code">%s</div>'
                    '<button type="button" class="mc-cp" data-code="%s" aria-label="Copy" title="Copy code">%s</button>'
                    '</div>' % (e(code), e(code), icon('copy'))
                )
            else:
                o.append('<div class="mc-top"><button type="button" class="mc-code mc-vd" data-i="%d">View details</button></div>' % i)
            subj = m.get('subject') or '(no subject)'
            frm = m.get('from')
            frm = 'Unknown' if frm is None or frm == '' else str(frm)
            o.append('<div class=\"mc-sub\">%s</div>' % e(subj))
            o.append('<div class=\"mc-meta\">%s</div>' % e(frm))
            o.append(date_line(bd_time(m.get('date')), 'mc-date', mail_ts(m.get('date'))))
            o.append('<button type="button" class="mc-full" data-i="%d">Full mail</button>' % i)
            o.append('</div>')
    elif r['empty']:
        o.append(
            '<div class="otp-box otp-none"><div class="em">📭</div><b>No messages found</b>'
            '<p>The inbox is empty or no verification code was received.</p></div>'
        )
    return ''.join(o)


# ═══ Page config ═══
TABS = ['hotmail', 'email', 'roundcube', 'totp']

PANES = {
    'hotmail': {
        'icon': 'mail', 'title': 'Hotmail & Outlook', 'tab': 'Hotmail',
        'btn': 'Read All', 'busy': 'Reading inbox…', 'mailbox': True, 'multi': True,
        'hint': 'Paste one account per line (up to 1000) to read the latest code from each inbox.',
        'ph': 'user@outlook.com|refresh_token|client_id|client_secret\nuser2@hotmail.com|refresh_token|client_id|client_secret',
        'fmt': '<code>email | refresh_token | client_id | client_secret</code> &mdash; one per line',
        'tips': [
            'Supported: <code>@hotmail.com</code> <code>@outlook.com</code> <code>@live.com</code>',
            'One account per line, up to 1000 lines at once.',
            'Each account gets its own Refresh button to pull the latest code without reloading.',
            'The summary bar shows how many codes were found, are still waiting, or errored.',
            '&ldquo;Auto-refresh&rdquo; in that bar rechecks every account every 20s &mdash; large lists may be throttled by the rate limit.',
            'Rows appear live with a progress bar while reading (use Stop to cancel).',
            'A new code shows a red NEW badge and plays a sound / vibration / notification &mdash; the bell icon at the top turns alerts on or off.',
            'Your credentials are never stored.',
        ],
    },
    'email': {
        'icon': 'inbox', 'title': 'Edu / Fake Mail', 'tab': 'Edu Mail',
        'btn': 'Get Code', 'busy': 'Checking inbox…', 'mailbox': False, 'multi': False,
        'hint': 'Enter a Gmail Edu or EmailFake address — no password required.',
        'ph': 'user@emailfake.com',
        'fmt': '<code>email</code> (emailfake / Gmail Edu)',
        'tips': [
            'Just enter the address — no password needed.',
            'Example: <code>user@emailfake.com</code>',
            'Only works with Gmail Edu / EmailFake accounts.',
            'Turn on &ldquo;Auto&rdquo; to recheck every 10s while you wait for a code.',
            'A new code shows a NEW badge and plays a sound / vibration / notification (bell icon at the top turns alerts on or off).',
        ],
    },
    'roundcube': {
        'icon': 'send', 'title': 'Roundcube (wmhotmail)', 'tab': 'Roundcube',
        'btn': 'Get Code', 'busy': 'Checking inbox…', 'mailbox': False, 'multi': False,
        'hint': 'Enter wmhotmail.com credentials to read via Roundcube webmail.',
        'ph': 'user@wmhotmail.com|password',
        'fmt': '<code>email | password</code> (wmhotmail.com accounts)',
        'tips': [
            'Only works with <code>@wmhotmail.com</code> accounts.',
            'Uses Roundcube webmail mode.',
            'Turn on &ldquo;Auto&rdquo; to recheck every 10s while you wait for a code.',
            'A new code shows a NEW badge and plays a sound / vibration / notification (bell icon at the top turns alerts on or off).',
            'Your credentials are never stored.',
        ],
    },
    'totp': {
        'icon': 'shield', 'title': '2FA Key', 'tab': '2FA Key',
        'btn': 'Get 2FA Code', 'busy': 'Generating…', 'mailbox': False, 'multi': False,
        'hint': 'Paste your Base32 secret key to generate the current 6-digit code.',
        'ph': 'JBSWY3DPEHPK3PXP',
        'fmt': '<code>BASE32_SECRET</code> or full <code>otpauth://</code> URL',
        'tips': [
            'The code refreshes every 30 seconds automatically.',
            'Calculated locally — your key is never sent to any server.',
            'Spaces and dashes in the key are stripped automatically.',
        ],
    },
}

PASTE_SVG = '<rect width="8" height="4" x="8" y="2" rx="1"/><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/>'
CLEAR_SVG = '<circle cx="12" cy="12" r="10"/><path d="m15 9-6 6"/><path d="m9 9 6 6"/>'

PAGE_HEAD = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="robots" content="noindex,nofollow">
<meta name="color-scheme" content="light dark">
<meta name="theme-color" content="#f1f4f9">
<link rel="manifest" href="manifest.webmanifest">
<link rel="icon" type="image/png" href="icon-192.png">
<link rel="apple-touch-icon" href="apple-touch-icon.png">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-title" content="Read OTP">
<meta name="application-name" content="Read OTP">
<script>(function(){try{var t=localStorage.getItem("otpTheme");if(t!=="dark"&&t!=="light")t=(window.matchMedia&&matchMedia("(prefers-color-scheme: dark)").matches)?"dark":"light";document.documentElement.setAttribute("data-theme",t);var m=document.querySelector("meta[name=theme-color]");if(m)m.content=t==="dark"?"#0b1020":"#f1f4f9"}catch(e){}})();</script>
<title>Read OTP</title>
<style>
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
button,a,summary,[role=button],svg{-webkit-touch-callout:none;touch-action:manipulation}
button,[role=button]{-webkit-user-select:none;user-select:none;-webkit-appearance:none;appearance:none}
button:focus,a:focus,[tabindex]:focus,svg:focus{outline:0}
button:focus-visible,a:focus-visible{outline:2px solid #6366f1;outline-offset:2px;border-radius:inherit}
::selection{background:rgba(99,102,241,.22)}
html{-webkit-text-size-adjust:100%;font-size:16px}
body{margin:0;min-height:100vh;background:#f1f4f9;color:#1e293b;font:.94rem/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;padding:16px 12px 40px;padding-left:max(12px,env(safe-area-inset-left));padding-right:max(12px,env(safe-area-inset-right));padding-bottom:max(40px,env(safe-area-inset-bottom))}
h2,h3,h4,p,ul{margin:0}
code{background:#fff;padding:1px 6px;border-radius:5px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:0.87rem;color:#4338ca;border:1px solid #e0e7ff;overflow-wrap:anywhere;display:inline}
svg.i{width:1em;height:1em;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;display:inline-block;vertical-align:-.1em}

/* ── layout ── */
.otp-wrap{width:100%;max-width:480px;margin:0 auto}

/* hero */
.otp-hero{display:flex;align-items:center;gap:12px;padding:14px 16px;margin-bottom:12px;border-radius:16px;color:#fff;position:relative;overflow:hidden;background:linear-gradient(135deg,#4338ca,#6d28d9);box-shadow:0 12px 26px -16px rgba(67,56,202,.7)}
.otp-hero::after{content:"";position:absolute;right:-34px;top:-52px;width:130px;height:130px;border-radius:50%;background:rgba(255,255,255,.09)}
.otp-hero .hb{position:relative;z-index:1;width:36px;height:36px;border-radius:11px;background:rgba(255,255,255,.18);border:1px solid rgba(255,255,255,.28);display:flex;align-items:center;justify-content:center;flex:none}
.otp-hero .hb svg.i{width:18px;height:18px}
.otp-hero .ht{position:relative;z-index:1;min-width:0;flex:1}
.otp-hero h2{font-size:1.15rem;line-height:1.25;color:#fff}
.otp-hero p{margin-top:1px;font-size:0.9rem;line-height:1.4;color:rgba(255,255,255,.82)}

/* tabs — 4 columns */
.otp-tabs{display:grid;grid-template-columns:repeat(4,1fr);gap:4px;padding:4px;margin-bottom:12px;background:#eef1f6;border:1px solid #e2e8f0;border-radius:13px}
.otp-tabs button{display:flex;align-items:center;justify-content:center;gap:5px;min-width:0;padding:8px 4px;border:0;border-radius:10px;background:transparent;color:#64748b;font:inherit;font-size:0.84rem;font-weight:600;line-height:1.2;cursor:pointer;transition:background .15s,color .15s,box-shadow .15s;-webkit-tap-highlight-color:transparent}
.otp-tabs button svg.i{width:13px;height:13px;flex:none}
.otp-tabs button span{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.otp-tabs button:hover:not(.on){color:#334155;background:rgba(255,255,255,.6)}
.otp-tabs button.on{background:#fff;color:#4338ca;box-shadow:0 1px 3px rgba(15,23,42,.12),0 0 0 1px rgba(79,70,229,.1)}
@media(max-width:420px){.otp-tabs button svg.i{display:none}.otp-tabs button{font-size:0.8rem;padding:8px 2px}}

/* ── responsive scaling: phone → tablet → desktop ── */
@media(max-width:360px){html{font-size:14.5px}body{padding:12px 8px 32px}.otp-card{padding:13px}}
@media(min-width:600px){html{font-size:17px}.otp-wrap{max-width:620px}body{padding:28px 16px 56px}.otp-card{padding:22px}.otp-hero{padding:18px 22px}.otp-tabs button svg.i{display:inline-block}.otp-tabs button{padding:10px 6px}}
@media(min-width:1024px){html{font-size:18px}.otp-wrap{max-width:780px}body{padding:40px 24px 72px}.fm-sh{max-width:760px}}
@media(min-width:1024px) and (min-height:0){.otp-input{padding:12px 14px}.otp-go{padding:14px 18px}}

/* card */
.otp-card{background:#fff;border:1px solid #e2e8f0;border-radius:16px;padding:16px;box-shadow:0 1px 2px rgba(15,23,42,.04),0 10px 24px -16px rgba(30,27,75,.25);margin-bottom:12px}
.otp-pane[hidden]{display:none}
.otp-card h3{margin:0 0 3px;font-size:1.09rem;display:flex;align-items:center;gap:8px}
.ic{width:24px;height:24px;border-radius:8px;flex:none;background:#eef2ff;border:1px solid #e0e7ff;display:inline-flex;align-items:center;justify-content:center}
.ic svg.i{width:13px;height:13px;color:#4f46e5}
.otp-card .hint{font-size:0.92rem;color:#64748b;margin:0 0 11px;line-height:1.45}

/* input */
.otp-input{display:block;width:100%;padding:10px 12px;border:1.5px solid #d5dbe5;border-radius:11px;background:#f8fafc;color:#1e293b;font:inherit;font-size:0.97rem;line-height:1.45;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;transition:border .15s,box-shadow .15s,background .15s}
textarea.otp-input{min-height:72px;resize:vertical}
.otp-input:focus{outline:0;border-color:#4f46e5;background:#fff;box-shadow:0 0 0 3px rgba(79,70,229,.12)}
.otp-input::placeholder{color:#a0aabb}

/* format hint */
.otp-format{display:flex;align-items:flex-start;gap:8px;margin-top:8px;padding:8px 11px;background:#f6f8fb;border:1px solid #e6ebf2;border-radius:10px;font-size:0.87rem;color:#556275;line-height:1.5}
.otp-format svg.i{width:14px;height:14px;color:#4f46e5;flex:none;margin-top:1px}
.otp-format[hidden]{display:none}

/* email chip */
.otp-mail{display:flex;align-items:center;gap:8px;margin-top:8px;padding:6px 6px 6px 11px;background:#f0fdf4;border:1px solid #bbf0cc;border-radius:10px;font-size:0.9rem}
.otp-mail[hidden]{display:none}
.otp-mail .lbl{flex:none;font-size:0.76rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#15803d}
.otp-mail .mv{flex:1;min-width:0;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-weight:600;color:#14532d;overflow-wrap:anywhere}
.mcp{flex:none;width:32px;height:32px;border:1px solid #bbf0cc;border-radius:9px;background:#fff;color:#15803d;display:flex;align-items:center;justify-content:center;cursor:pointer;transition:background .15s,transform .1s}
.mcp svg.i{width:16px;height:16px}
.mcp:active{transform:scale(.93)}
.mcp.done{background:#16a34a;border-color:#16a34a;color:#fff}

/* toolbar */
.otp-tools{display:flex;align-items:center;justify-content:space-between;gap:8px;margin:0 0 6px}
.otp-tools .tl{font-size:0.85rem;font-weight:600;color:#556275}
.otp-tools .tb{display:flex;gap:6px}
.tbtn{display:inline-flex;align-items:center;gap:5px;padding:5px 10px;border:1px solid #dfe5f7;background:#f5f6ff;color:#4338ca;border-radius:8px;font:inherit;font-size:0.85rem;font-weight:600;cursor:pointer;transition:background .15s,transform .1s}
.tbtn svg.i{width:13px;height:13px}
.tbtn:hover{background:#eceffd}
.tbtn:active{transform:scale(.96)}
.tbtn[data-act=clean]{color:#b45309;background:#fff7ed;border-color:#fde3c4}
.tbtn[data-act=clean]:hover{background:#ffedd5}
.tbtn[data-act=auto]{color:#0369a1;background:#f0f9ff;border-color:#bae6fd}
.tbtn[data-act=auto]:hover{background:#e0f2fe}
.tbtn[data-act=auto].on{background:#ecfdf3;border-color:#a7e8be;color:#15803d}
.tbtn[data-act=auto].on svg.i{animation:otpSp 1.6s linear infinite}

/* bulk status summary bar */
.bk-status{display:flex;align-items:center;gap:16px;flex-wrap:wrap;margin:0 0 12px;padding:11px 14px;background:#fff;border:1px solid #e2e8f0;border-radius:14px;box-shadow:0 1px 2px rgba(15,23,42,.04)}
.bk-stat{display:flex;align-items:baseline;gap:6px}
.bk-stat b{font-size:1.18rem;font-weight:800;color:#1e293b;line-height:1}
.bk-stat span{font-size:0.8rem;color:#64748b;font-weight:600}
.bk-stat.ok b{color:#16a34a}
.bk-stat.pending b{color:#d97706}
.bk-stat.err b{color:#dc2626}
.bk-auto{margin-left:auto;display:inline-flex;align-items:center;gap:7px;padding:7px 12px;border:1.5px solid #dfe5f7;background:#f5f6ff;color:#4338ca;border-radius:99px;font:inherit;font-size:0.85rem;font-weight:700;cursor:pointer;transition:background .15s}
.bk-auto svg.i{width:13px;height:13px}
.bk-auto .dot{width:7px;height:7px;border-radius:50%;background:#94a3b8;flex:none}
.bk-auto.on{background:#ecfdf3;border-color:#a7e8be;color:#15803d}
.bk-auto.on .dot{background:#16a34a;box-shadow:0 0 0 3px rgba(22,163,74,.22)}
.bk-auto.on svg.i{animation:otpSp 1.6s linear infinite}

/* submit button */
.otp-go{display:flex;align-items:center;justify-content:center;gap:8px;width:100%;margin-top:11px;padding:12px 14px;border:0;border-radius:11px;color:#fff;font:inherit;font-weight:700;font-size:1.03rem;background:linear-gradient(135deg,#4f46e5,#6d28d9);box-shadow:0 8px 18px -10px rgba(79,70,229,.8),inset 0 1px 0 rgba(255,255,255,.2);cursor:pointer;transition:transform .12s,filter .15s}
.otp-go:hover{filter:brightness(1.06)}
.otp-go:active{transform:scale(.985)}
.otp-go svg.i{width:17px;height:17px}
.otp-go:disabled{opacity:.8;cursor:wait}
.otp-go.load svg.i{display:none}
.otp-go.load::before{content:"";width:15px;height:15px;border-radius:50%;border:2px solid rgba(255,255,255,.4);border-top-color:#fff;animation:otpSp .7s linear infinite}
@keyframes otpSp{to{transform:rotate(360deg)}}
@keyframes otpUp{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}

/* info box */
.otp-info{margin-top:12px;padding:10px 12px;border-radius:11px;background:#f5f6ff;border:1px dashed #cfd6f7;font-size:0.9rem;color:#4338ca}
.otp-info h4{margin:0 0 5px;font-size:0.76rem;letter-spacing:.1em;text-transform:uppercase;display:flex;align-items:center;gap:6px}
.otp-info h4 svg.i{width:12px;height:12px}
.otp-info ul{padding:0;list-style:none}
.otp-info li{position:relative;padding:2px 0 2px 14px;color:#556275;line-height:1.5}
.otp-info li::before{content:"";position:absolute;left:3px;top:.72em;width:4px;height:4px;border-radius:50%;background:#6366f1}

/* ── results ── */
.otp-out{display:flex;flex-direction:column}
.otp-out>.otp-found,.otp-out>.otp-err,.otp-out>.otp-result{order:-99999}
.otp-out>*{animation:otpUp .3s both}
.otp-err{background:#fef2f2;color:#b91c1c;padding:10px 12px;border-radius:11px;margin-bottom:12px;font-size:0.97rem;border:1px solid #fecaca}

/* TOTP result */
.otp-result{position:relative;overflow:hidden;text-align:center;padding:18px 16px 16px;margin-bottom:12px;border-radius:16px;background:linear-gradient(135deg,#ecfdf3,#f7fefa);border:1px solid #a7e8be}
.otp-result::before{content:"";position:absolute;left:0;right:0;top:0;height:3px;background:linear-gradient(90deg,#16a34a,#4ade80,#16a34a)}
.otp-result .lb{display:inline-flex;align-items:center;gap:6px;font-size:0.78rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#15803d}
.otp-result .lb svg.i{width:13px;height:13px}
.otp-result .code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:2.38rem;font-weight:800;letter-spacing:.18em;line-height:1.15;margin:6px 0 10px;color:#15803d;word-break:break-all}
.otp-result .tm{display:flex;align-items:center;gap:10px;max-width:240px;margin:0 auto 12px}
.otp-result .bar{flex:1;height:5px;border-radius:99px;background:#cdeed8;overflow:hidden}
.otp-result .bar i{display:block;height:100%;width:100%;border-radius:99px;background:#16a34a;transition:width .3s linear,background .3s}
.otp-result .bar.low i{background:#f59e0b}
.otp-result .sec{font-size:0.9rem;font-weight:700;color:#15803d;min-width:28px;text-align:right}
.otp-result .cp{display:inline-flex;align-items:center;gap:7px;padding:9px 20px;border:0;border-radius:10px;background:#16a34a;color:#fff;font:inherit;font-weight:600;font-size:0.97rem;box-shadow:0 8px 16px -8px rgba(22,163,74,.8);cursor:pointer;transition:transform .12s}
.otp-result .cp:active{transform:scale(.97)}
.otp-result .cp svg.i{width:15px;height:15px}
.otp-result .cp.done{background:#15803d}

/* mail list */
.otp-found{text-align:center;color:#16a34a;font-weight:600;font-size:0.94rem;margin:2px 0 10px}
.otp-none{text-align:center;padding:24px 16px;background:#fff;border:1px solid #e2e8f0;border-radius:16px;margin-bottom:12px}
.otp-none .em{font-size:1.94rem;margin-bottom:4px}
.otp-none b{font-size:1.03rem}
.otp-none p{color:#64748b;font-size:0.92rem;margin:5px 0 0}
.mc{background:#fff;border:1px solid #e2e8f0;border-radius:16px;padding:12px;margin-bottom:10px;box-shadow:0 1px 2px rgba(15,23,42,.04),0 10px 22px -16px rgba(30,27,75,.25)}
.mc-top{display:flex;gap:8px;margin-bottom:10px}
.mc-code{flex:1;min-width:0;display:flex;align-items:center;justify-content:center;padding:9px 8px;border:1.5px dashed #6366f1;border-radius:12px;background:#eef2ff;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:1.67rem;font-weight:800;letter-spacing:.2em;color:#4338ca;word-break:break-all;text-indent:.2em}
.mc-cp{flex:none;width:46px;border:1px solid #e2e8f0;border-radius:12px;background:#fff;color:#4f46e5;display:flex;align-items:center;justify-content:center;cursor:pointer;transition:background .15s,transform .1s}
.mc-cp svg.i{width:18px;height:18px}
.mc-cp:active{transform:scale(.95)}
.mc-cp.done{background:#16a34a;border-color:#16a34a;color:#fff}
.mc-sub{font-weight:700;font-size:1.01rem;line-height:1.35;color:#1e293b;overflow-wrap:anywhere}
.mc-meta{margin:3px 0 10px;color:#7b8798;font-size:0.85rem;overflow-wrap:anywhere}
.mc-full{display:block;width:100%;padding:9px;border:0;border-radius:10px;background:linear-gradient(135deg,#4f46e5,#6d28d9);color:#fff;font:inherit;font-weight:600;font-size:0.97rem;cursor:pointer;transition:filter .15s,transform .1s}
.mc-full:hover{filter:brightness(1.07)}
.mc-full:active{transform:scale(.985)}

/* bulk account list */
.bk-list{display:flex;flex-direction:column;gap:8px}
.bk-row{background:#fff;border:1px solid #e2e8f0;border-radius:13px;padding:10px 11px}
.bk-row.bk-expanded{background:#fbfbff;border-color:#dfe5f7}
.bk-top{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.bk-no{flex:none;min-width:30px;height:30px;padding:0 8px;border-radius:99px;background:#eef2ff;border:1px solid #dfe5f7;color:#4338ca;font-size:.82rem;font-weight:800;display:inline-flex;align-items:center;justify-content:center}
.bk-mail{flex:1 1 150px;min-width:0;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:0.9rem;font-weight:600;color:#1e293b;overflow-wrap:anywhere}
.bk-btns{flex:none;display:flex;gap:6px;margin-left:auto}
.bk-ref,.bk-all,.bk-full{flex:none;display:inline-flex;align-items:center;gap:7px;padding:10px 16px;min-height:42px;border:1px solid #dfe5f7;background:#f5f6ff;color:#4338ca;border-radius:11px;font:inherit;font-size:0.95rem;font-weight:700;cursor:pointer;transition:background .15s,transform .1s}
.bk-ref svg.i,.bk-all svg.i,.bk-full svg.i{width:16px;height:16px;transition:transform .5s}
.bk-ref:hover,.bk-all:hover,.bk-full:hover{background:#eceffd}
.bk-ref:active,.bk-all:active,.bk-full:active{transform:scale(.95)}
.bk-ref:disabled,.bk-all:disabled,.bk-full:disabled{opacity:.6;cursor:wait}
.bk-ref.spin svg.i{animation:otpSp 1s linear infinite}
.bk-body{margin-top:7px}
.bk-all-list{margin-top:10px;padding-top:10px;border-top:1px dashed #e6ebf2;display:flex;flex-direction:column;gap:8px}
.bk-all-list .mc{box-shadow:none}
.bk-top2{display:flex;align-items:center;gap:8px}
.bk-code{flex:1;min-width:0;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:1.21rem;font-weight:800;letter-spacing:.12em;color:#4338ca;background:#eef2ff;border:1px dashed #6366f1;border-radius:9px;padding:6px 9px;word-break:break-all}
.bk-code.bk-dim{background:#f6f8fb;border-style:solid;border-color:#e6ebf2;color:#8b96a8;font-weight:600;font-size:0.92rem;letter-spacing:0}
.bk-code.bk-err{background:#fef2f2;border-style:solid;border-color:#fecaca;color:#b91c1c;font-weight:600;font-size:0.9rem;letter-spacing:0}
.bk-cp{flex:none;width:36px;height:36px;border:1px solid #e2e8f0;border-radius:9px;background:#fff;color:#4f46e5;display:flex;align-items:center;justify-content:center;cursor:pointer;transition:background .15s,transform .1s}
.bk-cp svg.i{width:15px;height:15px}
.bk-cp:active{transform:scale(.95)}
.bk-cp.done{background:#16a34a;border-color:#16a34a;color:#fff}
.mc-date,.bk-date{display:flex;align-items:center;gap:6px;color:#64748b;font-size:0.88rem;font-weight:600;margin:0 0 10px}
.bk-date{margin:6px 0 0}
.mc-date svg.i,.bk-date svg.i{width:14px;height:14px;color:#6366f1;flex:none}
.bk-sub{margin-top:5px;font-size:0.85rem;color:#7b8798;overflow-wrap:anywhere}

/* full mail dialog */
.fm{position:fixed;inset:0;z-index:3500;display:none;align-items:center;justify-content:center;padding:14px}
.fm.open{display:flex}
.fm-bd{position:absolute;inset:0;background:rgba(15,23,42,.55)}
.fm-sh{position:relative;display:flex;flex-direction:column;width:100%;max-width:560px;height:min(86vh,720px);background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 24px 60px rgba(15,23,42,.35)}
.fm-h{display:flex;gap:10px;align-items:flex-start;padding:13px 14px;border-bottom:1px solid #eef1f6}
.fm-t{flex:1;min-width:0}
.fm-t b{display:block;font-size:1.06rem;line-height:1.35;color:#1e293b;overflow-wrap:anywhere}
.fm-t small{display:block;margin-top:2px;color:#7b8798;font-size:0.85rem;overflow-wrap:anywhere}
.fm-x{flex:none;width:30px;height:30px;border:0;border-radius:50%;background:#f1f5f9;color:#475569;font-size:20px;line-height:1;cursor:pointer}
.fm-b{flex:1;min-height:0;overflow:auto;background:#fff}
.fm-b iframe{display:block;width:100%;height:100%;border:0;background:#fff}
.fm-b pre{margin:0;padding:14px;white-space:pre-wrap;overflow-wrap:anywhere;font:inherit;font-size:0.97rem;line-height:1.6;color:#334155}

/* ── theme toggle ── */
.ha{position:relative;z-index:1;margin-left:auto;display:flex;gap:8px;flex:none}
.theme-btn[hidden]{display:none}
.theme-btn{position:relative;z-index:1;flex:none;width:40px;height:40px;border-radius:12px;border:1px solid rgba(255,255,255,.3);background:rgba(255,255,255,.18);color:#fff;display:flex;align-items:center;justify-content:center;cursor:pointer;padding:0;transition:background .2s,transform .25s}
.theme-btn span{display:flex}
.theme-btn svg.i{width:20px;height:20px}
.theme-btn .moon{display:none}
html[data-theme=dark] .theme-btn .sun{display:none}
html[data-theme=dark] .theme-btn .moon{display:flex}
.theme-btn:hover{background:rgba(255,255,255,.28)}
.theme-btn:active,.theme-btn.tap{background:rgba(255,255,255,.4);transform:rotate(25deg) scale(.94)}

/* ── copied feedback (pure CSS, so it never ends up in the saved page state) ── */
.mc-cp,.bk-cp,.mcp{position:relative}
.mc-cp.done svg.i,.bk-cp.done svg.i,.mcp.done svg.i{display:none}
.mc-cp.done::before,.bk-cp.done::before,.mcp.done::before{content:"\2713";font-weight:800;font-size:1.1rem;line-height:1}
.mc-cp.done::after,.bk-cp.done::after,.mcp.done::after{content:"Copied";position:absolute;bottom:calc(100% + 7px);right:0;z-index:6;background:#16a34a;color:#fff;font-size:.78rem;font-weight:700;line-height:1;padding:5px 9px;border-radius:7px;white-space:nowrap;pointer-events:none;box-shadow:0 6px 14px -6px rgba(22,163,74,.8);animation:otpUp .18s both}
.otp-result .cp.done span,.otp-result .cp.done svg.i{display:none}
.otp-result .cp.done::after{content:"\2713  Copied"}

/* ── tap / click colour on every button ── */
.tbtn.tap,.bk-ref.tap,.bk-all.tap,.bk-full.tap,.mc-cp.tap,.bk-cp.tap,.mcp.tap{background:#6366f1!important;border-color:#6366f1!important;color:#fff!important}
.tbtn[data-act=clean].tap{background:#f59e0b!important;border-color:#f59e0b!important;color:#fff!important}
.otp-go.tap,.mc-full.tap{background:linear-gradient(135deg,#7c3aed,#db2777)!important;box-shadow:0 8px 18px -8px rgba(219,39,119,.7)!important}
.otp-tabs button.tap:not(.on){background:#6366f1;color:#fff}
.otp-result .cp.tap{background:#0f766e}
.fm-x.tap{background:#ef4444;color:#fff}
.mc-cp.done,.bk-cp.done,.mcp.done{background:#16a34a!important;border-color:#16a34a!important;color:#fff!important}
.otp-result .cp.done{background:#15803d!important}
button{transition:background .15s,color .15s,border-color .15s,transform .1s}

/* ── dark mode ── */
html[data-theme=dark]{color-scheme:dark}
html[data-theme=dark] body{background:#0b1020;color:#e2e8f0}
html[data-theme=dark] ::selection{background:rgba(129,140,248,.35)}
html[data-theme=dark] code{background:#1e2640;color:#a5b4fc;border-color:#2e3a63}
html[data-theme=dark] .otp-hero{background:linear-gradient(135deg,#3730a3,#5b21b6);box-shadow:0 12px 26px -16px rgba(0,0,0,.8)}
html[data-theme=dark] .otp-tabs{background:#141b2e;border-color:#262f4a}
html[data-theme=dark] .otp-tabs button{color:#94a3b8}
html[data-theme=dark] .otp-tabs button:hover:not(.on){color:#e2e8f0;background:rgba(255,255,255,.06)}
html[data-theme=dark] .otp-tabs button.on{background:#232c4d;color:#c7d2fe;box-shadow:0 1px 3px rgba(0,0,0,.4),0 0 0 1px rgba(129,140,248,.25)}
html[data-theme=dark] .otp-card,html[data-theme=dark] .otp-none,html[data-theme=dark] .mc,html[data-theme=dark] .bk-row{background:#141b2e;border-color:#262f4a;box-shadow:0 1px 2px rgba(0,0,0,.3),0 10px 24px -16px rgba(0,0,0,.6)}
html[data-theme=dark] .bk-row.bk-expanded{background:#171f36;border-color:#2e3a63}
html[data-theme=dark] .ic{background:#1e2748;border-color:#2e3a63}
html[data-theme=dark] .ic svg.i,html[data-theme=dark] .otp-format svg.i,html[data-theme=dark] .mc-date svg.i,html[data-theme=dark] .bk-date svg.i{color:#a5b4fc}
html[data-theme=dark] .otp-card .hint,html[data-theme=dark] .otp-none p,html[data-theme=dark] .otp-tools .tl,html[data-theme=dark] .mc-date,html[data-theme=dark] .bk-date{color:#94a3b8}
html[data-theme=dark] .otp-input{background:#0f1526;border-color:#2e3a63;color:#e2e8f0}
html[data-theme=dark] .otp-input:focus{background:#121a30;border-color:#818cf8;box-shadow:0 0 0 3px rgba(129,140,248,.22)}
html[data-theme=dark] .otp-input::placeholder{color:#5b6784}
html[data-theme=dark] .otp-format{background:#101728;border-color:#262f4a;color:#94a3b8}
html[data-theme=dark] .otp-mail{background:#0f2a1c;border-color:#1f5a3a}
html[data-theme=dark] .otp-mail .lbl{color:#4ade80}
html[data-theme=dark] .otp-mail .mv{color:#bbf7d0}
html[data-theme=dark] .mcp{background:#12301f;border-color:#1f5a3a;color:#4ade80}
html[data-theme=dark] .tbtn,html[data-theme=dark] .bk-ref,html[data-theme=dark] .bk-all,html[data-theme=dark] .bk-full,html[data-theme=dark] .mc-cp,html[data-theme=dark] .bk-cp{background:#1e2748;border-color:#2e3a63;color:#c7d2fe}
html[data-theme=dark] .tbtn:hover,html[data-theme=dark] .bk-ref:hover,html[data-theme=dark] .bk-all:hover,html[data-theme=dark] .bk-full:hover{background:#27315a}
html[data-theme=dark] .tbtn[data-act=clean]{color:#fbbf24;background:#33260f;border-color:#5a4318}
html[data-theme=dark] .tbtn[data-act=clean]:hover{background:#40300f}
html[data-theme=dark] .tbtn[data-act=auto]{color:#7dd3fc;background:#0c2433;border-color:#155e75}
html[data-theme=dark] .tbtn[data-act=auto]:hover{background:#0e2e40}
html[data-theme=dark] .tbtn[data-act=auto].on,html[data-theme=dark] .bk-auto.on{background:#0f2a1c;border-color:#1f5a3a;color:#4ade80}
html[data-theme=dark] .bk-status{background:#141b2e;border-color:#262f4a}
html[data-theme=dark] .bk-stat b{color:#e5e9f5}
html[data-theme=dark] .bk-stat span{color:#8896b3}
html[data-theme=dark] .bk-stat.ok b{color:#4ade80}
html[data-theme=dark] .bk-stat.pending b{color:#fbbf24}
html[data-theme=dark] .bk-stat.err b{color:#fca5a5}
html[data-theme=dark] .bk-auto{background:#1e2748;border-color:#2e3a63;color:#c7d2fe}
html[data-theme=dark] .otp-info{background:#171f3a;border-color:#2e3a63;color:#a5b4fc}
html[data-theme=dark] .otp-info li{color:#94a3b8}
html[data-theme=dark] .otp-err,html[data-theme=dark] .bk-code.bk-err{background:#3a1416;color:#fca5a5;border-color:#6b2226}
html[data-theme=dark] .otp-result{background:linear-gradient(135deg,#0f2a1c,#0d2216);border-color:#1f5a3a}
html[data-theme=dark] .otp-result .lb,html[data-theme=dark] .otp-result .code,html[data-theme=dark] .otp-result .sec,html[data-theme=dark] .otp-found{color:#4ade80}
html[data-theme=dark] .otp-result .bar{background:#1f4a33}
html[data-theme=dark] .mc-code,html[data-theme=dark] .bk-code{background:#1a2248;border-color:#818cf8;color:#c7d2fe}
html[data-theme=dark] .bk-code.bk-dim{background:#101728;border-color:#262f4a;color:#8896b3}
html[data-theme=dark] .bk-no{background:#1e2748;border-color:#2e3a63;color:#c7d2fe}
html[data-theme=dark] .mc-sub,html[data-theme=dark] .bk-mail,html[data-theme=dark] .otp-none b,html[data-theme=dark] .otp-card h3{color:#e5e9f5}
html[data-theme=dark] .mc-meta,html[data-theme=dark] .bk-sub{color:#8896b3}
html[data-theme=dark] .bk-all-list{border-color:#262f4a}
html[data-theme=dark] .fm-sh{background:#141b2e}
html[data-theme=dark] .fm-h{border-color:#262f4a}
html[data-theme=dark] .fm-t b{color:#e5e9f5}
html[data-theme=dark] .fm-t small{color:#8896b3}
html[data-theme=dark] .fm-x{background:#1e2748;color:#c7d2fe}
html[data-theme=dark] .fm-b{background:#141b2e}
html[data-theme=dark] .fm-b pre{color:#cbd5e1}
html[data-theme=dark] .fm-b iframe{background:#fff}

/* ── sender badge ── */
.sv-row{margin:0 0 8px}
.bk-body .sv-row{margin:7px 0 0}
.sv{display:inline-flex;align-items:center;gap:6px;padding:3px 11px;border-radius:99px;background:var(--c);color:var(--t,#fff);font-size:.78rem;font-weight:800;letter-spacing:.02em;line-height:1.35}

/* ── filter + search ── */
.otp-filter{margin:0 0 12px;padding:11px 12px;background:#fff;border:1px solid #e2e8f0;border-radius:14px;box-shadow:0 1px 2px rgba(15,23,42,.04)}
.otp-filter[hidden]{display:none}
.fl-chips{display:flex;flex-wrap:wrap;gap:8px}
.fl-chip{display:inline-flex;align-items:center;gap:8px;padding:8px 14px;border:1.5px solid #dfe5f7;background:#f5f6ff;color:#334155;border-radius:99px;font:inherit;font-size:.92rem;font-weight:700;cursor:pointer}
.fl-chip::before{content:"";width:10px;height:10px;border-radius:50%;background:var(--c)}
.fl-chip.on{background:var(--c);border-color:var(--c);color:var(--t,#fff);box-shadow:0 6px 14px -8px var(--c)}
.fl-chip.on::before{background:var(--t,#fff)}
.fl-n{min-width:20px;padding:1px 7px;border-radius:99px;background:rgba(0,0,0,.12);font-size:.78rem;font-weight:800;text-align:center}
.fl-chip.on .fl-n{background:rgba(255,255,255,.25)}
.fl-chip.tap:not(.on){background:#6366f1;border-color:#6366f1;color:#fff}
.fl-note{margin:7px 0 0;font-size:.8rem;color:#7b8798}
.fl-search{position:relative;margin-top:9px}
.fl-search>svg.i{position:absolute;left:12px;top:50%;transform:translateY(-50%);width:16px;height:16px;color:#94a3b8;pointer-events:none}
.fl-q{display:block;width:100%;padding:10px 38px 10px 36px;border:1.5px solid #d5dbe5;border-radius:11px;background:#f8fafc;color:#1e293b;font:inherit;font-size:.95rem;-webkit-appearance:none;appearance:none}
.fl-q::-webkit-search-cancel-button{display:none}
.fl-q:focus{outline:0;border-color:#4f46e5;background:#fff;box-shadow:0 0 0 3px rgba(79,70,229,.12)}
.fl-x{position:absolute;right:6px;top:50%;transform:translateY(-50%);width:28px;height:28px;border:0;border-radius:50%;background:#e2e8f0;color:#475569;display:flex;align-items:center;justify-content:center;cursor:pointer;padding:0}
.fl-x[hidden]{display:none}
.fl-x svg.i{width:14px;height:14px}
.fl-none{margin-top:9px;text-align:center;color:#64748b;font-size:.9rem}
.fl-none[hidden]{display:none}
.fl-hide{display:none!important}
.fl-hit{border-color:#6366f1!important;box-shadow:0 0 0 2px rgba(99,102,241,.35),0 10px 22px -14px rgba(67,56,202,.6)!important}

/* ── QR scanner ── */
.tbtn[data-act=qr]{color:#0f766e;background:#f0fdfa;border-color:#b6ede4}
.tbtn[data-act=qr]:hover{background:#ccfbf1}
.qr{position:fixed;inset:0;z-index:4000;display:flex;align-items:center;justify-content:center;padding:14px}
.qr[hidden]{display:none}
.qr-bd{position:absolute;inset:0;background:rgba(15,23,42,.62)}
.qr-sh{position:relative;width:100%;max-width:420px;background:#fff;border-radius:18px;padding:14px;box-shadow:0 24px 60px rgba(15,23,42,.4)}
.qr-h{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:10px}
.qr-h b{font-size:1.05rem;color:#1e293b}
.qr-v{position:relative;aspect-ratio:1/1;border-radius:14px;overflow:hidden;background:#0b1020}
.qr-v video{position:absolute;inset:0;width:100%;height:100%;object-fit:cover}
.qr-frame{position:absolute;inset:16%;border-radius:14px;border:3px solid rgba(255,255,255,.9);box-shadow:0 0 0 999px rgba(0,0,0,.28);pointer-events:none}
.qr-frame::after{content:"";position:absolute;left:6%;right:6%;top:0;height:2px;background:#4ade80;box-shadow:0 0 12px #4ade80;animation:qrScan 2s ease-in-out infinite alternate}
@keyframes qrScan{from{top:6%}to{top:94%}}
.qr-msg{margin:10px 2px 0;text-align:center;font-size:.92rem;color:#475569;min-height:1.4em}
.qr-msg.err{color:#b91c1c}
.qr-btns{display:flex;gap:8px;justify-content:center;margin-top:12px}
.qr-btns .tbtn{padding:9px 14px;font-size:.92rem}

/* ── toast ── */
.toast{position:fixed;left:50%;bottom:calc(22px + env(safe-area-inset-bottom,0px));transform:translateX(-50%);z-index:5000;max-width:90vw;padding:11px 16px;border-radius:12px;background:#1e293b;color:#fff;font-size:.92rem;font-weight:600;text-align:center;box-shadow:0 14px 30px -10px rgba(15,23,42,.6);animation:otpUp .2s both}
.toast[hidden]{display:none}

/* dark mode — new parts */
html[data-theme=dark] .otp-filter,html[data-theme=dark] .qr-sh{background:#141b2e;border-color:#262f4a}
html[data-theme=dark] .fl-chip{background:#1e2748;border-color:#2e3a63;color:#d6dcf0}
html[data-theme=dark] .fl-chip.on{background:var(--c);border-color:var(--c);color:var(--t,#fff)}
html[data-theme=dark] .fl-note{color:#8896b3}
html[data-theme=dark] .fl-q{background:#0f1526;border-color:#2e3a63;color:#e2e8f0}
html[data-theme=dark] .fl-q:focus{background:#121a30;border-color:#818cf8;box-shadow:0 0 0 3px rgba(129,140,248,.22)}
html[data-theme=dark] .fl-x{background:#27315a;color:#c7d2fe}
html[data-theme=dark] .fl-none,html[data-theme=dark] .qr-msg{color:#94a3b8}
html[data-theme=dark] .qr-msg.err{color:#fca5a5}
html[data-theme=dark] .qr-h b{color:#e5e9f5}
html[data-theme=dark] .tbtn[data-act=qr]{color:#5eead4;background:#0f2a2a;border-color:#1f5a56}
html[data-theme=dark] .tbtn[data-act=qr]:hover{background:#133636}
html[data-theme=dark] .toast{background:#e2e8f0;color:#0f172a}
html[data-theme=dark] .fl-hit{border-color:#818cf8!important;box-shadow:0 0 0 2px rgba(129,140,248,.4),0 10px 22px -14px rgba(0,0,0,.7)!important}
/* ── NEW badge / "x min ago" / live progress / alert button ── */
.new-badge{display:inline-flex;align-items:center;flex:none;padding:2px 9px;border-radius:99px;background:#ef4444;color:#fff;font-size:.72rem;font-weight:800;letter-spacing:.06em;animation:newPulse 1.3s ease-in-out infinite}
.mc>.new-badge{margin:0 0 8px}
@keyframes newPulse{50%{box-shadow:0 0 0 5px rgba(239,68,68,.2)}}
.bk-row.bk-isnew{border-color:#ef4444;box-shadow:0 0 0 2px rgba(239,68,68,.16)}
.ago{margin-left:4px;color:#7b8798;font-weight:700}
.ago.fresh{color:#16a34a}
.bk-prog{flex:1 1 100%;display:flex;align-items:center;gap:10px;order:99}
.bk-prog-bar{flex:1;height:8px;border-radius:99px;background:#e2e8f0;overflow:hidden}
.bk-prog-bar i{display:block;height:100%;width:0;border-radius:99px;background:linear-gradient(90deg,#4f46e5,#6d28d9);transition:width .3s}
.bk-prog-txt{font-size:.85rem;font-weight:800;color:#4338ca;min-width:74px;text-align:right}
.bk-stop{flex:none;padding:5px 12px;border:1px solid #fecaca;background:#fef2f2;color:#b91c1c;border-radius:8px;font:inherit;font-size:.82rem;font-weight:700;cursor:pointer}
.alert-btn .boff{display:none}
.alert-btn.off{opacity:.65}
.alert-btn.off .bon{display:none}
.alert-btn.off .boff{display:flex}
html[data-theme=dark] .bk-prog-bar{background:#262f4a}
html[data-theme=dark] .bk-prog-txt{color:#c7d2fe}
html[data-theme=dark] .bk-stop{background:#3a1416;border-color:#6b2226;color:#fca5a5}
html[data-theme=dark] .ago{color:#8896b3}
html[data-theme=dark] .ago.fresh{color:#4ade80}
.mc-code.mc-vd{font-family:inherit;font-size:1.05rem;font-weight:700;letter-spacing:0;text-indent:0;cursor:pointer}
.bk-code.bk-vd{display:block;width:100%;text-align:center;cursor:pointer;font-family:inherit;font-size:.97rem;font-weight:700;letter-spacing:0}
.bk-code.bk-vd span{pointer-events:none}
html[data-theme=dark] .bk-code.bk-vd{background:#1a2248;border:1px dashed #818cf8;color:#c7d2fe}
.otp-pane.has-out .otp-info{display:none}
.bk-ecp{display:inline-flex;vertical-align:middle;margin-left:6px;width:26px;height:26px;border-radius:8px;border-color:#dfe5f7;background:#f5f6ff;color:#4f46e5}
.bk-ecp svg.i{width:14px;height:14px}
html[data-theme=dark] .bk-ecp{background:#1e2748;border-color:#2e3a63;color:#c7d2fe}
</style>
</head>
<body>
"""

PAGE_JS = r"""
(function(){
  var wrap = document.getElementById('otpWrap');
  if (!wrap) return;
  var csrf = wrap.dataset.csrf, timers = {}, busy = {}, mails = {}, bulkAccounts = {}, rowMails = {};
  var autoChk = {}, bulkAutoTimer = null;
  var stopFlag = {}, lastIn = {}, newSig = {};

  function qs(s, r){ return (r||document).querySelector(s); }
  function qsa(s, r){ return [].slice.call((r||document).querySelectorAll(s)); }

  /* ── tabs ── */
  function setTab(t){
    qsa('.otp-tabs button').forEach(function(b){
      var on = b.dataset.tab === t;
      b.classList.toggle('on', on);
      b.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    qsa('.otp-pane').forEach(function(p){ p.hidden = p.dataset.pane !== t; });
    try{ history.replaceState(null, '', '?tab=' + t); } catch(e){}
    if (t === 'totp' && qs('.otp-pane[data-pane="totp"] [data-totp]')) run('totp', true);
  }
  qsa('.otp-tabs button').forEach(function(b){
    b.addEventListener('click', function(){ setTab(b.dataset.tab); });
  });

  /* ── TOTP countdown ── */
  function startTotp(tab, out){
    clearInterval(timers[tab]);
    var el = qs('[data-totp]', out); if (!el) return;
    var end  = Date.now() + (parseInt(el.dataset.rem, 10) || 30) * 1000,
        bar  = qs('.bar', el),
        fill = qs('.bar i', el),
        sec  = qs('.sec', el),
        pane = out.parentNode;
    function tick(){
      if (pane.hidden || !document.body.contains(el)){ clearInterval(timers[tab]); return; }
      var left = Math.max(0, Math.ceil((end - Date.now()) / 1000));
      sec.textContent = left + 's';
      fill.style.width = (left / 30 * 100) + '%';
      bar.classList.toggle('low', left <= 5);
      if (left <= 0){ clearInterval(timers[tab]); run(tab, true); }
    }
    tick(); timers[tab] = setInterval(tick, 250);
  }

  /* ── email chip ── */
  var EM = /[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}/;
  function syncMail(f){
    var box = qs('.otp-mail', f); if (!box) return;
    var line = (f.elements.data.value.split(/\r?\n/)[0] || '').split('|')[0];
    var m = line.match(EM);
    box.hidden = !m;
    qs('.otp-format', f).hidden = !!m;
    if (m){ qs('.mv', box).textContent = m[0]; qs('.mcp', box).dataset.code = m[0]; }
  }

  /* ── clean pasted text ── */
  function clean(v){
    return String(v)
      .replace(/[\u200B-\u200D\uFEFF]/g, '')
      .replace(/\r/g, '')
      .split('\n')
      .map(function(l){ return l.split('|').map(function(x){ return x.trim(); }).join('|').trim(); })
      .filter(Boolean)
      .join('\n');
  }

  /* ── per-form listeners ── */
  qsa('.otp-form').forEach(function(f){
    var inp = f.elements.data;
    inp.addEventListener('input',  function(){ syncMail(f); });
    inp.addEventListener('paste',  function(){ setTimeout(function(){ inp.value = clean(inp.value); syncMail(f); }, 0); });

    f.addEventListener('click', function(e){
      var b = e.target.closest('.tbtn'); if (!b) return;
      var tab = f.dataset.tab, s = qs('span', b), orig = s.textContent;
      if (b.dataset.act === 'qr'){ openQr(); return; }
      if (b.dataset.act === 'auto'){ toggleAutoCheck(tab, b); return; }
      if (b.dataset.act === 'clean'){
        inp.value = ''; syncMail(f); clearInterval(timers[tab]); delete mails[tab];
        disableAutoCheck(tab, qs('.tbtn[data-act="auto"]', f));
        setBulkAuto(tab, false);
        stopFlag[tab] = true; lastIn[tab] = ''; delete newSig[tab];
        f.closest('.otp-pane').classList.remove('has-out');
        qs('.otp-out', f.closest('.otp-pane')).innerHTML = ''; inp.focus(); return;
      }
      // paste from clipboard
      function got(t){ inp.value = clean(t); syncMail(f); try{ inp.dispatchEvent(new Event('input')); } catch(x){} inp.focus(); s.textContent = 'Pasted!'; setTimeout(function(){ s.textContent = orig; }, 1300); }
      function hint(){ openPaste(got); }   // clipboard blocked / not HTTPS -> small paste box
      if (navigator.clipboard && navigator.clipboard.readText && window.isSecureContext)
        navigator.clipboard.readText().then(function(t){ t ? got(t) : hint(); }, hint);
      else hint();
    });
  });

  /* ── fetch OTP ── */
  function run(tab, silent){
    var pane = qs('.otp-pane[data-pane="' + tab + '"]'),
        f    = qs('form', pane),
        inp  = f.elements.data,
        btn  = qs('.otp-go', f),
        lab  = qs('span', btn),
        out  = qs('.otp-out', pane);

    if (!silent) inp.value = clean(inp.value);
    if (!inp.value.trim()){ inp.focus(); return; }
    if (busy[tab]) return;
    busy[tab] = true;
    if (!silent){
      btn.disabled = true;
      btn.classList.add('load');
      lab.textContent = btn.dataset.busy || 'Checking\u2026';
      askNotif(); audioCtx();
    }

    fetch(location.pathname, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'X-Requested-With': 'fetch', 'Accept': 'application/json' },
      body: new URLSearchParams({ ajax: '1', csrf: csrf, tab: tab, data: inp.value })
    })
    .then(function(r){ return r.json().catch(function(){ throw new Error(r.status); }); })
    .then(function(j){
      var prevHad = lastIn[tab] === inp.value && !!out.innerHTML.trim() && !qs('.otp-err', out), prevSig = firstSig(out);
      out.innerHTML = j.html;
      mails[tab] = j.mails || [];
      if (tab !== 'totp') trackNew(tab, out, inp.value, prevHad, prevSig);
      startTotp(tab, out);
      if (!silent){
        var el = qs('.mc-top, .otp-result, .otp-err', out) || out;
        setTimeout(function(){ try{ el.scrollIntoView({ behavior: 'smooth', block: 'center' }); } catch(e){} }, 60);
      }
    })
    .catch(function(){
      if (!silent) out.innerHTML = '<div class="otp-err">Request failed. Check your connection or reload the page.</div>';
    })
    .then(function(){
      busy[tab] = false;
      btn.disabled = false;
      btn.classList.remove('load');
      lab.textContent = btn.dataset.label;
    });
  }

  /* ── bulk hotmail/outlook read: rows appear live (in chunks) with a progress bar ── */
  var BULK_CHUNK = 24, BULK_LIMIT = 1000;
  function runBulk(f){
    var tab  = f.dataset.tab,
        inp  = f.elements.data,
        btn  = qs('.otp-go', f),
        lab  = qs('span', btn),
        pane = f.closest('.otp-pane'),
        out  = qs('.otp-out', pane);

    inp.value = clean(inp.value);
    if (!inp.value.trim()){ inp.focus(); return; }
    if (busy[tab]) return;

    var lines = inp.value.split('\n').filter(Boolean);
    if (lines.length > BULK_LIMIT){ lines = lines.slice(0, BULK_LIMIT); toast('Only the first ' + BULK_LIMIT + ' lines are read.'); }
    var total = lines.length, pos = 0, tries = 0, map = {};
    bulkAccounts[tab] = map;
    busy[tab] = true; stopFlag[tab] = false;
    pane.classList.add('has-out');   // hide the Instructions box while results are shown
    btn.disabled = true; btn.classList.add('load');
    lab.textContent = btn.dataset.busy || 'Reading…';
    askNotif(); audioCtx();
    out.innerHTML = '<div class="otp-found">Reading 0 / ' + total + '…</div>';

    function finish(note){
      busy[tab] = false;
      btn.disabled = false; btn.classList.remove('load');
      lab.textContent = btn.dataset.label;
      var pg = qs('.bk-prog', out); if (pg) pg.parentNode.removeChild(pg);
      updateBkStatus(tab);
      if (bulkAutoTimer) setBulkAuto(tab, true);   // re-bind to the freshly rendered status bar
      if (note) toast(note, 5000);
    }
    function retry(j){
      if (stopFlag[tab]){ finish(); return; }
      if (!(j && j._st === 403) && ++tries <= 3){ setTimeout(step, 4000 * tries); return; }
      if (!qs('.bk-list', out)) out.innerHTML = (j && j.html) || '<div class="otp-err">Request failed. Check your connection or reload the page.</div>';
      finish('Stopped at ' + pos + ' / ' + total + ' — press Read All again');
    }
    function step(){
      if (stopFlag[tab] || pos >= total){
        finish(stopFlag[tab] && pos < total && qs('.bk-row', out) ? 'Stopped at ' + pos + ' / ' + total : '');
        return;
      }
      var chunk = lines.slice(pos, pos + BULK_CHUNK);
      fetch(location.pathname, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'X-Requested-With': 'fetch', 'Accept': 'application/json' },
        body: new URLSearchParams({ ajax: '1', csrf: csrf, tab: tab, bulk_chunk: '1', start: pos, total: total, data: chunk.join('\n') })
      })
      .then(function(r){ return r.json().then(function(j){ j._st = r.status; return j; }); })
      .then(function(j){
        if (stopFlag[tab]){ finish(); return; }
        if (j._st !== 200){ retry(j); return; }
        if (j.shell) out.innerHTML = j.shell;
        var list = qs('.bk-list', out);
        if (!list){ finish(); return; }
        list.insertAdjacentHTML('beforeend', j.rows || '');
        (j.accounts || []).forEach(function(a){ map[a.idx] = a.line; });
        pos += chunk.length; tries = 0;
        var pb = qs('.bk-prog-bar i', out), pt = qs('.bk-prog-txt', out);
        if (pb) pb.style.width = Math.round(pos / total * 100) + '%';
        if (pt) pt.textContent = pos + ' / ' + total;
        lab.textContent = (btn.dataset.busy || 'Reading…') + ' ' + pos + '/' + total;
        updateBkStatus(tab);
        if (j.shell){
          var first = qs('.bk-row', out);
          if (first) setTimeout(function(){ try{ first.scrollIntoView({ behavior: 'smooth', block: 'center' }); } catch(e){} }, 60);
        }
        step();
      })
      .catch(function(){ retry(null); });
    }
    step();
  }

  /* refresh ONE account's latest code in place, no page reload */
  function refreshRow(tab, idx, btn){
    var line = (bulkAccounts[tab] || {})[idx];
    if (!line) return;
    var row = btn.closest('.bk-row'), body = qs('.bk-body', row);
    btn.disabled = true;
    btn.classList.add('spin');
    fetch(location.pathname, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'X-Requested-With': 'fetch', 'Accept': 'application/json' },
      body: new URLSearchParams({ ajax: '1', csrf: csrf, tab: tab, refresh_line: '1', data: line })
    })
    .then(function(r){ return r.json().catch(function(){ throw new Error(r.status); }); })
    .then(function(j){
      if (body && j.bodyHtml) body.innerHTML = j.bodyHtml;
      if (j.svc !== undefined) row.setAttribute('data-svc', j.svc);
      if (j.status) row.dataset.status = j.status;
      var prevSig = row.getAttribute('data-sig') || '';
      if (j.sig !== undefined) row.setAttribute('data-sig', j.sig);
      if (j.code && j.sig && j.sig !== prevSig && isFresh(j.ts)) markNew(row, j.email, j.code);
      updateBkStatus(tab);
    })
    .catch(function(){ /* keep previous value shown on failure */ })
    .then(function(){
      btn.disabled = false;
      btn.classList.remove('spin');
      if (row.classList.contains('bk-expanded')) loadAllInto(tab, idx, row);
    });
  }

  /* status-summary bar: recount accounts by their current data-status */
  function updateBkStatus(tab){
    var pane = qs('.otp-pane[data-pane="' + tab + '"]'); if (!pane) return;
    var bar = qs('.bk-status', pane); if (!bar) return;
    var rows = qsa('.bk-row', pane), ok = 0, err = 0;
    rows.forEach(function(r){
      if (r.dataset.status === 'ok') ok++;
      else if (r.dataset.status === 'err') err++;
    });
    var set = function(sel, v){ var el = qs(sel, bar); if (el) el.textContent = v; };
    set('.bk-stat.total b', bar.getAttribute('data-total') || rows.length);
    set('.bk-stat.ok b', ok);
    set('.bk-stat.pending b', rows.length - ok - err);
    set('.bk-stat.err b', err);
  }

  /* auto-refresh ALL bulk accounts, staggered so the per-minute rate limit isn't hammered at once */
  function runAutoAllOnce(tab){
    if (busy[tab]) return;   // initial live read still running
    var pane = qs('.otp-pane[data-pane="' + tab + '"]'); if (!pane) return;
    var btns = qsa('.bk-ref', pane).filter(function(b){ return !b.disabled; });
    btns.forEach(function(b, i){
      setTimeout(function(){
        if (document.body.contains(b) && !b.disabled) refreshRow(tab, parseInt(b.dataset.idx, 10), b);
      }, i * 400);
    });
  }
  function setBulkAuto(tab, on){
    var pane = qs('.otp-pane[data-pane="' + tab + '"]');
    var btn = pane ? qs('.bk-auto', pane) : null;
    clearInterval(bulkAutoTimer); bulkAutoTimer = null;
    if (btn){
      btn.classList.toggle('on', on);
      btn.setAttribute('aria-pressed', on ? 'true' : 'false');
      var lbl = qs('.lbl', btn); if (lbl) lbl.textContent = 'Auto-refresh: ' + (on ? 'ON' : 'OFF');
    }
    if (on) bulkAutoTimer = setInterval(function(){ runAutoAllOnce(tab); }, 20000);
    saveSoon();
  }
  wrap.addEventListener('click', function(e){
    var b = e.target.closest('.bk-auto'); if (!b) return;
    var pane = b.closest('.otp-pane');
    setBulkAuto(pane.dataset.pane, !b.classList.contains('on'));
  });

  /* auto-check a single-account tab (Edu Mail / Roundcube) on a timer */
  function enableAutoCheck(tab, btn){
    if (!btn || autoChk[tab]) return;
    btn.classList.add('on'); btn.setAttribute('aria-pressed', 'true');
    var lbl = qs('span', btn); if (lbl) lbl.textContent = 'Auto: ON';
    autoChk[tab] = setInterval(function(){ run(tab, true); }, 10000);
  }
  function disableAutoCheck(tab, btn){
    clearInterval(autoChk[tab]); delete autoChk[tab];
    if (btn){ btn.classList.remove('on'); btn.setAttribute('aria-pressed', 'false'); var lbl = qs('span', btn); if (lbl) lbl.textContent = 'Auto: OFF'; }
  }
  function toggleAutoCheck(tab, btn){
    if (autoChk[tab]) disableAutoCheck(tab, btn); else enableAutoCheck(tab, btn);
    saveSoon();
  }

  /* "See all": fetch every inbox message for ONE account and show it under the row */
  function loadAllInto(tab, idx, row){
    var line = (bulkAccounts[tab] || {})[idx];
    if (!line) return Promise.resolve();
    return fetch(location.pathname, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'X-Requested-With': 'fetch', 'Accept': 'application/json' },
      body: new URLSearchParams({ ajax: '1', csrf: csrf, tab: tab, list_all: '1', idx: idx, data: line })
    })
    .then(function(r){ return r.json().catch(function(){ throw new Error(r.status); }); })
    .then(function(j){
      rowMails[idx] = j.mails || [];
      var listEl = qs('.bk-all-list', row);
      if (!listEl){ listEl = document.createElement('div'); listEl.className = 'bk-all-list'; row.appendChild(listEl); }
      listEl.innerHTML = j.html || '';
    })
    .catch(function(){
      var listEl = qs('.bk-all-list', row);
      if (!listEl){ listEl = document.createElement('div'); listEl.className = 'bk-all-list'; row.appendChild(listEl); }
      listEl.innerHTML = '<div class="otp-err">Request failed.</div>';
    });
  }

  function toggleAll(tab, idx, btn){
    var row = btn.closest('.bk-row'), lab = qs('span', btn);
    if (row.classList.contains('bk-expanded')){
      row.classList.remove('bk-expanded');
      var listEl = qs('.bk-all-list', row);
      if (listEl) listEl.innerHTML = '';
      lab.textContent = 'See all';
      return;
    }
    btn.disabled = true;
    loadAllInto(tab, idx, row).then(function(){
      row.classList.add('bk-expanded');
      lab.textContent = 'Hide all';
      btn.disabled = false;
    });
  }

  wrap.addEventListener('click', function(e){
    var b = e.target.closest('.bk-ref'); if (!b) return;
    var pane = b.closest('.otp-pane');
    refreshRow(pane.dataset.pane, parseInt(b.dataset.idx, 10), b);
  });

  /* "Full mail" on a bulk row: open the latest email of that account directly */
  wrap.addEventListener('click', function(e){
    var b = e.target.closest('.bk-full, .bk-vd'); if (!b) return;
    var pane = b.closest('.otp-pane'), tab = pane.dataset.pane, idx = parseInt(b.dataset.idx || b.closest('.bk-row').dataset.idx, 10);
    var line = (bulkAccounts[tab] || {})[idx]; if (!line) return;
    var lab = qs('span', b), orig = lab.textContent;
    b.disabled = true; lab.textContent = 'Loading\u2026';
    fetch(location.pathname, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'X-Requested-With': 'fetch', 'Accept': 'application/json' },
      body: new URLSearchParams({ ajax: '1', csrf: csrf, tab: tab, list_all: '1', idx: idx, data: line })
    })
    .then(function(r){ return r.json().catch(function(){ throw new Error(r.status); }); })
    .then(function(j){
      var m = (j.mails || [])[0];
      if (m) openFM(m); else toast('No email found for this account.');
    })
    .catch(function(){ toast('Request failed. Try again.'); })
    .then(function(){ b.disabled = false; lab.textContent = orig; });
  });

  wrap.addEventListener('click', function(e){
    var b = e.target.closest('.bk-all'); if (!b) return;
    var pane = b.closest('.otp-pane');
    toggleAll(pane.dataset.pane, parseInt(b.dataset.idx, 10), b);
  });

  qsa('.otp-form').forEach(function(f){
    f.addEventListener('submit', function(e){
      e.preventDefault();
      if (f.dataset.tab === 'hotmail') runBulk(f); else run(f.dataset.tab, false);
    });
    if (f.elements.data.tagName === 'TEXTAREA')
      f.elements.data.addEventListener('keydown', function(e){
        if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)){
          e.preventDefault();
          if (f.dataset.tab === 'hotmail') runBulk(f); else run(f.dataset.tab, false);
        }
      });
  });

  /* ── copy buttons ── */
  wrap.addEventListener('click', function(e){
    var b = e.target.closest('.cp, .mc-cp, .mcp, .bk-cp'); if (!b || !b.dataset.code) return;
    var t = b.dataset.code;
    function done(){ b.classList.remove('tap'); b.classList.add('done'); clearTimeout(b._dt); b._dt = setTimeout(function(){ b.classList.remove('done'); }, 1600); }
    function fb(){ var a = document.createElement('textarea'); a.value = t; a.style.cssText = 'position:fixed;left:-9999px'; document.body.appendChild(a); a.select(); try{ document.execCommand('copy'); } catch(x){} document.body.removeChild(a); done(); }
    if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(t).then(done, fb); else fb();
  });

  /* ── full mail dialog ── */
  var FM = null;
  function buildFM(){
    FM = document.createElement('div');
    FM.className = 'fm';
    FM.setAttribute('aria-hidden', 'true');
    FM.innerHTML =
      '<div class="fm-bd" data-x></div>' +
      '<div class="fm-sh" role="dialog" aria-modal="true">' +
        '<div class="fm-h"><div class="fm-t"><b></b><small></small></div>' +
        '<button type="button" class="fm-x" data-x aria-label="Close">&times;</button></div>' +
        '<div class="fm-b"></div>' +
      '</div>';
    document.body.appendChild(FM);
    FM.addEventListener('click', function(e){ if (e.target.closest('[data-x]')) closeFM(); });
    document.addEventListener('keydown', function(e){ if (e.key === 'Escape' && FM.classList.contains('open')) closeFM(); });
  }
  function closeFM(){
    FM.classList.remove('open');
    FM.setAttribute('aria-hidden', 'true');
    qs('.fm-b', FM).innerHTML = '';
    document.documentElement.style.overflow = '';
  }
  function openFM(m){
    if (!FM) buildFM();
    qs('.fm-t b', FM).textContent = m.subject || '(no subject)';
    qs('.fm-t small', FM).textContent = [m.from, m.date].filter(Boolean).join(' \u2022 ');
    var box = qs('.fm-b', FM);
    box.innerHTML = '';
    if (!m.body){
      var pre = document.createElement('pre'); pre.textContent = 'Full message body is not available for this email.'; box.appendChild(pre);
    } else if (m.html){
      var fr = document.createElement('iframe');
      fr.setAttribute('sandbox', 'allow-popups allow-popups-to-escape-sandbox');
      fr.setAttribute('referrerpolicy', 'no-referrer');
      fr.srcdoc = '<base target="_blank"><meta name="viewport" content="width=device-width,initial-scale=1"><style>body{margin:12px;font-family:system-ui,sans-serif;font-size:16px;line-height:1.55;color:#1e293b;word-break:break-word}img{max-width:100%;height:auto}</style>' + m.body;
      box.appendChild(fr);
    } else {
      var pr = document.createElement('pre'); pr.textContent = m.body; box.appendChild(pr);
    }
    FM.classList.add('open');
    FM.setAttribute('aria-hidden', 'false');
    document.documentElement.style.overflow = 'hidden';
  }

  wrap.addEventListener('click', function(e){
    var b = e.target.closest('.mc-full, .mc-vd'); if (!b) return;
    var i = parseInt(b.dataset.i, 10);
    var bkRow = b.closest('.bk-row');
    var m = bkRow
      ? (rowMails[bkRow.dataset.idx] || [])[i]
      : (mails[b.closest('.otp-pane').dataset.pane] || [])[i];
    if (m) openFM(m);
  });

  /* ── service filter + search: matching items jump to the top ── */
  var flt = { chips: [], raw: '', q: '' }, fltT = null;
  function filterSoon(){ clearTimeout(fltT); fltT = setTimeout(applyFilter, 60); }

  function directMc(list){ return [].slice.call(list.children).filter(function(c){ return c.classList && c.classList.contains('mc'); }); }

  function sortHide(items){
    var shown = 0;
    items.forEach(function(it, i){
      var svcs = (it.getAttribute('data-svc') || '').split(' ').filter(Boolean);
      var hit = flt.chips.length > 0 && svcs.some(function(x){ return flt.chips.indexOf(x) > -1; });
      var vis = !flt.q || it.textContent.toLowerCase().indexOf(flt.q) > -1;
      it.classList.toggle('fl-hit', hit && vis);
      it.classList.toggle('fl-hide', !vis);
      it.style.order = String(hit ? i - 100000 : i);
      if (vis) shown++;
    });
    return shown;
  }

  var SVC = __SVC_JSON__;

  /* brands that actually arrived in this inbox -> chips (with counts) */
  function buildChips(bar, items){
    var counts = {}, order = [];
    items.forEach(function(it){
      (it.getAttribute('data-svc') || '').split(' ').filter(Boolean).forEach(function(k){
        if (!SVC[k]) return;
        if (!counts[k]){ counts[k] = 0; order.push(k); }
        counts[k]++;
      });
    });
    order.sort(function(a, b){ return counts[b] - counts[a]; });
    flt.chips = flt.chips.filter(function(k){ return counts[k]; });   // drop brands no longer present
    var box = qs('.fl-chips', bar); if (!box) return;
    var sig = order.map(function(k){ return k + ':' + counts[k]; }).join('|');
    if (box.getAttribute('data-sig') !== sig){
      box.setAttribute('data-sig', sig);
      box.innerHTML = order.map(function(k){
        var v = SVC[k];
        return '<button type="button" class="fl-chip" data-svc="' + k + '" aria-pressed="false" style="--c:' + v[1] + ';--t:' + v[2] + '">'
             + v[0] + '<span class="fl-n">' + counts[k] + '</span></button>';
      }).join('');
    }
    var note = qs('.fl-note', bar);
    if (note) note.hidden = !order.length;
  }

  function applyFilter(){
    ['hotmail', 'email', 'roundcube'].forEach(function(tab){
      var pane = qs('.otp-pane[data-pane="' + tab + '"]'); if (!pane) return;
      var bar = qs('.otp-filter', pane), out = qs('.otp-out', pane); if (!bar || !out) return;
      var has = !!qs('.bk-row, .mc', out);
      bar.hidden = !has;
      var shown = 0, bl = qs('.bk-list', out), items;
      if (bl) items = [].slice.call(bl.children).filter(function(c){ return c.classList.contains('bk-row'); });
      else    items = directMc(out);
      if (has) buildChips(bar, items);
      shown = sortHide(items);
      qsa('.bk-all-list', out).forEach(function(l){ sortHide(directMc(l)); });
      qs('.fl-none', bar).hidden = !(has && flt.q && shown === 0);
      qsa('.fl-chip', bar).forEach(function(c){
        var on = flt.chips.indexOf(c.dataset.svc) > -1;
        c.classList.toggle('on', on); c.setAttribute('aria-pressed', on ? 'true' : 'false');
      });
      var inp = qs('.fl-q', bar);
      if (inp && document.activeElement !== inp && inp.value !== flt.raw) inp.value = flt.raw;
      qs('.fl-x', bar).hidden = !flt.raw;
    });
  }

  wrap.addEventListener('click', function(e){
    var c = e.target.closest('.fl-chip');
    if (c){
      var i = flt.chips.indexOf(c.dataset.svc);
      if (i > -1) flt.chips.splice(i, 1); else flt.chips.push(c.dataset.svc);
      applyFilter(); saveSoon(); return;
    }
    var x = e.target.closest('.fl-x');
    if (x){ flt.raw = ''; flt.q = ''; applyFilter(); saveSoon(); }
  });
  wrap.addEventListener('input', function(e){
    if (!e.target.classList || !e.target.classList.contains('fl-q')) return;
    flt.raw = e.target.value; flt.q = flt.raw.trim().toLowerCase();
    applyFilter(); saveSoon();
  });

  /* ── keep page state (tab, inputs, results) across leaving / reloading ── */
  var STORE_KEY = 'otpPageState.v1', STORE_TTL = 24 * 60 * 60 * 1000, saveTimer = null, restoring = true;

  function saveState(){
    if (restoring) return;
    var st = { t: Date.now(), tab: (qs('.otp-tabs button.on') || {dataset:{}}).dataset.tab || 'hotmail',
               panes: {}, mails: mails, bulk: bulkAccounts, rowMails: rowMails, filter: { chips: flt.chips, q: flt.raw },
               auto: Object.keys(autoChk), bulkAuto: !!bulkAutoTimer };
    qsa('.otp-pane').forEach(function(p){
      st.panes[p.dataset.pane] = { v: qs('.otp-input', p).value, h: qs('.otp-out', p).innerHTML };
    });
    try{
      localStorage.setItem(STORE_KEY, JSON.stringify(st));
    } catch(e){
      try{ st.mails = {}; st.rowMails = {}; localStorage.setItem(STORE_KEY, JSON.stringify(st)); } catch(x){}
    }
  }
  function saveSoon(){ clearTimeout(saveTimer); saveTimer = setTimeout(saveState, 400); }

  function restoreState(){
    var st = null;
    try{ st = JSON.parse(localStorage.getItem(STORE_KEY) || 'null'); } catch(e){}
    if (!st || !st.panes || (Date.now() - (st.t || 0)) > STORE_TTL){ restoring = false; return; }
    qsa('.otp-pane').forEach(function(p){
      var d = st.panes[p.dataset.pane]; if (!d) return;
      var f = qs('form', p);
      f.elements.data.value = d.v || '';
      syncMail(f);
      qs('.otp-out', p).innerHTML = d.h || '';
      if (qs('.bk-row', p)) p.classList.add('has-out');
    });
    mails = st.mails || {};
    bulkAccounts = st.bulk || {};
    rowMails = st.rowMails || {};
    if (st.filter){ flt.chips = (st.filter.chips || []).filter(String); flt.raw = st.filter.q || ''; flt.q = flt.raw.trim().toLowerCase(); }
    applyFilter();
    // a refresh that was running when the page closed must not stay stuck
    qsa('.bk-ref.spin').forEach(function(b){ b.classList.remove('spin'); });
    qsa('.done, .tap').forEach(function(b){ b.classList.remove('done'); b.classList.remove('tap'); });
    qsa('.bk-ref:disabled, .bk-all:disabled').forEach(function(b){ b.disabled = false; });
    qsa('.new-badge, .bk-prog').forEach(function(b){ b.parentNode.removeChild(b); });
    qsa('.bk-isnew').forEach(function(b){ b.classList.remove('bk-isnew'); });
    (st.auto || []).forEach(function(t){
      var p = qs('.otp-pane[data-pane="' + t + '"]'); if (!p) return;
      enableAutoCheck(t, qs('.tbtn[data-act="auto"]', p));
    });
    if (st.bulkAuto) setBulkAuto('hotmail', true);
    restoring = false;
    if (st.tab) setTab(st.tab);   // also refreshes the TOTP code when that tab is shown
  }

  restoreState();
  restoring = false;

  qsa('.otp-input').forEach(function(i){ i.addEventListener('input', saveSoon); });
  wrap.addEventListener('click', function(){ setTimeout(saveSoon, 60); });
  new MutationObserver(function(recs){
    for (var i = 0; i < recs.length; i++){
      var n = recs[i].target; if (n.nodeType === 3) n = n.parentNode;
      if (!(n && n.closest && n.closest('[data-totp], .ago'))){ saveSoon(); filterSoon(); agoSoon(); return; }  // ignore countdown ticks
    }
  }).observe(wrap, { childList: true, subtree: true, characterData: true });
  document.addEventListener('visibilitychange', function(){ if (document.visibilityState === 'hidden') saveState(); });
  window.addEventListener('pagehide', saveState);
  window.addEventListener('pageshow', function(ev){ if (ev.persisted && qs('.otp-pane[data-pane="totp"]:not([hidden]) [data-totp]')) run('totp', true); });

  /* ── live "x min ago" labels ── */
  var agoT = null;
  function fmtAgo(s){
    if (s < 45) return 'just now';
    var m = Math.max(1, Math.floor(s / 60));
    if (m < 60) return m + ' min ago';
    var h = Math.floor(s / 3600);
    if (h < 24) return h + ' hr ago';
    var d = Math.floor(s / 86400);
    return d + ' day' + (d > 1 ? 's' : '') + ' ago';
  }
  function updateAgo(){
    var now = Date.now() / 1000;
    qsa('.ago').forEach(function(el){
      var ts = +el.getAttribute('data-ts'); if (!ts) return;
      var s = Math.max(0, now - ts), t = '· ' + fmtAgo(s);
      if (el.textContent !== t) el.textContent = t;
      el.classList.toggle('fresh', s < 300);
    });
  }
  function agoSoon(){ clearTimeout(agoT); agoT = setTimeout(updateAgo, 80); }
  setInterval(updateAgo, 15000);
  updateAgo();

  /* ── NEW code detection + alerts (sound, vibration, notification) ── */
  var alertsOn = true, actx = null, lastBeep = 0, ab = document.getElementById('alertBtn');
  try{ alertsOn = localStorage.getItem('otpAlerts') !== 'off'; } catch(e){}
  function paintAlert(){ if (ab){ ab.classList.toggle('off', !alertsOn); ab.setAttribute('aria-pressed', alertsOn ? 'true' : 'false'); } }
  paintAlert();
  function audioCtx(){
    try{
      if (!actx){ var C = window.AudioContext || window.webkitAudioContext; if (C) actx = new C(); }
      if (actx && actx.state === 'suspended') actx.resume();
    } catch(e){}
    return actx;
  }
  document.addEventListener('pointerdown', function(){ if (!actx || actx.state !== 'running') audioCtx(); }, true);
  function beep(){
    var c = audioCtx(); if (!c) return;
    var t = c.currentTime;
    [880, 1175].forEach(function(fr, i){
      var o = c.createOscillator(), g = c.createGain(), st = t + i * 0.17;
      o.type = 'sine'; o.frequency.value = fr; o.connect(g); g.connect(c.destination);
      g.gain.setValueAtTime(0.0001, st);
      g.gain.exponentialRampToValueAtTime(0.28, st + 0.02);
      g.gain.exponentialRampToValueAtTime(0.0001, st + 0.16);
      o.start(st); o.stop(st + 0.17);
    });
  }
  function askNotif(){
    try{ if (alertsOn && 'Notification' in window && Notification.permission === 'default') Notification.requestPermission(); } catch(e){}
  }
  function sysNotify(title, body, tag){
    var opts = { body: body, tag: tag, renotify: true, icon: 'icon-192.png', vibrate: [180, 80, 180] };
    function fallback(){ try{ new Notification(title, opts); } catch(e){} }
    if (navigator.serviceWorker && navigator.serviceWorker.getRegistration){
      navigator.serviceWorker.getRegistration().then(function(r){ if (r && r.showNotification) r.showNotification(title, opts); else fallback(); }, fallback);
    } else fallback();
  }
  function notifyNew(email, code){
    if (!alertsOn) return;
    var now = Date.now();
    if (now - lastBeep > 1500){
      lastBeep = now; beep();
      if (navigator.vibrate) try{ navigator.vibrate([180, 80, 180]); } catch(e){}
    }
    toast('NEW code: ' + code + (email ? '  •  ' + email : ''), 4500);
    if ('Notification' in window && Notification.permission === 'granted' && (document.hidden || !document.hasFocus()))
      sysNotify('New code: ' + code, email || '', 'otp-' + (email || 'x'));
  }
  function isFresh(ts){ ts = +ts || 0; return !ts || (Date.now() / 1000 - ts) < 1800; }   // ignore codes older than 30 min
  function markNew(row, email, code){
    row.classList.add('bk-isnew');
    if (!qs('.new-badge', row)){
      var b = document.createElement('span'); b.className = 'new-badge'; b.textContent = 'NEW';
      var top = qs('.bk-top', row); if (top) top.insertBefore(b, qs('.bk-mail', top));
    }
    notifyNew(email, code);
  }
  /* single-account tabs: signature of the newest mail's code */
  function firstSig(out){
    var mc = qs('.mc', out); if (!mc) return '';
    var c = qs('.mc-code:not(.mc-vd)', mc);
    return c ? c.textContent + '|' + (mc.getAttribute('data-ts') || '') : '';
  }
  function trackNew(tab, out, val, prevHad, prevSig){
    var ns = firstSig(out), mc = qs('.mc', out);
    if (prevHad && ns && ns !== prevSig && isFresh(mc.getAttribute('data-ts'))){
      newSig[tab] = ns;
      notifyNew((val.split(/\r?\n/)[0] || '').split('|')[0], qs('.mc-code:not(.mc-vd)', mc).textContent);
    }
    lastIn[tab] = val;
    if (ns && newSig[tab] === ns && !qs('.new-badge', mc)){
      var b = document.createElement('span'); b.className = 'new-badge'; b.textContent = 'NEW';
      mc.insertBefore(b, mc.firstChild);
    }
  }
  if (ab) ab.addEventListener('click', function(){
    alertsOn = !alertsOn;
    try{ localStorage.setItem('otpAlerts', alertsOn ? 'on' : 'off'); } catch(e){}
    paintAlert();
    if (alertsOn){
      askNotif(); beep();
      if (navigator.vibrate) try{ navigator.vibrate(120); } catch(x){}
      toast('Alerts ON — sound, vibration & notification for new codes');
    } else toast('Alerts OFF');
  });
  /* copying a code = "seen": drop its NEW badge */
  wrap.addEventListener('click', function(e){
    var c = e.target.closest('.bk-cp, .mc-cp'); if (!c) return;
    var row = c.closest('.bk-row');
    if (row){
      row.classList.remove('bk-isnew');
      var nb = qs('.bk-top .new-badge', row); if (nb) nb.parentNode.removeChild(nb);
    } else {
      var mc = c.closest('.mc'), pane = c.closest('.otp-pane');
      if (pane) delete newSig[pane.dataset.pane];
      var b2 = mc && qs('.new-badge', mc); if (b2) b2.parentNode.removeChild(b2);
    }
  });
  /* Stop button of the live bulk read */
  wrap.addEventListener('click', function(e){
    var s_ = e.target.closest('.bk-stop'); if (!s_) return;
    stopFlag[s_.closest('.otp-pane').dataset.pane] = true;
    s_.disabled = true; s_.textContent = 'Stopping…';
  });

  /* ── paste box: fallback when the browser blocks direct clipboard reading ── */
  var pasteCb = null;
  function closePaste(){ var b = document.getElementById('pasteBox'); if (b) b.hidden = true; pasteCb = null; }
  function openPaste(cb){
    var b = document.getElementById('pasteBox'); if (!b) return;
    var ta = document.getElementById('pasteTa'); ta.value = ''; pasteCb = cb; b.hidden = false;
    setTimeout(function(){ try{ ta.focus(); } catch(e){} }, 60);
  }
  function applyPaste(){
    var ta = document.getElementById('pasteTa'), v = ta.value, cb = pasteCb;
    if (!v.trim()) return;
    closePaste(); if (cb) cb(v);
  }
  (function(){
    var b = document.getElementById('pasteBox'); if (!b) return;
    var ta = document.getElementById('pasteTa');
    ta.addEventListener('paste', function(){ setTimeout(applyPaste, 0); });
    b.addEventListener('click', function(e){
      var x = e.target.closest('[data-pm]'); if (!x) return;
      if (x.dataset.pm === 'ok') applyPaste(); else closePaste();
    });
    document.addEventListener('keydown', function(e){ if (e.key === 'Escape' && !b.hidden) closePaste(); });
  })();

  /* ── dark / light toggle ── */
  (function(){
    var root = document.documentElement, tb = document.getElementById('themeBtn');
    function apply(t, save){
      root.setAttribute('data-theme', t);
      var m = document.querySelector('meta[name=theme-color]'); if (m) m.content = t === 'dark' ? '#0b1020' : '#f1f4f9';
      if (tb) tb.setAttribute('aria-pressed', t === 'dark' ? 'true' : 'false');
      if (save){ try{ localStorage.setItem('otpTheme', t); } catch(e){} }
    }
    apply(root.getAttribute('data-theme') === 'dark' ? 'dark' : 'light', false);
    if (tb) tb.addEventListener('click', function(){ apply(root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark', true); });
    try{
      var mq = matchMedia('(prefers-color-scheme: dark)');
      var follow = function(ev){ var st = null; try{ st = localStorage.getItem('otpTheme'); } catch(e){} if (st !== 'dark' && st !== 'light') apply(ev.matches ? 'dark' : 'light', false); };
      if (mq.addEventListener) mq.addEventListener('change', follow);
    } catch(e){}
  })();

  /* ── press colour on every button ── */
  function tapOn(ev){
    var b = ev.target && ev.target.closest ? ev.target.closest('button') : null;
    if (!b || b.disabled) return;
    b.classList.add('tap'); clearTimeout(b._tt);
    b._tt = setTimeout(function(){ b.classList.remove('tap'); }, 450);
  }
  document.addEventListener('pointerdown', tapOn, true);
  document.addEventListener('click', tapOn, true);


  /* ── small toast ── */
  var toastT = null;
  function toast(msg, ms){
    var t = document.getElementById('toast'); if (!t) return;
    t.textContent = msg; t.hidden = false; clearTimeout(toastT);
    toastT = setTimeout(function(){ t.hidden = true; }, ms || 3500);
  }

  /* ── QR scanner for the 2FA tab ── */
  var qrS = { stream: null, raf: 0, det: null, busy: false, last: 0, on: false };
  function qrEl(id){ return document.getElementById(id); }
  function qrMsg(t, err){ var m = qrEl('qrMsg'); m.textContent = t; m.classList.toggle('err', !!err); }

  function loadJsQR(){
    if (window.jsQR) return Promise.resolve(window.jsQR);
    var urls = ['https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.js', 'https://cdnjs.cloudflare.com/ajax/libs/jsQR/1.4.0/jsQR.min.js'];
    function tryOne(i){
      if (i >= urls.length) return Promise.reject(new Error('jsQR'));
      return new Promise(function(res, rej){
        var sc = document.createElement('script'); sc.src = urls[i];
        sc.onload = function(){ window.jsQR ? res(window.jsQR) : rej(); };
        sc.onerror = rej; document.head.appendChild(sc);
      }).catch(function(){ return tryOne(i + 1); });
    }
    return tryOne(0);
  }

  function decodeWithJsQR(src){
    return loadJsQR().then(function(jsQR){
      var w = src.videoWidth || src.naturalWidth || src.width, h = src.videoHeight || src.naturalHeight || src.height;
      if (!w || !h) return null;
      var k = Math.min(1, 720 / Math.max(w, h)), cw = Math.round(w * k), ch = Math.round(h * k);
      var cv = document.createElement('canvas'); cv.width = cw; cv.height = ch;
      var cx = cv.getContext('2d', { willReadFrequently: true }); cx.drawImage(src, 0, 0, cw, ch);
      var d = cx.getImageData(0, 0, cw, ch), r = jsQR(d.data, cw, ch, { inversionAttempts: 'attemptBoth' });
      return r ? r.data : null;
    });
  }

  function decodeQr(src){
    if ('BarcodeDetector' in window){
      try{
        qrS.det = qrS.det || new BarcodeDetector({ formats: ['qr_code'] });
        return qrS.det.detect(src).then(function(r){ return r && r[0] ? r[0].rawValue : null; })
          .catch(function(){ return decodeWithJsQR(src); });
      } catch(e){}
    }
    return decodeWithJsQR(src);
  }

  function qrStop(){
    qrS.on = false; cancelAnimationFrame(qrS.raf);
    if (qrS.stream){ qrS.stream.getTracks().forEach(function(t){ t.stop(); }); qrS.stream = null; }
    var v = qrEl('qrVideo'); if (v){ try{ v.pause(); } catch(e){} v.srcObject = null; }
  }
  function closeQr(){ qrStop(); qrEl('qrBox').hidden = true; }

  function qrAccept(text){
    var t = String(text || '').trim();
    if (/^otpauth-migration:/i.test(t)){ qrMsg('This is a Google Authenticator export QR. Use the original setup QR instead.', true); return false; }
    if (/^otpauth:\/\/totp\//i.test(t) || /^[A-Z2-7][A-Z2-7\s-]{14,}=*$/i.test(t)){
      var inp = qs('.otp-pane[data-pane="totp"] .otp-input');
      inp.value = t; closeQr();
      if (navigator.vibrate) try{ navigator.vibrate(60); } catch(e){}
      run('totp'); return true;
    }
    qrMsg('This QR does not contain a 2FA key. Try another one.', true); return false;
  }

  function qrLoop(ts){
    if (!qrS.on) return;
    var v = qrEl('qrVideo');
    if (ts - qrS.last > 180 && !qrS.busy && v.readyState >= 2){
      qrS.last = ts; qrS.busy = true;
      decodeQr(v).then(function(t){ qrS.busy = false; if (t && qrS.on) qrAccept(t); })
                 .catch(function(){ qrS.busy = false; });
    }
    qrS.raf = requestAnimationFrame(qrLoop);
  }

  function openQr(){
    var box = qrEl('qrBox'); box.hidden = false; qrMsg('Starting camera\u2026', false);
    if (!(navigator.mediaDevices && navigator.mediaDevices.getUserMedia) || !window.isSecureContext){
      qrMsg('Live camera needs HTTPS. Tap \u201cUpload QR image\u201d instead.', true); return;
    }
    navigator.mediaDevices.getUserMedia({ video: { facingMode: { ideal: 'environment' } }, audio: false })
      .then(function(stream){
        if (box.hidden){ stream.getTracks().forEach(function(t){ t.stop(); }); return; }
        qrS.stream = stream; qrS.on = true;
        var v = qrEl('qrVideo'); v.srcObject = stream; v.play().catch(function(){});
        qrMsg('Point the camera at the QR code.', false);
        qrS.raf = requestAnimationFrame(qrLoop);
      })
      .catch(function(){ qrMsg('Camera is blocked or unavailable. Allow camera access, or tap \u201cUpload QR image\u201d.', true); });
  }

  function qrFromFile(file){
    if (!file) return;
    qrMsg('Reading image\u2026', false);
    var p = (window.createImageBitmap ? createImageBitmap(file) : Promise.reject())
      .catch(function(){
        return new Promise(function(res, rej){
          var im = new Image(); im.onload = function(){ res(im); }; im.onerror = rej; im.src = URL.createObjectURL(file);
        });
      });
    p.then(function(img){ return decodeQr(img); })
     .then(function(t){ if (!t) qrMsg('No QR code found in that image.', true); else qrAccept(t); })
     .catch(function(){ qrMsg('Could not read that image.', true); });
  }

  (function(){
    var box = qrEl('qrBox'); if (!box) return;
    box.addEventListener('click', function(e){
      var b = e.target.closest('[data-qr]'); if (!b) return;
      if (b.dataset.qr === 'close') closeQr();
      else if (b.dataset.qr === 'file') qrEl('qrFile').click();
    });
    qrEl('qrFile').addEventListener('change', function(){ qrFromFile(this.files && this.files[0]); this.value = ''; });
    document.addEventListener('keydown', function(e){ if (e.key === 'Escape' && !box.hidden) closeQr(); });
    document.addEventListener('visibilitychange', function(){ if (document.hidden && !box.hidden) closeQr(); });
  })();

  /* ── Add to home screen (PWA) ── */
  (function(){
    var ib = document.getElementById('installBtn'), dp = null;
    var standalone = (window.matchMedia && matchMedia('(display-mode: standalone)').matches) || window.navigator.standalone === true;
    if ('serviceWorker' in navigator && (location.protocol === 'https:' || location.hostname === 'localhost' || location.hostname === '127.0.0.1')){
      navigator.serviceWorker.register('sw.js').catch(function(){});
    }
    if (!ib || standalone) return;
    var ios = /iphone|ipad|ipod/i.test(navigator.userAgent);
    if (ios) ib.hidden = false;
    window.addEventListener('beforeinstallprompt', function(ev){ ev.preventDefault(); dp = ev; ib.hidden = false; });
    window.addEventListener('appinstalled', function(){ ib.hidden = true; dp = null; toast('Added to your home screen \u2713'); });
    ib.addEventListener('click', function(){
      if (dp){ dp.prompt(); dp.userChoice.then(function(){ dp = null; ib.hidden = true; }); }
      else toast('Tap the Share button \u2B06\uFE0F, then \u201cAdd to Home Screen\u201d.', 6000);
    });
  })();

})();
"""


FILTER_BAR = (
    '    <div class="otp-filter" hidden>\n'
    '      <div class="fl-chips" role="group" aria-label="Filter by service">\n'
    + '      </div>\n'
    '      <div class="fl-note">Inbox-এ যেসব brand এর mail এসেছে সেগুলো এখানে। Tap করলে ওই brand এর mail ওপরে আসবে।</div>\n'
    '      <div class="fl-search">' + icon('search') +
    '<input type="search" class="fl-q" placeholder="Search email, subject or code&hellip;" autocomplete="off" spellcheck="false" aria-label="Search">'
    '<button type="button" class="fl-x" aria-label="Clear search" hidden>' + icon('x') + '</button></div>\n'
    '      <div class="fl-none" hidden>No match found.</div>\n'
    '    </div>\n'
)

QR_MODAL = (
    '<div class="qr" id="qrBox" hidden>\n'
    '  <div class="qr-bd" data-qr="close"></div>\n'
    '  <div class="qr-sh" role="dialog" aria-modal="true" aria-label="Scan 2FA QR code">\n'
    '    <div class="qr-h"><b>Scan 2FA QR code</b><button type="button" class="fm-x" data-qr="close" aria-label="Close">%s</button></div>\n'
    '    <div class="qr-v"><video id="qrVideo" playsinline muted></video><div class="qr-frame"></div></div>\n'
    '    <p class="qr-msg" id="qrMsg">Point the camera at the QR code.</p>\n'
    '    <div class="qr-btns">\n'
    '      <button type="button" class="tbtn" data-qr="file">Upload QR image</button>\n'
    '      <button type="button" class="tbtn" data-qr="close">Cancel</button>\n'
    '    </div>\n'
    '    <input type="file" id="qrFile" accept="image/*" hidden>\n'
    '  </div>\n'
    '</div>\n'
)


PASTE_MODAL = (
    '<div class="qr" id="pasteBox" hidden>\n'
    '  <div class="qr-bd" data-pm="close"></div>\n'
    '  <div class="qr-sh" role="dialog" aria-modal="true" aria-label="Paste">\n'
    '    <div class="qr-h"><b>Paste your data</b></div>\n'
    '    <textarea class="otp-input" id="pasteTa" rows="5" spellcheck="false" placeholder="Tap and hold here, then choose Paste (or press Ctrl+V)"></textarea>\n'
    '    <p class="qr-msg">It is filled in automatically as soon as you paste.</p>\n'
    '    <div class="qr-btns">\n'
    '      <button type="button" class="tbtn" data-pm="ok">Use text</button>\n'
    '      <button type="button" class="tbtn" data-pm="close">Cancel</button>\n'
    '    </div>\n'
    '  </div>\n'
    '</div>\n'
)


def render_page(tab: str, csrf: str) -> str:
    o = [PAGE_HEAD]
    o.append('\n<div class="otp-wrap" id="otpWrap" data-csrf="%s">\n' % e(csrf))

    # hero
    o.append(
        '\n  <!-- hero -->\n  <div class="otp-hero">\n'
        '    <div class="hb">%s</div>\n'
        '    <div class="ht"><h2>Read OTP</h2><p>Fast &amp; simple &mdash; no key required.</p></div>\n'
        '    <div class="ha">\n'
        '      <button type="button" class="theme-btn" id="installBtn" aria-label="Add to home screen" title="Add to home screen" hidden>'
        '<span>%s</span></button>\n'
        '      <button type="button" class="theme-btn alert-btn" id="alertBtn" aria-label="New code alerts" title="Alerts: sound / vibration / notification" aria-pressed="true">'
        '<span class="bon">%s</span><span class="boff">%s</span></button>\n'
        '      <button type="button" class="theme-btn" id="themeBtn" aria-label="Toggle dark mode" title="Dark / Light mode">'
        '<span class="sun">%s</span><span class="moon">%s</span></button>\n'
        '    </div>\n'
        '  </div>\n' % (icon('key'), icon('download'), icon('bell'), icon('bell-off'), icon('sun'), icon('moon'))
    )

    # tabs
    o.append('\n  <!-- tabs -->\n  <div class="otp-tabs" role="tablist" aria-label="OTP method">\n')
    for k in TABS:
        p = PANES[k]
        on = tab == k
        o.append(
            '    <button type="button" role="tab" data-tab="%s" class="%s" aria-selected="%s">\n'
            '      %s<span>%s</span>\n    </button>\n'
            % (k, 'on' if on else '', 'true' if on else 'false', icon(p['icon']), e(p['tab']))
        )
    o.append('  </div>\n')

    # panes
    o.append('\n  <!-- panes -->\n')
    for k in TABS:
        p = PANES[k]
        if p['multi']:
            label = 'Account data'
        elif k == 'totp':
            label = '2FA secret key'
        elif k == 'roundcube':
            label = 'Account data'
        else:
            label = 'Email address'

        o.append('  <div class="otp-pane" data-pane="%s"%s>\n' % (k, '' if tab == k else ' hidden'))
        o.append('    <div class="otp-card">\n')
        o.append('      <h3><span class="ic">%s</span>%s</h3>\n' % (icon(p['icon']), e(p['title'])))
        o.append('      <p class="hint">%s</p>\n' % e(p['hint']))
        o.append('      <form class="otp-form" data-tab="%s" autocomplete="off" novalidate>\n' % k)

        # toolbar
        qr_btn = ('            <button type="button" class="tbtn" data-act="qr">\n'
                  '              %s\n              <span>Scan QR</span>\n            </button>\n' % icon('qr')) if k == 'totp' else ''
        auto_btn = (
            '            <button type="button" class="tbtn" data-act="auto" aria-pressed="false">\n'
            '              %s\n              <span>Auto: OFF</span>\n            </button>\n' % icon('refresh')
        ) if (k != 'totp' and not p['multi']) else ''
        o.append(
            (
                '        <div class="otp-tools">\n'
                '          <span class="tl">%s</span>\n'
                '          <span class="tb">\n'
                + qr_btn + auto_btn +
                '            <button type="button" class="tbtn" data-act="paste">\n'
                '              %s\n              <span>Paste</span>\n            </button>\n'
                '            <button type="button" class="tbtn" data-act="clean">\n'
                '              %s\n              <span>Clear</span>\n            </button>\n'
                '          </span>\n        </div>\n'
            ) % (label, otp_svg(PASTE_SVG), otp_svg(CLEAR_SVG))
        )

        # input
        if p['multi']:
            o.append('        <textarea class="otp-input" name="data" rows="6" spellcheck="false" placeholder="%s"></textarea>\n' % e(p['ph']))
        else:
            o.append('        <input class="otp-input" type="text" name="data" spellcheck="false" autocapitalize="off" placeholder="%s">\n' % e(p['ph']))

        # format hint / email chip
        o.append('        <div class="otp-format">%s<span>Format: %s</span></div>\n' % (icon('shield'), p['fmt']))
        if p['mailbox']:
            o.append(
                '        <div class="otp-mail" hidden>\n'
                '          <span class="lbl">Email</span><b class="mv"></b>\n'
                '          <button type="button" class="mcp" data-code="" aria-label="Copy email">%s</button>\n'
                '        </div>\n' % icon('copy')
            )

        o.append(
            '        <button type="submit" class="otp-go" data-label="%s" data-busy="%s">\n'
            '          %s<span>%s</span>\n        </button>\n'
            '      </form>\n' % (e(p['btn']), e(p['busy']), icon('send'), e(p['btn']))
        )

        o.append(
            '      <div class="otp-info">\n        <h4>%s Instructions</h4>\n        <ul>%s</ul>\n      </div>\n'
            % (icon('shield'), ''.join('<li>%s</li>' % t for t in p['tips']))
        )
        o.append('    </div>\n')
        if k != 'totp':
            o.append(FILTER_BAR)
        o.append('    <div class="otp-out" aria-live="polite"></div>\n  </div>\n')

    o.append('\n</div><!-- /otp-wrap -->\n')
    o.append(QR_MODAL % icon('x'))
    o.append(PASTE_MODAL)
    o.append('<div class="toast" id="toast" role="status" aria-live="polite" hidden></div>\n')
    o.append('\n<script>')
    o.append(PAGE_JS.replace('__SVC_JSON__', json.dumps({k: list(v) for k, v in SERVICE_MAP.items()}).replace('</', '<\\/')))
    o.append('</script>\n</body>\n</html>\n')
    return ''.join(o)


# ═══ Route (page + AJAX handler) ═══
def _json(payload: dict, status: int = 200) -> Response:
    resp = Response(json.dumps(payload, ensure_ascii=False), status=status,
                    mimetype='application/json')
    resp.headers['Content-Type'] = 'application/json; charset=utf-8'
    resp.headers['Cache-Control'] = 'no-store'
    return resp


@app.route('/', methods=['GET', 'POST'])
@app.route('/otp_page', methods=['GET', 'POST'])
def index():
    if not session.get('csrf'):
        session['csrf'] = secrets.token_hex(16)

    # ═══ AJAX handler ═══
    if request.method == 'POST' and 'ajax' in request.form:
        if not hmac.compare_digest(session['csrf'], request.form.get('csrf', '')):
            return _json({'html': '<div class="otp-err">Session expired. Reload the page.</div>',
                          'mails': []}, 403)

        bulk_chunk = bool(request.form.get('bulk_chunk'))
        if not (rate_ok('bulk', BULK_CHUNK_RATE) if bulk_chunk else rate_ok()):
            return _json({'html': '<div class="otp-err">Too many requests. Wait a minute and try again.</div>',
                          'mails': []}, 429)

        valid_tabs = ('hotmail', 'email', 'totp', 'roundcube')
        t = request.form.get('tab', '')
        if t not in valid_tabs:
            t = 'hotmail'

        # ── single-account refresh of one row from a bulk hotmail read ──
        if t == 'hotmail' and request.form.get('refresh_line'):
            line = request.form.get('data', '')
            acc = fetch_hotmail_account(line)
            return _json({'ok': acc['ok'], 'bodyHtml': _bk_body_html(acc),
                          'svc': ' '.join(acc.get('svcs') or []), 'status': row_status(acc),
                          'code': acc.get('code') or '', 'sig': row_sig(acc),
                          'ts': acc.get('ts') or 0, 'email': acc.get('email') or ''})

        # ── "See all": every inbox message for ONE bulk-row account ──
        if t == 'hotmail' and request.form.get('list_all'):
            line = request.form.get('data', '')
            if parse_hotmail_line(line) is None:
                return _json({'ok': False, 'html': '<div class="otp-err">Invalid account line.</div>', 'mails': []})

            res = mg_call('/api/get-inbox', {'data': line, 'mode': 'oauth'})
            base = {'err': '', 'apiErr': '', 'messages': [], 'found': None, 'totp': None, 'empty': False}
            r = otp_parse_response(base, res)
            if r['apiErr']:
                return _json({'ok': False, 'html': '<div class="otp-err">%s</div>' % e(r['apiErr']), 'mails': []})

            msgs = [m for m in r['messages'][:15] if isinstance(m, dict)]
            mails = []
            for m in msgs:
                body, is_html = otp_mail_body(m)
                mails.append({
                    'subject': str(m.get('subject') or '(no subject)'),
                    'from':    str(m.get('from') or ''),
                    'date':    bd_time(m.get('date')),
                    'body':    body,
                    'html':    is_html,
                })
            return _json({'ok': True, 'html': _messages_cards_html(msgs), 'mails': mails})

        # ── bulk hotmail/outlook read: every pasted line is its own account ──
        # ── live bulk read: the browser sends the lines in small chunks and draws rows as they finish ──
        if t == 'hotmail' and bulk_chunk:
            try:
                start = max(0, int(request.form.get('start', '0')))
                total = max(1, min(BULK_MAX_LINES, int(request.form.get('total', '1'))))
            except ValueError:
                start, total = 0, 1
            if start >= BULK_MAX_LINES:
                return _json({'shell': '', 'rows': '', 'accounts': []})
            accounts = otp_run_bulk(request.form.get('data', ''), BULK_CHUNK_MAX, start)
            return _json({
                'shell': bulk_shell_html(total) if start == 0 else '',
                'rows': ''.join(bulk_row_html(a) for a in accounts),
                'accounts': [{'idx': a['idx'], 'line': a['line']} for a in accounts],
            })

        if t == 'hotmail':
            accounts = otp_run_bulk(request.form.get('data', ''))
            return _json({
                'html': otp_bulk_html(accounts),
                'accounts': [{'idx': a['idx'], 'line': a['line']} for a in accounts],
            })

        r = otp_run(t, request.form.get('data', ''))

        mails = []
        for m in r['messages'][:15]:
            if not isinstance(m, dict):
                continue
            body, is_html = otp_mail_body(m)
            mails.append({
                'subject': str(m.get('subject') or '(no subject)'),
                'from':    str(m.get('from') or ''),
                'date':    bd_time(m.get('date')),
                'body':    body,
                'html':    is_html,
            })
        return _json({'html': otp_out_html(r), 'mails': mails})

    # ═══ Page ═══
    tab = request.args.get('tab', '')
    if tab not in TABS:
        tab = 'hotmail'
    return Response(render_page(tab, session['csrf']), mimetype='text/html')


# ═══ PWA: manifest, service worker, generated icons (no extra libraries needed) ═══
def _png_icon(size: int, maskable: bool = False) -> bytes:
    """Draw the app icon (indigo gradient + white padlock) as a PNG with plain Python."""
    S = size
    r_bg = 0.0 if maskable else S * 0.22
    scale = 0.74 if maskable else 1.0
    c1, c2 = (67, 56, 202), (109, 40, 217)

    def box(px, py, cx, cy, hw, hh, r=0.0):
        qx = abs(px - cx) - (hw - r)
        qy = abs(py - cy) - (hh - r)
        return math.hypot(max(qx, 0.0), max(qy, 0.0)) + min(max(qx, qy), 0.0) - r

    raw = bytearray()
    for y in range(S):
        raw.append(0)
        for x in range(S):
            px, py = x + 0.5, y + 0.5
            if r_bg:
                a = min(max(0.5 - box(px, py, S / 2, S / 2, S / 2, S / 2, r_bg), 0.0), 1.0)
            else:
                a = 1.0
            t = (px + py) / (2.0 * S)
            R = c1[0] + (c2[0] - c1[0]) * t
            G = c1[1] + (c2[1] - c1[1]) * t
            B = c1[2] + (c2[2] - c1[2]) * t
            u = (px - S / 2) / (S * scale) + 0.5
            v = (py - S / 2) / (S * scale) + 0.5
            if 0.22 < u < 0.78 and 0.2 < v < 0.8:
                d_body = box(u, v, 0.5, 0.60, 0.22, 0.16, 0.05)
                d_ring = abs(math.hypot(u - 0.5, v - 0.43) - 0.1225) - 0.0275
                d_arch = max(d_ring, v - 0.43)
                d_leg = min(box(u, v, 0.5 - 0.1225, 0.47, 0.0275, 0.05),
                            box(u, v, 0.5 + 0.1225, 0.47, 0.0275, 0.05))
                d = min(d_body, d_arch, d_leg)
                d_hole = min(math.hypot(u - 0.5, v - 0.585) - 0.035, box(u, v, 0.5, 0.635, 0.014, 0.04))
                d = max(d, -d_hole)
                g = min(max(0.5 - d * S * scale, 0.0), 1.0)
                R += (255 - R) * g
                G += (255 - G) * g
                B += (255 - B) * g
            raw += bytes((int(R), int(G), int(B), int(a * 255)))

    def chunk(tag, data):
        c = struct.pack('>I', len(data)) + tag + data
        return c + struct.pack('>I', zlib.crc32(tag + data) & 0xffffffff)

    return (b'\x89PNG\r\n\x1a\n'
            + chunk(b'IHDR', struct.pack('>IIBBBBB', S, S, 8, 6, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(bytes(raw), 9))
            + chunk(b'IEND', b''))


_ICON_CACHE = {}


def _icon_response(size: int, maskable: bool = False) -> Response:
    key = (size, maskable)
    if key not in _ICON_CACHE:
        _ICON_CACHE[key] = _png_icon(size, maskable)
    resp = Response(_ICON_CACHE[key], mimetype='image/png')
    resp.headers['Cache-Control'] = 'public, max-age=604800'
    return resp


@app.route('/icon-192.png')
def pwa_icon_192():
    return _icon_response(192)


@app.route('/icon-512.png')
def pwa_icon_512():
    return _icon_response(512)


@app.route('/icon-maskable-512.png')
def pwa_icon_maskable():
    return _icon_response(512, True)


@app.route('/apple-touch-icon.png')
def pwa_icon_apple():
    return _icon_response(180, True)


@app.route('/manifest.webmanifest')
def pwa_manifest():
    data = {
        'name': 'Read OTP',
        'short_name': 'Read OTP',
        'description': 'Read OTP codes and 2FA keys fast.',
        'start_url': './',
        'scope': './',
        'display': 'standalone',
        'orientation': 'portrait',
        'background_color': '#f1f4f9',
        'theme_color': '#4338ca',
        'icons': [
            {'src': 'icon-192.png', 'sizes': '192x192', 'type': 'image/png', 'purpose': 'any'},
            {'src': 'icon-512.png', 'sizes': '512x512', 'type': 'image/png', 'purpose': 'any'},
            {'src': 'icon-maskable-512.png', 'sizes': '512x512', 'type': 'image/png', 'purpose': 'maskable'},
        ],
    }
    resp = Response(json.dumps(data), mimetype='application/manifest+json')
    resp.headers['Cache-Control'] = 'no-cache'
    return resp


_SW_JS = """\
const OFFLINE = '<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Offline</title><body style="font-family:system-ui;display:grid;place-items:center;min-height:100vh;margin:0;background:#f1f4f9;color:#334155;text-align:center"><div><h2>You are offline</h2><p>Connect to the internet and reopen Read OTP.</p></div>';
self.addEventListener('install', function(e){ self.skipWaiting(); });
self.addEventListener('activate', function(e){ e.waitUntil(self.clients.claim()); });
self.addEventListener('notificationclick', function(e){
  e.notification.close();
  e.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function(l){
    if (l.length) return l[0].focus();
    return self.clients.openWindow('./');
  }));
});
self.addEventListener('fetch', function(e){
  if (e.request.mode === 'navigate') {
    e.respondWith(fetch(e.request).catch(function(){
      return new Response(OFFLINE, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }));
  }
});
"""


@app.route('/sw.js')
def pwa_sw():
    resp = Response(_SW_JS, mimetype='application/javascript')
    resp.headers['Cache-Control'] = 'no-cache'
    resp.headers['Service-Worker-Allowed'] = '/'
    return resp


if __name__ == '__main__':
    # Hosting panels (Pterodactyl / Wispbyte etc.) give each server its own port
    port = int(os.environ.get('SERVER_PORT') or os.environ.get('PORT') or 5000)
    print('Starting on 0.0.0.0:%d' % port, flush=True)
    app.run(host='0.0.0.0', port=port, debug=False)
