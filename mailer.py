"""COMPESA e-mail module.

TRANSPORTS (host independent)
-----------------------------
1. Gmail API over HTTPS (port 443)  - works on EVERY host, including ones that block SMTP ports
                                      (Render's free plan blocks 25/465/587 since Sept 2025).
                                      Needs GMAIL_CLIENT_ID / GMAIL_CLIENT_SECRET / GMAIL_REFRESH_TOKEN.
2. SMTP (Gmail app password)        - fine on your own PC / VPS / paid hosts.
                                      Needs SMTP_HOST / SMTP_PORT / SMTP_USER / SMTP_PASSWORD.

EMAIL_TRANSPORT=auto (default) uses the Gmail API when it is configured and falls back to SMTP.
EMAIL_TRANSPORT=smtp | gmail_api forces one of them.

Both send the very same MIME message, so the inline logo / QR images and the attached QR work identically.
The SMTP path forces IPv4 (many hosts have no IPv6 route and Gmail randomly answers with IPv6 addresses,
which is the classic "works sometimes, fails sometimes" bug) and retries on temporary errors.
"""
import base64
import html
import io
import json
import logging
import os
import smtplib
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone, timedelta
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid, parseaddr
from pathlib import Path

from dotenv import dotenv_values
import qrcode

BASE = Path(__file__).resolve().parent
ASSETS = BASE / 'static' / 'assets'
MAIL_ASSETS = ASSETS / 'mail'
ENV_FILES_FOUND = []


def load_env_files():
    """Read .env and compesa.env. A value that is EMPTY (or missing) in the environment is filled from the file,
    so a blank 'GMAIL_CLIENT_ID=' in one file can no longer hide the real value in the other."""
    for name in ('.env', 'compesa.env'):
        path = BASE / name
        if not path.exists():
            continue
        if name not in ENV_FILES_FOUND:
            ENV_FILES_FOUND.append(name)
        for k, v in (dotenv_values(path) or {}).items():
            v = (v or '').strip().strip('"\'').strip()
            if k and v and not (os.environ.get(k) or '').strip():
                os.environ[k] = v


load_env_files()

logger = logging.getLogger('compesa.mail')
IST = timezone(timedelta(hours=5, minutes=30))

refresh_token_provider = None   # app.py plugs in a function returning the refresh token saved by 'Connect Gmail'
GMAIL_AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth'
GMAIL_TOKEN_URL = os.getenv('GMAIL_TOKEN_URL', 'https://oauth2.googleapis.com/token')
GMAIL_SEND_URL = os.getenv('GMAIL_API_URL', 'https://gmail.googleapis.com/gmail/v1/users/me/messages/send')


# ----------------------------------------------------------------------------- configuration
def _password():
    # Google shows App Passwords as "abcd efgh ijkl mnop"; the spaces are not part of the password.
    return (os.getenv('SMTP_PASSWORD') or '').replace(' ', '').strip()


def _env(name):
    return (os.getenv(name) or '').strip()


def smtp_only_configured():
    return bool(_env('SMTP_HOST') and _env('SMTP_USER') and _password())


def gmail_refresh_token():
    t = _env('GMAIL_REFRESH_TOKEN')
    if not t and refresh_token_provider:
        try: t = (refresh_token_provider() or '').strip()
        except Exception: t = ''
    return t


def gmail_api_configured():
    return bool(_env('GMAIL_CLIENT_ID') and _env('GMAIL_CLIENT_SECRET') and gmail_refresh_token())


def gmail_oauth_url(redirect_uri, state, login_hint=''):
    q = {'client_id': _env('GMAIL_CLIENT_ID'), 'redirect_uri': redirect_uri, 'response_type': 'code',
         'scope': 'https://www.googleapis.com/auth/gmail.send', 'access_type': 'offline', 'prompt': 'consent',
         'state': state}
    if login_hint: q['login_hint'] = login_hint
    return GMAIL_AUTH_URL + '?' + urllib.parse.urlencode(q)


def gmail_exchange_code(code, redirect_uri):
    """Returns the refresh token ('' if Google did not send one). Raises MailError on failure."""
    data = urllib.parse.urlencode({'code': code, 'client_id': _env('GMAIL_CLIENT_ID'), 'client_secret': _env('GMAIL_CLIENT_SECRET'),
                                   'redirect_uri': redirect_uri, 'grant_type': 'authorization_code'}).encode()
    try:
        j = _http_json(GMAIL_TOKEN_URL, data, {'Content-Type': 'application/x-www-form-urlencoded'})
    except urllib.error.HTTPError as ex:
        raise MailError(f'Google rejected the authorization code: {ex.read().decode("utf8", "replace")[:300]}', False)
    except (urllib.error.URLError, OSError, TimeoutError) as ex:
        raise MailError(f'Could not reach Google: {ex}', True)
    _token_cache['token'] = None
    return j.get('refresh_token', '')


def transports():
    """Ordered list of transports that will be tried for every e-mail."""
    mode = (_env('EMAIL_TRANSPORT') or 'auto').lower()
    out = []
    if mode in ('auto', 'gmail_api', 'gmail') and gmail_api_configured():
        out.append('gmail_api')
    if mode in ('auto', 'smtp') and smtp_only_configured():
        out.append('smtp')
    return out


def mail_configured():
    return bool(transports())


smtp_configured = mail_configured   # name used by older code


def sender_address():
    return (_env('GMAIL_SENDER') or _env('SMTP_USER') or parseaddr(_env('SMTP_FROM'))[1]).strip()


def is_deliverable(address):
    a = (address or '').strip().lower()
    return '@' in a and not a.endswith('.local')   # seeded demo accounts use *.local


def public_url():
    """Public address of the site (used for the buttons inside e-mails). Works on any host."""
    return (_env('COMPESA_PUBLIC_URL') or _env('RENDER_EXTERNAL_URL') or _env('PUBLIC_URL')).rstrip('/')


def _now_ist():
    return datetime.now(IST).strftime('%d %b %Y, %I:%M %p IST')


# ----------------------------------------------------------------------------- transport helpers
class MailError(Exception):
    def __init__(self, message, transient):
        super().__init__(message)
        self.transient = transient


def _connect_v4(host, port, timeout, source_address=None):
    """Connect over IPv4 only (see module docstring)."""
    infos = []
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror:
        pass
    if not infos:
        return socket.create_connection((host, port), timeout, source_address)
    last = None
    for _fam, _typ, _proto, _canon, addr in infos:
        try:
            return socket.create_connection(addr[:2], timeout, source_address)
        except OSError as ex:
            last = ex
    raise last


class _SMTP4(smtplib.SMTP):
    def _get_socket(self, host, port, timeout):
        return _connect_v4(host, port, timeout, self.source_address)


class _SMTPSSL4(smtplib.SMTP_SSL):
    def _get_socket(self, host, port, timeout):
        raw = _connect_v4(host, port, timeout, self.source_address)
        return self.context.wrap_socket(raw, server_hostname=self._host)


def _build_message(to_email, subject, html_body, text_body, images=None, attachments=None):
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = formataddr((os.getenv('COMPESA_MAIL_NAME', 'COMPESA Events'), sender_address()))
    msg['To'] = to_email
    msg['Date'] = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid(domain=(sender_address().split('@')[-1] or 'compesa.local'))
    msg.set_content(text_body)
    msg.add_alternative(html_body, subtype='html')
    if images:
        html_part = msg.get_body(preferencelist=('html',))
        for cid, (data, sub) in images.items():
            html_part.add_related(data, 'image', sub, cid=f'<{cid}>')
    for fname, data, sub in (attachments or []):
        msg.add_attachment(data, maintype='image', subtype=sub, filename=fname)
    return msg


def _describe_os_error(ex):
    text = f'{type(ex).__name__}: {ex}'
    if isinstance(ex, (socket.timeout, TimeoutError)) or 'timed out' in str(ex).lower():
        text += (' — the server could not reach the SMTP port in time. Many hosts (for example Render\'s free plan) '
                 'block SMTP ports 25/465/587. Use the Gmail API (HTTPS) option from the README instead.')
    return text


def _smtp_once(msg, host, port):
    ctx = ssl.create_default_context()
    if port == 465:
        server = _SMTPSSL4(host, port, timeout=20, context=ctx)
    else:
        server = _SMTP4(host, port, timeout=20)
    with server as s:
        if port != 465:
            s.ehlo(); s.starttls(context=ctx); s.ehlo()
        s.login(_env('SMTP_USER'), _password())
        s.send_message(msg)


def _send_smtp(msg):
    host = _env('SMTP_HOST') or 'smtp.gmail.com'
    port = int(_env('SMTP_PORT') or '587')
    ports = [port]
    if _env('SMTP_FALLBACK_PORT').lower() != 'off':
        alt = 465 if port == 587 else 587 if port == 465 else None
        if alt:
            ports.append(alt)
    last = None
    for p in ports:
        try:
            _smtp_once(msg, host, p)
            return
        except smtplib.SMTPAuthenticationError:
            raise MailError('Gmail rejected the login. Use a 16-character Google App Password in SMTP_PASSWORD '
                            '(2-Step Verification must be ON for the Gmail account), not the normal Gmail password.', False)
        except smtplib.SMTPRecipientsRefused as ex:
            raise MailError(f'The recipient address was refused: {ex}', False)
        except smtplib.SMTPResponseException as ex:
            transient = 400 <= ex.smtp_code < 500
            last = MailError(f'SMTP {ex.smtp_code}: {ex.smtp_error!r}', transient)
            if not transient:
                raise last
        except (OSError, smtplib.SMTPException) as ex:   # timeouts, resets, DNS, disconnects
            last = MailError(_describe_os_error(ex), True)
    raise last


_token_cache = {'token': None, 'exp': 0.0}


def _http_json(url, data, headers, timeout=25):
    req = urllib.request.Request(url, data=data, headers=headers, method='POST')
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = r.read().decode('utf8', 'replace')
        return json.loads(body) if body else {}


def _gmail_access_token(force=False):
    if not force and _token_cache['token'] and _token_cache['exp'] - 60 > time.time():
        return _token_cache['token']
    data = urllib.parse.urlencode({
        'client_id': _env('GMAIL_CLIENT_ID'), 'client_secret': _env('GMAIL_CLIENT_SECRET'),
        'refresh_token': gmail_refresh_token(), 'grant_type': 'refresh_token'}).encode()
    try:
        j = _http_json(GMAIL_TOKEN_URL, data, {'Content-Type': 'application/x-www-form-urlencoded'})
    except urllib.error.HTTPError as ex:
        body = ex.read().decode('utf8', 'replace')[:300]
        if ex.code in (400, 401):
            raise MailError('Google refused the Gmail refresh token (it may be revoked or expired — in Google Cloud '
                            f'set the OAuth consent screen to "In production" and create a new token). Details: {body}', False)
        raise MailError(f'Google token endpoint HTTP {ex.code}: {body}', ex.code >= 500 or ex.code == 429)
    except (urllib.error.URLError, OSError, TimeoutError) as ex:
        raise MailError(f'Could not reach Google: {type(ex).__name__}: {ex}', True)
    _token_cache['token'] = j.get('access_token')
    _token_cache['exp'] = time.time() + int(j.get('expires_in', 3000))
    if not _token_cache['token']:
        raise MailError('Google did not return an access token.', False)
    return _token_cache['token']


def _send_gmail_api(msg, _retry=True):
    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
    token = _gmail_access_token()
    try:
        _http_json(GMAIL_SEND_URL, json.dumps({'raw': raw}).encode(),
                   {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'})
    except urllib.error.HTTPError as ex:
        body = ex.read().decode('utf8', 'replace')[:300]
        if ex.code == 401 and _retry:
            _gmail_access_token(force=True)
            return _send_gmail_api(msg, _retry=False)
        if ex.code == 403:
            raise MailError('Gmail API refused the request (403). Enable the Gmail API in Google Cloud and make sure '
                            f'the token has the gmail.send scope. Details: {body}', False)
        raise MailError(f'Gmail API HTTP {ex.code}: {body}', ex.code >= 500 or ex.code == 429)
    except (urllib.error.URLError, OSError, TimeoutError) as ex:
        raise MailError(f'Could not reach the Gmail API: {type(ex).__name__}: {ex}', True)


# ----------------------------------------------------------------------------- public sending API
def attempt_send(to_email, subject, html_body, text_body, images=None, attachments=None, attempts=1):
    """Send one e-mail. Returns (ok, error_text, transient). `transient` tells the caller whether trying
    again later can help (network problem, rate limit) or not (wrong password, bad address)."""
    order = transports()
    if not order:
        return False, ('E-mail is not configured. Set GMAIL_CLIENT_ID/GMAIL_CLIENT_SECRET/GMAIL_REFRESH_TOKEN '
                       '(works on every host) or SMTP_HOST/SMTP_PORT/SMTP_USER/SMTP_PASSWORD in compesa.env / .env.'), False
    try:
        msg = _build_message(to_email, subject, html_body, text_body, images, attachments)
    except Exception as ex:
        return False, f'Could not build the e-mail: {type(ex).__name__}: {ex}', False
    last_err, last_transient = '', False
    for n in range(max(1, attempts)):
        errors = []
        any_transient = False
        for t in order:
            try:
                (_send_gmail_api if t == 'gmail_api' else _send_smtp)(msg)
                return True, '', False
            except MailError as ex:
                errors.append(f'{t}: {ex}'); any_transient = any_transient or ex.transient
            except Exception as ex:   # never let a mail problem crash a request
                errors.append(f'{t}: {type(ex).__name__}: {ex}'); any_transient = True
        last_err, last_transient = ' | '.join(errors), any_transient
        if not any_transient:
            break
        if n + 1 < attempts:
            time.sleep(2 * (n + 1))
    return False, last_err, last_transient


def send_compesa_email(to_email, subject, html_body, text_body, images=None, attachments=None, attempts=2):
    """Compatibility wrapper. Returns (ok, error_text)."""
    ok, err, _ = attempt_send(to_email, subject, html_body, text_body, images, attachments, attempts)
    return ok, err


def send_mail(to_email, mail, attempts=1):
    """Send a dict produced by one of the *_email builders. Returns (ok, error_text)."""
    ok, err, _ = attempt_send(to_email, mail['subject'], mail['html'], mail['text'],
                              mail.get('images'), mail.get('attachments'), attempts)
    return ok, err


def send_mail_detailed(to_email, mail):
    return attempt_send(to_email, mail['subject'], mail['html'], mail['text'],
                        mail.get('images'), mail.get('attachments'), 1)


# ----------------------------------------------------------------------------- QR code
def qr_payload(reg_code, qr_token):
    return f'COMPESA|REG|{reg_code}|TOKEN:{qr_token}'


def qr_png_bytes(reg_code, qr_token):
    """The attendance QR. Same payload the scanner already understands: COMPESA|REG|<code>|TOKEN:<token>.
    qr_token is random (secrets.token_urlsafe) and unique per registration, so every pass is unique."""
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=10, border=2)
    qr.add_data(qr_payload(reg_code, qr_token))
    qr.make(fit=True)
    buf = io.BytesIO()
    qr.make_image(fill_color='black', back_color='white').save(buf, format='PNG')
    return buf.getvalue()


# ----------------------------------------------------------------------------- shared HTML pieces
_E = lambda v: html.escape(str(v if v is not None else ''))
FONT = "Arial,'Segoe UI',Helvetica,sans-serif"
SERIF = "Georgia,'Times New Roman',serif"


def _read(path):
    p = Path(path)
    return p.read_bytes() if p.exists() else None


def _logo_images():
    out = {}
    b = _read(MAIL_ASSETS / 'logos.png')
    if b:
        out['compesalogos'] = (b, 'png')
    return out


def _data_uri(png_bytes):
    return 'data:image/png;base64,' + base64.b64encode(png_bytes).decode()


def _head(title):
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark"><meta name="supported-color-schemes" content="light dark"><title>{_E(title)}</title>
<style>
body{{margin:0;padding:0;-webkit-text-size-adjust:100%}}
img{{border:0;outline:none;text-decoration:none;-ms-interpolation-mode:bicubic}}
a{{text-decoration:none}}
@media only screen and (max-width:620px){{
 .wrap{{width:100%!important;border-radius:0!important}}
 .m-hide{{display:none!important}}
 .m-pad{{padding-left:16px!important;padding-right:16px!important}}
 .m-h1{{font-size:26px!important}}
 .m-stack{{display:block!important;width:100%!important}}
 .m-btn{{display:block!important;margin:8px 0!important;text-align:center!important}}
}}
</style></head>'''


def _brand_header(logo_src):
    """Top bar like the reference: [SIT logo | emblem] COMPESA / COMPUTER ENGINEERING ... Code • Compete • Innovate"""
    return f'''<tr><td style="padding:22px 24px 14px" class="m-pad"><table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>
<td width="160" valign="middle"><img src="{logo_src}" width="156" height="64" alt="SIT · COMPESA" style="display:block;width:156px;height:64px"></td>
<td valign="middle" style="padding-left:8px"><div style="font-family:{FONT};font-size:26px;line-height:28px;font-weight:bold;letter-spacing:1px;color:#ffffff">COMPESA</div>
<div style="font-family:{FONT};font-size:13px;line-height:18px;letter-spacing:.6px;color:#38bdf8;font-weight:bold">COMPUTER ENGINEERING</div></td>
<td valign="middle" align="right" class="m-hide" style="font-family:{SERIF};font-style:italic;font-size:14px;color:#a9c9f5;white-space:nowrap">Code &nbsp;<span style="color:#38bdf8">&bull;</span>&nbsp; Compete &nbsp;<span style="color:#38bdf8">&bull;</span>&nbsp; Innovate</td>
</tr></table></td></tr>
<tr><td style="padding:0 24px" class="m-pad"><div style="height:1px;line-height:1px;font-size:1px;background:#1b3a6b">&nbsp;</div></td></tr>'''


def _shell(title, logo_src, rows_html, footer_note='Automated message from COMPESA &bull; Computer Engineering Events'):
    return _head(title) + f'''<body style="margin:0;padding:0;background:#030a18">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" bgcolor="#030a18" style="background:#030a18"><tr><td align="center" style="padding:18px 8px">
<table role="presentation" class="wrap" width="640" cellpadding="0" cellspacing="0" bgcolor="#071a3a" style="width:640px;max-width:640px;background:#071a3a;background-image:linear-gradient(160deg,#0a2a5e 0%,#071a3a 45%,#04112b 100%);border-radius:20px;overflow:hidden;border:1px solid #12305f">
{_brand_header(logo_src)}
{rows_html}
<tr><td align="center" style="padding:6px 24px 22px;font-family:{FONT};font-size:11px;color:#6b86b0">{footer_note}</td></tr>
</table></td></tr></table></body></html>'''


def _card(title_html, body_html):
    """Light card with a dark-blue title band (Event Details / QR card in the reference)."""
    return f'''<table role="presentation" width="100%" cellpadding="0" cellspacing="0" bgcolor="#eaf1ff" style="background:#eaf1ff;border-radius:16px;overflow:hidden">
<tr><td bgcolor="#0b2a63" style="background:#0b2a63;padding:13px 18px;border-bottom:3px solid #1f7aff;font-family:{FONT};font-size:18px;font-weight:bold;color:#ffffff">{title_html}</td></tr>
<tr><td style="padding:14px 18px 16px">{body_html}</td></tr></table>'''


def _btn(label, href, solid=False):
    if not href:
        return ''
    bg = 'background:#1d6fe8;border:1px solid #3b8bff' if solid else 'background:#0a2149;border:1px solid #3b82f6'
    return (f'<a class="m-btn" href="{_E(href)}" style="display:inline-block;margin:6px 4px;padding:12px 20px;{bg};border-radius:999px;'
            f'font-family:{FONT};font-size:14px;font-weight:bold;color:#ffffff;text-decoration:none">{label}</a>')


def _pretty_date(d):
    try:
        return datetime.strptime(str(d), '%Y-%m-%d').strftime('%d %b %Y')
    except Exception:
        return str(d)


def calendar_url(event, reg_code=''):
    """'Add to Google Calendar' link (no server needed)."""
    try:
        start = datetime.strptime(f"{event['date']} {event['start_time']}", '%Y-%m-%d %H:%M')
        end = datetime.strptime(f"{event['date']} {event['end_time']}", '%Y-%m-%d %H:%M')
        if end <= start:
            end = start + timedelta(hours=1)
    except Exception:
        return ''
    q = {'action': 'TEMPLATE', 'text': f"{event['name']} — COMPESA",
         'dates': f"{start:%Y%m%dT%H%M%S}/{end:%Y%m%dT%H%M%S}", 'ctz': 'Asia/Kolkata',
         'details': f"Registration ID: {reg_code}\nShow your attendance QR code at the entry desk.",
         'location': event.get('venue', '')}
    return 'https://calendar.google.com/calendar/render?' + urllib.parse.urlencode(q)


def _approval_body(user, event, reg_code, qr_src, ok_src, links, show_buttons=True):
    name, ev = _E(user['name']), _E(event['name'])
    cat = event.get('category', '')
    is_comp = 'competition' in (cat + ' ' + event['name']).lower()
    date_label = 'Competition Date' if is_comp else 'Event Date'
    rows = [('🏆', 'Event', ev, True), ('🏷️', 'Category', _E(cat), True), ('📅', 'Date', _E(event['date']), False),
            ('🕒', 'Time', f"{_E(event['start_time'])} – {_E(event['end_time'])}", False),
            ('📍', 'Venue', _E(event['venue']), False), ('#️⃣', 'Registration ID', _E(reg_code), False)]
    detail_rows = ''.join(
        f'<tr><td width="30" style="padding:9px 0;border-bottom:1px solid #d3e0f5;font-size:16px">{ic}</td>'
        f'<td width="130" style="padding:9px 0;border-bottom:1px solid #d3e0f5;font-family:{FONT};font-size:15px;color:#334155">{lb}</td>'
        f'<td width="14" style="padding:9px 0;border-bottom:1px solid #d3e0f5;font-family:{FONT};font-size:15px;color:#64748b">:</td>'
        f'<td style="padding:9px 0;border-bottom:1px solid #d3e0f5;font-family:{FONT};font-size:15px;color:#0b1f44;{"font-weight:bold" if bold else ""}">{val}</td></tr>'
        for ic, lb, val, bold in rows)
    details = _card('📅&nbsp; Event Details',
                    f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0">{detail_rows}</table>'
                    f'<div align="center" style="padding-top:16px"><span style="display:inline-block;background:#bbf7d0;color:#14532d;border-radius:999px;'
                    f'padding:10px 26px;font-family:{FONT};font-size:16px;font-weight:bold">✔&nbsp; Status: APPROVED</span></div>')
    qr_card = _card('🔳&nbsp; Your Unique Attendance QR Code',
                    f'<div align="center"><table role="presentation" cellpadding="0" cellspacing="0" style="margin:2px auto"><tr><td bgcolor="#ffffff" '
                    f'style="background:#ffffff;border:3px solid #38bdf8;border-radius:14px;padding:8px"><img src="{qr_src}" width="220" height="220" alt="Attendance QR" '
                    f'style="display:block;width:220px;height:220px"></td></tr></table></div>'
                    f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin-top:14px"><tr><td bgcolor="#d6e6ff" '
                    f'style="background:#d6e6ff;border:1px solid #b9d2fb;border-radius:12px;padding:12px 14px;font-family:{FONT};font-size:14px;line-height:20px;color:#0b1f44">'
                    f'ℹ️&nbsp; Show this QR at the entry desk to mark your attendance.<br>It is personal to you and this event — please do not share it.</td></tr></table>')
    buttons = ''
    if show_buttons:
        buttons = (_btn('⬇&nbsp; Download QR', links.get('download_qr'), True)
                   + _btn('📅&nbsp; Add to Google Calendar', links.get('calendar') or calendar_url(event, reg_code))
                   + _btn('🖨&nbsp; Print Confirmation', links.get('print')))
    luck = _E(f"Best of Luck for the {event['name']}!")
    return f'''
<tr><td style="padding:12px 24px 4px" class="m-pad"><table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>
<td width="100" valign="middle" class="m-hide"><img src="{ok_src}" width="84" height="84" alt="Approved" style="display:block;width:84px;height:84px"></td>
<td valign="middle"><div class="m-h1" style="font-family:{FONT};font-size:32px;line-height:38px;font-weight:bold;color:#ffffff">Registration <span style="color:#4ade80">Approved!</span></div>
<div style="font-family:{FONT};font-size:17px;color:#e2e8f0;padding-top:10px">Hello <b style="color:#ffffff">{name}</b>,</div>
<div style="font-family:{FONT};font-size:16px;line-height:23px;color:#dbe7fb;padding-top:4px">Great news! Your registration for <b style="color:#38bdf8">{ev}</b> has been approved by the <b style="color:#ffffff">COMPESA</b> event team.</div></td>
</tr></table></td></tr>
<tr><td style="padding:14px 24px 2px" class="m-pad"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" bgcolor="#0a2a5c" style="background:#0a2a5c;border:1px solid #1f4f9c;border-radius:14px"><tr>
<td class="m-stack" style="padding:14px 18px"><div style="font-family:{FONT};font-size:13px;color:#cbd5e1">📅&nbsp; {date_label}</div><div style="font-family:{FONT};font-size:25px;line-height:32px;font-weight:bold;color:#ffffff">{_E(_pretty_date(event['date']))}</div></td>
<td class="m-stack" style="padding:14px 18px"><div style="font-family:{FONT};font-size:13px;color:#cbd5e1">🕒&nbsp; Time</div><div style="font-family:{FONT};font-size:25px;line-height:32px;font-weight:bold;color:#ffffff">{_E(event['start_time'])} – {_E(event['end_time'])}</div></td>
</tr></table></td></tr>
<tr><td style="padding:14px 24px 0" class="m-pad">{details}</td></tr>
<tr><td style="padding:14px 24px 0" class="m-pad">{qr_card}</td></tr>
<tr><td align="center" class="m-pad noprint" style="padding:14px 24px 0">{buttons}</td></tr>
<tr><td align="center" style="padding:20px 24px 4px"><div style="font-family:{SERIF};font-style:italic;font-size:21px;color:#cfe3ff">{luck}</div>
<div style="width:150px;height:3px;line-height:3px;font-size:1px;background:#38bdf8;border-radius:3px;margin-top:8px">&nbsp;</div></td></tr>
<tr><td align="center" style="padding:16px 24px 8px;font-family:{FONT};font-size:13px;line-height:20px;color:#cbd5e1">Regards,<br><b style="color:#ffffff">COMPESA Event Management Team</b></td></tr>'''


def _approval_text(user, event, reg_code):
    return (f"Hello {user['name']},\n\nGreat news! Your registration for {event['name']} has been approved by the COMPESA event team.\n\n"
            f"Event Details\nEvent: {event['name']}\nCategory: {event['category']}\nDate: {event['date']}\n"
            f"Time: {event['start_time']} – {event['end_time']}\nVenue: {event['venue']}\n"
            f"Registration ID: {reg_code}\nStatus: APPROVED\n\n"
            f"Your unique attendance QR code is attached (qr-{reg_code}.png). Show it at the entry desk to mark your attendance. "
            f"It is personal to you and this event — please do not share it.\n\nBest of Luck for the {event['name']}!\n\n"
            f"Regards,\nCOMPESA Event Management Team")


# ----------------------------------------------------------------------------- the e-mails
def approval_email(user, event, reg_code, qr_token, links=None):
    """Approval e-mail carrying the registration's own unique attendance QR (inline + as attachment)."""
    links = links or {}
    qr = qr_png_bytes(reg_code, qr_token)
    images = _logo_images()
    ok = _read(MAIL_ASSETS / 'approved.png')
    if ok:
        images['approvedicon'] = (ok, 'png')
    images['attendanceqr'] = (qr, 'png')
    body = _approval_body(user, event, reg_code, 'cid:attendanceqr', 'cid:approvedicon', links)
    return {'subject': f"✅ Registration Approved — {event['name']}",
            'html': _shell('Registration Approved', 'cid:compesalogos', body),
            'text': _approval_text(user, event, reg_code), 'images': images,
            'attachments': [(f'qr-{reg_code}.png', qr, 'png')]}


def confirmation_page(user, event, reg_code, qr_token, links=None, auto_print=False):
    """Standalone printable page with the same design (opened from the 'Print Confirmation' button)."""
    links = dict(links or {}); links.pop('print', None)
    qr = qr_png_bytes(reg_code, qr_token)
    logos = _read(MAIL_ASSETS / 'logos.png') or b''
    ok = _read(MAIL_ASSETS / 'approved.png') or b''
    body = _approval_body(user, event, reg_code, _data_uri(qr), _data_uri(ok), links)
    page = _shell('COMPESA Registration Confirmation', _data_uri(logos), body, 'COMPESA &bull; Computer Engineering Events')
    extra = ('<style>@media print{.noprint{display:none!important}body{-webkit-print-color-adjust:exact;print-color-adjust:exact}}'
             '@page{margin:8mm}</style>'
             '<div class="noprint" style="position:fixed;top:12px;right:12px"><button onclick="window.print()" style="padding:10px 16px;border:0;border-radius:999px;'
             'background:#1d6fe8;color:#fff;font:bold 14px Arial;cursor:pointer">🖨 Print / Save as PDF</button></div>'
             + ('<script>window.addEventListener("load",function(){setTimeout(function(){window.print()},400)})</script>' if auto_print else ''))
    return page.replace('</body>', extra + '</body>')


def _simple_layout(kicker, heading, inner_html):
    """Same dark brand header, with a white content card (welcome / login / reset e-mails)."""
    rows = f'''<tr><td style="padding:18px 24px 6px" class="m-pad"><div style="font-family:{FONT};font-size:12px;letter-spacing:2px;color:#8ed8ff">{kicker}</div>
<div class="m-h1" style="font-family:{FONT};font-size:28px;line-height:34px;font-weight:bold;color:#ffffff;padding-top:4px">{heading}</div></td></tr>
<tr><td style="padding:12px 24px 10px" class="m-pad"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" bgcolor="#ffffff" style="background:#ffffff;border-radius:16px">
<tr><td style="padding:24px 24px;font-family:{FONT};font-size:15px;line-height:23px;color:#0f172a">{inner_html}</td></tr></table></td></tr>'''
    return _shell(heading, 'cid:compesalogos', rows)


def _portal_button():
    url = public_url()
    if not url:
        return ''
    return (f'<p style="margin:22px 0 4px"><a href="{_E(url)}" style="display:inline-block;padding:12px 22px;background:#1d6fe8;color:#ffffff;'
            f'text-decoration:none;border-radius:999px;font-weight:bold">Open COMPESA portal</a></p>')


def _info_box(rows_html):
    return f'<div style="background:#f1f6ff;border:1px solid #d3e0f5;border-radius:12px;padding:14px 16px;margin:16px 0">{rows_html}</div>'


def welcome_email(user):
    name = user['name']
    text = (f'Hello {name},\n\nYour COMPESA student account has been created successfully.\n'
            f'You can now log in, browse events and register for them. When the admin approves an event registration '
            f'we will e-mail you your unique attendance QR code.\n\nRegards,\nCOMPESA Event Management Team')
    inner = (f'<p style="margin:0 0 10px">Hello <b>{_E(name)}</b>,</p>'
             f'<p style="margin:0 0 6px">Your COMPESA student account has been <b>created successfully</b>. 🎉</p>'
             + _info_box(f'<div><b>Name:</b> {_E(name)}</div><div><b>Login e-mail:</b> {_E(user.get("email", ""))}</div>'
                         f'<div><b>PRN / Roll No.:</b> {_E(user.get("prn", ""))}</div>')
             + '<p style="margin:0">You can now log in, browse events and register for them. Once the admin <b>approves</b> an event '
               'registration, we will e-mail you the event details together with your <b>unique attendance QR code</b>.</p>'
             + _portal_button() + '<p style="margin:22px 0 0">Regards,<br><b>COMPESA Event Management Team</b></p>')
    return {'subject': 'Welcome to COMPESA — account created', 'html': _simple_layout('WELCOME', 'Your account is ready ✓', inner),
            'text': text, 'images': _logo_images(), 'attachments': []}


def login_email(user, ip='', device='', when=None):
    name = user['name']
    when = when or _now_ist()
    text = (f'Hello {name},\n\nYou have logged in to your COMPESA account successfully.\nTime: {when}\n'
            + (f'IP address: {ip}\n' if ip else '')
            + '\nIf this was not you, please change your password immediately.\n\nRegards,\nCOMPESA Event Management Team')
    rows = f'<div><b>Time:</b> {_E(when)}</div>'
    if ip:
        rows += f'<div><b>IP address:</b> {_E(ip)}</div>'
    if device:
        rows += f'<div><b>Device:</b> {_E(device[:120])}</div>'
    inner = (f'<p style="margin:0 0 10px">Hello <b>{_E(name)}</b>,</p><p style="margin:0">You have <b>logged in successfully</b> to your COMPESA account.</p>'
             + _info_box(rows)
             + '<p style="margin:0;color:#b45309"><b>Was this not you?</b> Please change your password immediately using “Forgot password?” on the login page.</p>'
             + '<p style="margin:22px 0 0">Regards,<br><b>COMPESA Event Management Team</b></p>')
    return {'subject': 'COMPESA — Login successful', 'html': _simple_layout('SECURITY NOTICE', 'Login successful ✓', inner),
            'text': text, 'images': _logo_images(), 'attachments': []}


def reset_email(user, reset_url):
    name = user['name']
    text = (f'Hello {name},\n\nA password reset was requested for your COMPESA account.\nReset link: {reset_url}\n\n'
            f'This link expires in 30 minutes. If you did not request it, ignore this email.')
    inner = (f'<p style="margin:0 0 10px">Hello <b>{_E(name)}</b>,</p><p style="margin:0">A password reset was requested for your COMPESA account.</p>'
             f'<p style="margin:20px 0"><a href="{_E(reset_url)}" style="display:inline-block;padding:12px 22px;background:#1d6fe8;color:#ffffff;'
             f'text-decoration:none;border-radius:999px;font-weight:bold">Reset Password</a></p>'
             '<p style="margin:0;color:#64748b">This link expires in 30 minutes. If you did not request it, you can ignore this e-mail.</p>')
    return {'subject': 'COMPESA Password Reset Request', 'html': _simple_layout('ACCOUNT', 'Reset your password', inner),
            'text': text, 'images': _logo_images(), 'attachments': []}


def build_mail(kind, p):
    """Rebuild an e-mail from the parameters stored in the outbox (so retries after a restart still work)."""
    if kind == 'welcome':
        return welcome_email(p['user'])
    if kind == 'login':
        return login_email(p['user'], p.get('ip', ''), p.get('device', ''), p.get('when'))
    if kind == 'approval':
        return approval_email(p['user'], p['event'], p['reg_code'], p['qr_token'], p.get('links'))
    if kind == 'reset':
        return reset_email(p['user'], p['reset_url'])
    raise ValueError(f'Unknown e-mail kind: {kind}')
