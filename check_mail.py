"""Email diagnostic:  python check_mail.py  [recipient@gmail.com]
Tells you exactly what is missing / wrong and sends a real test mail."""
import os, sys, socket
import mailer
from mailer import _env, transports, gmail_api_configured, smtp_only_configured, attempt_send

print('Env files found :', mailer.ENV_FILES_FOUND or 'NONE  (create .env next to app.py)')
print('Sender          :', mailer.sender_address() or '-- not set --')
print('Gmail API       :', 'configured' if gmail_api_configured() else
      'not configured (needs GMAIL_CLIENT_ID, GMAIL_CLIENT_SECRET, GMAIL_REFRESH_TOKEN or the Connect Gmail button)')
print('SMTP            :', 'configured' if smtp_only_configured() else
      'not configured (needs SMTP_HOST, SMTP_USER, SMTP_PASSWORD)')
print('Transports      :', transports() or 'NONE')

if smtp_only_configured():
    host, port = _env('SMTP_HOST') or 'smtp.gmail.com', int(_env('SMTP_PORT') or 587)
    for p in sorted({port, 465, 587}):
        try:
            socket.create_connection((host, p), timeout=6).close(); print(f'Port {p} on {host}: OPEN')
        except OSError as e:
            print(f'Port {p} on {host}: BLOCKED ({e}) -> host blocks SMTP; use Gmail API instead')

if not transports():
    sys.exit('\nNothing configured. Open .env, fill the values, run again.')

to = sys.argv[1] if len(sys.argv) > 1 else mailer.sender_address()
ok, err, _ = attempt_send(to, 'COMPESA test mail', '<h3>COMPESA e-mail works ✓</h3>', 'COMPESA e-mail works.', attempts=1)
print(f'\nSend to {to}:', 'SUCCESS' if ok else 'FAILED\n' + err)
