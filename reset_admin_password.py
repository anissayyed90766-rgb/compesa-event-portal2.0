#!/usr/bin/env python3
"""
Reset a COMPESA account's password directly in the database.

Use this when you are locked out of the admin account and the in-app
"Forgot password?" flow cannot help (for example, SMTP email is not set up,
and the server was not started with COMPESA_DEV_RESET=true). This script
does not need the server to be running, and it does not need email at all.

Windows:     double-click reset_admin_password.bat
Mac / Linux: python3 reset_admin_password.py
Scripted:    python3 reset_admin_password.py --email admin@compesa.local --password "NewPass123"

It edits the same database file the server uses (COMPESA_DB_PATH from your
.env if set, otherwise data/compesa.db next to this script), using the exact
same password hashing as the app, so the new password works immediately the
next time you log in.
"""
import argparse
import getpass
import sys

from app import DB, db, hash_pw  # reuse the server's own DB path + hashing logic


def main():
    parser = argparse.ArgumentParser(description="Reset a COMPESA account's password.")
    parser.add_argument('--email', help='Account email to reset (you will be asked if omitted)')
    parser.add_argument('--password', help='New password (you will be asked to type it if omitted)')
    args = parser.parse_args()

    print(f'Using database: {DB}')
    con = db()
    try:
        email = (args.email or input('Account email to reset [admin@compesa.local]: ').strip() or 'admin@compesa.local')
        user = con.execute(
            'select id, email, name, role from users where lower(email)=lower(?) or lower(notification_email)=lower(?)',
            (email, email),
        ).fetchone()
        if not user:
            print(f'\nNo account found with email "{email}".')
            accounts = con.execute('select email, role from users order by role').fetchall()
            if accounts:
                print('Accounts that do exist in this database:')
                for a in accounts:
                    print(f'  - {a["email"]}  ({a["role"]})')
            sys.exit(1)

        print(f'Found account: {user["name"]} <{user["email"]}>  role={user["role"]}')

        new_password = args.password
        if new_password:
            if len(new_password) < 8:
                print('Password must be at least 8 characters.')
                sys.exit(1)
        else:
            while True:
                new_password = getpass.getpass('New password (min 8 characters): ')
                if len(new_password) < 8:
                    print('Too short, try again.')
                    continue
                confirm = getpass.getpass('Confirm new password: ')
                if confirm != new_password:
                    print('Passwords did not match, try again.')
                    continue
                break

        con.execute('update users set password=? where id=?', (hash_pw(new_password), user['id']))
        con.commit()
        print(f'\nDone. The password for {user["email"]} has been reset.')
        print('You can log in with the new password right away.')
    finally:
        con.close()


if __name__ == '__main__':
    main()
    if sys.platform == 'win32':
        input('\nPress Enter to close...')
