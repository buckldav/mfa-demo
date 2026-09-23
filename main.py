"""
main.py
-------
High School Python Demo: Login / Authentication

This script demonstrates the "login" side of an authentication system:
  1. Ask for a username and password (hidden input via getpass), up to
     3 times. If all 3 attempts fail, exit with status code 1.
  2. Once the password is correct, ask for a 6-digit TOTP code from the
     user's authenticator app and verify it with pyotp.

Run setup.py first to create an account before using this script.
"""

import sqlite3
import getpass
import sys

import bcrypt
import pyotp

DB_FILE = "auth_demo.db"
MAX_ATTEMPTS = 3

# Must match the secret used in setup.py so the codes line up.
TOTP_SECRET = "JBSWY3DPEHPK3PXP"


def get_user(conn, username: str):
    """Look up a user's stored password hash + salt by username."""
    cursor = conn.execute(
        "SELECT username, password, salt FROM user WHERE username = ?",
        (username,),
    )
    return cursor.fetchone()  # None if no matching user


def check_password(plain_password: str, stored_hash: str) -> bool:
    """
    Verify a typed password against the bcrypt hash stored in the database.

    bcrypt.checkpw() re-hashes the typed password using the salt that is
    embedded inside stored_hash, then compares the result to stored_hash.
    We never need to decrypt anything -- hashing is one-way!
    """
    return bcrypt.checkpw(plain_password.encode("utf-8"), stored_hash.encode("utf-8"))


def authenticate_password(conn) -> str | None:
    """
    Prompt for username/password up to MAX_ATTEMPTS times.
    Returns the username on success, or None if all attempts fail.
    """
    for attempt in range(1, MAX_ATTEMPTS + 1):
        username = input("Username: ").strip()
        password = getpass.getpass("Password: ")

        row = get_user(conn, username)
        if row is not None:
            _, stored_hash, _salt = row
            if check_password(password, stored_hash):
                print("Password correct!\n")
                return username

        remaining = MAX_ATTEMPTS - attempt
        if remaining > 0:
            print(
                f"Incorrect username or password. "
                f"{remaining} attempt(s) remaining.\n"
            )

    return None


def authenticate_totp() -> bool:
    """Ask for a 6-digit authenticator code and verify it against the secret."""
    totp = pyotp.TOTP(TOTP_SECRET)
    code = input("Enter the 6-digit code from your authenticator app: ").strip()
    return totp.verify(code)


def main():
    conn = sqlite3.connect(DB_FILE)

    username = authenticate_password(conn)
    if username is None:
        print("Too many failed attempts. Exiting.")
        conn.close()
        sys.exit(1)

    if authenticate_totp():
        print(f"\nWelcome, {username}! You are fully authenticated (password + TOTP).")
    else:
        print("\nIncorrect or expired authentication code. Access denied.")
        conn.close()
        sys.exit(1)

    conn.close()


if __name__ == "__main__":
    main()
