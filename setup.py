"""
setup.py
--------
High School Python Demo: Account Setup

This script demonstrates the "enrollment" side of an authentication system:
  1. Create a SQLite database with a "user" table.
  2. Ask the new user for a username and password.
  3. Generate a random "salt" and combine it with bcrypt to hash the password.
     (bcrypt actually manages its own salt internally, but we also store a
     separate salt column so students can SEE what a salt looks like and
     understand the concept -- see the comments below.)
  4. Generate a QR code the user can scan with an authenticator app
     (like Google Authenticator or Authy) to set up TOTP (Time-based
     One-Time Passwords) for two-factor authentication (2FA).

Run this once to create an account, then run main.py to log in.
"""

import sqlite3
import getpass

import bcrypt
import pyotp
import qrcode

DB_FILE = "auth_demo.db"

# In a REAL application, every user would get their OWN random TOTP secret,
# generated with pyotp.random_base32() and stored securely in the database.
# For this classroom demo we hardcode one shared secret so it's easy to
# follow along. Base32 is just a text-friendly way to encode random bytes.
TOTP_SECRET = "JBSWY3DPEHPK3PXP"


def create_table(conn):
    """Create the 'user' table if it doesn't already exist."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS user (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            salt TEXT NOT NULL
        )
        """
    )
    conn.commit()


def hash_password(plain_password: str):
    """
    Hash a password using bcrypt.

    bcrypt.gensalt() creates a random salt -- extra random data mixed into
    the password before hashing. Salting means two users with the SAME
    password end up with DIFFERENT hashes, which stops attackers from using
    precomputed "rainbow table" lookups to crack passwords in bulk.

    bcrypt.hashpw() then takes the password + salt and produces a hash that
    is safe to store in the database. We never store the plain password!
    """
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(plain_password.encode("utf-8"), salt)
    # Both salt and hashed come back as bytes; decode to text for storage.
    return hashed.decode("utf-8"), salt.decode("utf-8")


def save_user(conn, username: str, hashed_password: str, salt: str):
    conn.execute(
        "INSERT OR REPLACE INTO user (username, password, salt) VALUES (?, ?, ?)",
        (username, hashed_password, salt),
    )
    conn.commit()


def generate_qr_code(username: str):
    """
    Build a TOTP "provisioning URI" and turn it into a QR code image.

    An authenticator app scans this QR code to learn the secret key, then
    generates a new 6-digit code every 30 seconds using that same secret
    combined with the current time -- that's what "Time-based One-Time
    Password" (TOTP) means.
    """
    totp = pyotp.TOTP(TOTP_SECRET)
    uri = totp.provisioning_uri(name=username, issuer_name="HighSchoolAuthDemo")

    img = qrcode.make(uri)
    filename = "totp_qrcode.png"
    img.save(filename)
    return filename


def main():
    print("=== Account Setup ===")
    username = input("Choose a username: ").strip()

    # getpass hides the password as it's typed, instead of showing it on
    # screen like input() would.
    password = getpass.getpass("Choose a password: ")

    conn = sqlite3.connect(DB_FILE)
    create_table(conn)

    hashed_password, salt = hash_password(password)
    save_user(conn, username, hashed_password, salt)
    conn.close()

    print(f"\nUser '{username}' created in {DB_FILE}.")
    print(f"Stored bcrypt hash: {hashed_password}")
    print(f"Stored salt:        {salt}")

    qr_file = generate_qr_code(username)
    print(f"\nScan '{qr_file}' with an authenticator app (e.g. Google "
          f"Authenticator) to enable TOTP 2FA.")
    print(f"(For testing without a phone, the secret is: {TOTP_SECRET})")
    print("\nSetup complete! Run main.py to log in.")


if __name__ == "__main__":
    main()
