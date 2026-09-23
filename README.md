# Authentication Demo 

Two small scripts that show how real login systems work under the hood.

## Install dependencies

### If using `pip`

```
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### If using [`uv`](https://docs.astral.sh/uv/getting-started/installation/)

Just use `uv run` instead of `python` in the below commands.

## 1. Create an account

```
python setup.py
```

- Enter a username and password.
- The password is hashed with **bcrypt** (never stored in plain text) and
  saved, along with a salt, in `auth_demo.db` (a SQLite database).
- A file called `totp_qrcode.png` is generated. Scan it with an
  authenticator app (Google Authenticator, Authy, etc.) to set up
  two-factor authentication (2FA).

## 2. Log in

```
python main.py
```

- You get **3 tries** to enter the correct username/password
  (typed with `getpass`, so it won't show on screen). Fail all 3 and the
  program exits with status code 1.
- Once your password is correct, you're asked for the current 6-digit
  code from your authenticator app (TOTP = Time-based One-Time Password).

## Concepts covered
- Hashing vs. encryption (bcrypt hashes are one-way)
- Salting passwords
- Storing credentials in a SQLite database
- Two-factor authentication (2FA) with TOTP
- QR codes as a way to transmit a secret key
