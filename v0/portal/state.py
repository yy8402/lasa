"""Portal-owned credentials and submission metadata on a private SQLite volume."""

import fcntl
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

import jwt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from lasa_service.contracts import canonical, digest

from .config import PortalError, read_key


def now():
    return int(time.time())


def opaque():
    return secrets.token_urlsafe(32)


def cookie_digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


class State:
    def __init__(self, settings):
        self.settings = settings
        encryption = read_key(settings.encryption_key_file)
        self.journal_key = read_key(settings.journal_key_file)
        self.ticket_key = read_key(settings.ticket_key_file)
        if len({encryption, self.journal_key, self.ticket_key}) != 3:
            raise ValueError("Use three distinct portal keys")
        self.cipher = AESGCM(encryption)
        root = Path(settings.state_dir)
        root.mkdir(exist_ok=True, parents=True, mode=0o700)
        root.chmod(0o700)
        self.lock = (root / "portal.lock").open("a+")
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.lock.close()
            raise ValueError("Another portal owns this volume") from None
        self.db = sqlite3.connect(root / "portal.sqlite3", isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS logins(
                id TEXT PRIMARY KEY, document BLOB NOT NULL, expires INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS sessions(
                id TEXT PRIMARY KEY, owner TEXT NOT NULL, csrf TEXT NOT NULL,
                tokens BLOB NOT NULL, idle INTEGER NOT NULL, expires INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS submissions(
                owner TEXT NOT NULL, id TEXT NOT NULL, document TEXT NOT NULL,
                created INTEGER NOT NULL, expires INTEGER NOT NULL,
                PRIMARY KEY(owner,id));
        """)

    @contextmanager
    def transaction(self):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self.db.execute("ROLLBACK")
            raise
        else:
            self.db.execute("COMMIT")

    def close(self):
        self.db.close()
        self.lock.close()

    def seal(self, key, value):
        nonce = os.urandom(12)
        return nonce + self.cipher.encrypt(nonce, canonical(value), key.encode())

    def open(self, key, value):
        return json.loads(self.cipher.decrypt(value[:12], value[12:], key.encode()))

    def owner(self, subject):
        return digest([self.settings.lasa_service_id, self.settings.issuer, subject])

    def save_login(self, cookie, value):
        key = cookie_digest(cookie)
        with self.transaction():
            self.db.execute("DELETE FROM logins WHERE expires<=?", (now(),))
            self.ensure_capacity("logins", self.settings.max_sessions)
            self.db.execute(
                "INSERT INTO logins VALUES(?,?,?)",
                (key, self.seal(key, value), now() + self.settings.login_seconds),
            )

    def take_login(self, cookie):
        if not cookie:
            return None
        key = cookie_digest(cookie)
        with self.transaction():
            row = self.db.execute("DELETE FROM logins WHERE id=? RETURNING *", (key,)).fetchone()
        return self.open(key, row["document"]) if row and row["expires"] > now() else None

    def ensure_capacity(self, table, maximum):
        if self.db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] >= maximum:
            raise PortalError(429, "capacity", "Try again shortly.", retry_after=10)

    def create_session(self, subject, tokens, old_cookie):
        cookie = opaque()
        key = cookie_digest(cookie)
        with self.transaction():
            self.delete_session(old_cookie)
            self.db.execute("DELETE FROM sessions WHERE idle<=? OR expires<=?", (now(), now()))
            self.ensure_capacity("sessions", self.settings.max_sessions)
            self.db.execute(
                "INSERT INTO sessions VALUES(?,?,?,?,?,?)",
                (
                    key,
                    self.owner(subject),
                    opaque(),
                    self.seal(key, tokens),
                    now() + self.settings.idle_seconds,
                    now() + self.settings.session_seconds,
                ),
            )
        return cookie

    def session(self, cookie):
        if not cookie:
            return None
        key = cookie_digest(cookie)
        row = self.db.execute(
            "SELECT * FROM sessions WHERE id=? AND idle>? AND expires>?", (key, now(), now())
        ).fetchone()
        if row is None:
            return None
        if row["idle"] - now() < self.settings.idle_seconds // 2:
            self.db.execute(
                "UPDATE sessions SET idle=? WHERE id=?", (now() + self.settings.idle_seconds, key)
            )
        return {**row, "tokens": self.open(key, row["tokens"])}

    def update_tokens(self, key, tokens):
        return (
            self.db.execute(
                "UPDATE sessions SET tokens=? WHERE id=? AND idle>? AND expires>?",
                (self.seal(key, tokens), key, now(), now()),
            ).rowcount
            == 1
        )

    def delete_session(self, cookie):
        if cookie:
            self.db.execute("DELETE FROM sessions WHERE id=?", (cookie_digest(cookie),))

    def ticket(self, owner):
        value = {
            "id": secrets.token_hex(16),
            "owner": owner,
            "exp": now() + self.settings.ticket_seconds,
        }
        return {"id": value["id"], "value": jwt.encode(value, self.ticket_key, algorithm="HS256")}

    def read_ticket(self, ticket, owner):
        try:
            value = jwt.decode(
                ticket,
                self.ticket_key,
                algorithms=["HS256"],
                options={"require": ["id", "owner", "exp"]},
            )
            if value["owner"] == owner:
                return value
        except (jwt.PyJWTError, TypeError, ValueError):
            pass
        raise PortalError(409, "ticket_expired", "The submission ticket expired.")

    def fingerprint(self, request_digest):
        return hmac.digest(self.journal_key, request_digest.encode(), "sha256").hex()

    def submission(self, owner, submission_id):
        row = self.db.execute(
            "SELECT document FROM submissions WHERE owner=? AND id=? AND expires>?",
            (owner, submission_id, now()),
        ).fetchone()
        return json.loads(row["document"]) if row else None

    def reserve(self, owner, submission_id, value):
        with self.transaction():
            self.db.execute("DELETE FROM submissions WHERE expires<=?", (now(),))
            existing = self.submission(owner, submission_id)
            if existing:
                return existing
            self.ensure_capacity("submissions", self.settings.max_journal)
            count = self.db.execute(
                "SELECT COUNT(*) FROM submissions WHERE owner=?", (owner,)
            ).fetchone()[0]
            if count >= self.settings.per_user_journal:
                raise PortalError(429, "capacity", "Your submission recovery limit is reached.")
            self.db.execute(
                "INSERT INTO submissions VALUES(?,?,?,?,?)",
                (
                    owner,
                    submission_id,
                    canonical(value).decode(),
                    now(),
                    now() + self.settings.journal_seconds,
                ),
            )
        return value

    def save_submission(self, owner, submission_id, value):
        self.db.execute(
            "UPDATE submissions SET document=? WHERE owner=? AND id=?",
            (canonical(value).decode(), owner, submission_id),
        )

    def unresolved(self, owner, limit=25):
        rows = self.db.execute(
            "SELECT id FROM submissions WHERE owner=? AND expires>? "
            "AND json_extract(document,'$.state') IN ('checking','unconfirmed') "
            "ORDER BY created DESC,id DESC LIMIT ?",
            (owner, now(), limit),
        )
        return [row["id"] for row in rows]
