"""Transactional task state, immutable operation identities, and reservation ledger."""

import fcntl
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

from .capabilities import instant, require
from .contracts import canonical, parse_json

TERMINAL = frozenset({"completed", "failed", "rejected", "cancelled", "indeterminate"})


def identity(prefix):
    return prefix + "-" + uuid4().hex


def now():
    return instant()


def encode(value):
    return canonical(value).decode()


def timestamp(value):
    from .capabilities import epoch

    return epoch(value)


def zero():
    return dict.fromkeys(
        [
            "model_tokens",
            "model_calls",
            "tool_calls",
            "delegations",
            "wall_time_ms",
            "input_bytes",
            "output_bytes",
            "artifact_bytes",
        ],
        0,
    )


class Store:
    def __init__(self, root: Path):
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(root, 0o700)
        self.lock = (root / "service.lock").open("a+")
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.lock.close()
            raise ValueError("Another service owns this storage") from None
        self.db = sqlite3.connect(root / "tasks.sqlite3", isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA foreign_keys=ON")
        if self.db.execute("PRAGMA user_version").fetchone()[0] not in (0, 11):
            self.close()
            raise ValueError("Unsupported target storage version")
        self.db.executescript("""
CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY,owner TEXT,document TEXT);
CREATE TABLE IF NOT EXISTS tasks(id TEXT PRIMARY KEY,session_id TEXT REFERENCES sessions(id),state TEXT,document TEXT,request TEXT,principal TEXT,authority TEXT,plan TEXT);
CREATE TABLE IF NOT EXISTS operations(owner TEXT,route TEXT,key TEXT,digest TEXT,operation_id TEXT,resource_id TEXT,kind TEXT,status INTEGER,PRIMARY KEY(owner,route,key),UNIQUE(owner,operation_id));
CREATE TABLE IF NOT EXISTS allocations(task_id TEXT,operation_id TEXT,kind TEXT,state TEXT,reserved TEXT,usage TEXT,details TEXT,PRIMARY KEY(task_id,operation_id));
CREATE TABLE IF NOT EXISTS children(delegation_id TEXT PRIMARY KEY,task_id TEXT,document TEXT);
CREATE TABLE IF NOT EXISTS actions(task_id TEXT,operation_id TEXT,digest TEXT,state TEXT,result TEXT,effect TEXT,intent TEXT,PRIMARY KEY(task_id,operation_id));
CREATE TABLE IF NOT EXISTS events(task_id TEXT,sequence INTEGER,document TEXT,PRIMARY KEY(task_id,sequence));
CREATE TABLE IF NOT EXISTS audit(task_id TEXT,kind TEXT,document TEXT,created_at TEXT);
CREATE TABLE IF NOT EXISTS artifacts(id TEXT PRIMARY KEY,task_id TEXT,manifest TEXT,content BLOB,released INTEGER);
CREATE TABLE IF NOT EXISTS runtimes(task_id TEXT PRIMARY KEY,pid INTEGER,created REAL,container_id TEXT);
PRAGMA user_version=11;
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
        if self.db is not None:
            self.db.close()
            self.db = None
        if not self.lock.closed:
            self.lock.close()

    def session(self, session_id, owner=None):
        row = self.db.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
        require(row is not None and (owner is None or row["owner"] == owner), "not_found", 404)
        return row, parse_json(row["document"])

    def task(self, task_id, owner=None):
        row = self.db.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
        require(row is not None, "not_found", 404)
        self.session(row["session_id"], owner)
        return row, parse_json(row["document"])

    def save_task(self, document):
        row, current = self.task(document["task_id"])
        require(current["status"] not in TERMINAL, "task_state_conflict", 409)
        document["revision"] = current["revision"] + 1
        document["updated_at"] = now()
        self.db.execute(
            "UPDATE tasks SET state=?,document=? WHERE id=?",
            (document["status"], encode(document), document["task_id"]),
        )
        if document["status"] in TERMINAL:
            _, session = self.session(document["session_id"])
            session["active_task_id"] = None
            self.db.execute(
                "UPDATE sessions SET document=? WHERE id=?",
                (encode(session), session["session_id"]),
            )

    def active(self, session_id=None):
        rows = self.db.execute("SELECT id,state,session_id FROM tasks").fetchall()
        return [
            x["id"]
            for x in rows
            if x["state"] not in TERMINAL and (session_id is None or x["session_id"] == session_id)
        ]

    def replay(self, owner, route, key, request_hash, operation_id):
        row = self.db.execute(
            "SELECT * FROM operations WHERE owner=? AND ((route=? AND key=?) OR operation_id=?)",
            (owner, route, key, operation_id),
        ).fetchall()
        if row:
            require(
                all(x["digest"] == request_hash and x["route"] == route for x in row),
                "idempotency_conflict",
                409,
            )
            return row[0]
        return None

    def operation(self, owner, route, key, request_hash, operation_id, resource_id, kind, status):
        self.db.execute(
            "INSERT INTO operations VALUES(?,?,?,?,?,?,?,?)",
            (owner, route, key, request_hash, operation_id, resource_id, kind, status),
        )

    def event(self, task_id, kind, document):
        self.db.execute(
            "INSERT INTO audit VALUES(?,?,?,?)", (task_id, kind, encode(document), now())
        )

    def usage(self, task_id, *, reserved=False):
        total = zero()
        for row in self.db.execute("SELECT * FROM allocations WHERE task_id=?", (task_id,)):
            value = parse_json(
                row["reserved"] if reserved and row["state"] != "finished" else row["usage"]
            )
            for key in total:
                total[key] += value[key]
        return total

    def reserve(self, task_id, operation_id, kind, amount, ceiling, details=None):
        require(self.task(task_id)[1]["status"] not in TERMINAL, "task_state_conflict", 409)
        require(
            set(amount) == set(zero()) and all(type(x) is int and x >= 0 for x in amount.values()),
            "invalid_input",
        )
        existing = self.db.execute(
            "SELECT * FROM allocations WHERE task_id=? AND operation_id=?", (task_id, operation_id)
        ).fetchone()
        if existing:
            require(parse_json(existing["reserved"]) == amount, "idempotency_conflict", 409)
            return False
        held = self.usage(task_id, reserved=True)
        require(
            all(held[key] + amount[key] <= ceiling[key] for key in held), "capacity_exhausted", 429
        )
        self.db.execute(
            "INSERT INTO allocations VALUES(?,?,?,?,?,?,?)",
            (
                task_id,
                operation_id,
                kind,
                "reserved",
                encode(amount),
                encode(zero()),
                encode(details or {}),
            ),
        )
        return True

    def settle(self, task_id, operation_id, usage):
        row = self.db.execute(
            "SELECT * FROM allocations WHERE task_id=? AND operation_id=?", (task_id, operation_id)
        ).fetchone()
        require(row is not None, "internal_error", 500)
        require(
            all(0 <= usage[key] <= parse_json(row["reserved"])[key] for key in usage),
            "capacity_exhausted",
            429,
        )
        if row["state"] == "finished":
            require(parse_json(row["usage"]) == usage, "idempotency_conflict", 409)
            return
        self.db.execute(
            "UPDATE allocations SET state='finished',usage=? WHERE task_id=? AND operation_id=?",
            (encode(usage), task_id, operation_id),
        )

    def uncertain(self, task_id):
        child = self.db.execute(
            "SELECT 1 FROM children WHERE task_id=? AND json_extract(document,'$.dispatched')=1 AND json_extract(document,'$.state') NOT IN ('completed','failed','rejected','cancelled')",
            (task_id,),
        ).fetchone()
        action = self.db.execute(
            "SELECT 1 FROM actions WHERE task_id=? AND state='started' AND effect!='none'",
            (task_id,),
        ).fetchone()
        return bool(child or action)

    def save_child(self, child):
        self.db.execute(
            "INSERT INTO children VALUES(?,?,?) ON CONFLICT(delegation_id) DO UPDATE SET document=excluded.document",
            (child["delegation_id"], child["parent_task_id"], encode(child)),
        )

    def children(self, task_id):
        return [
            parse_json(x[0])
            for x in self.db.execute("SELECT document FROM children WHERE task_id=?", (task_id,))
        ]
