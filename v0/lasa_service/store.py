"""Transactional task state, immutable operation identities, and reservation ledger."""

import fcntl
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

from .capabilities import instant, require
from .contracts import canonical, parse_json

STORAGE_SCHEMA_VERSION = 2
TERMINAL = frozenset({"completed", "failed", "rejected", "cancelled", "indeterminate"})
ACTIVE_TASKS = "state NOT IN (" + ",".join(repr(state) for state in sorted(TERMINAL)) + ")"
RETENTION_UNTIL = "json_extract(document,'$.retention_until')"
RESOLUTION_EVENT = "json_extract(document,'$.kind')='resolution'"
PENDING_CHILD = (
    "json_extract(document,'$.dispatched')=1 AND "
    "(json_extract(document,'$.state') NOT IN ('completed','failed','rejected','cancelled') "
    "OR json_extract(document,'$.effect_disposition')='unknown')"
)
BUDGET_KEYS = (
    "model_tokens",
    "model_calls",
    "tool_calls",
    "delegations",
    "wall_time_ms",
    "input_bytes",
    "output_bytes",
    "artifact_bytes",
)


def identity(prefix):
    return prefix + "-" + uuid4().hex


def encode(value):
    return canonical(value).decode()


def zero():
    return dict.fromkeys(BUDGET_KEYS, 0)


def budget_sql(value):
    return "json_object(" + ",".join(f"'{key}',{value(key)}" for key in BUDGET_KEYS) + ")"


def budget_field(source, key):
    return f"json_extract({source},'$.{key}')"


def adjust_budget(column, previous, current):
    def field(key):
        value = f"{budget_field(column, key)}-{budget_field(previous, key)}"
        return value + f"+{budget_field(current, key)}" if current else value

    return budget_sql(field)


def held_budget(row):
    return f"(CASE WHEN {row}.state = 'finished' THEN {row}.usage ELSE {row}.reserved END)"


def event_bytes(row):
    return f"COALESCE(length(CAST(json_extract({row}.document,'$.content.text') AS BLOB)),0)"


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
        if self.db.execute("PRAGMA user_version").fetchone()[0] not in (0, STORAGE_SCHEMA_VERSION):
            self.close()
            raise ValueError("Unsupported target storage version")
        self.db.executescript(f"""
CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY,owner TEXT,document TEXT);
CREATE TABLE IF NOT EXISTS tasks(id TEXT PRIMARY KEY,session_id TEXT REFERENCES sessions(id),state TEXT,document TEXT,request TEXT,principal TEXT,authority TEXT,plan TEXT);
CREATE TABLE IF NOT EXISTS operations(owner TEXT,route TEXT,key TEXT,digest TEXT,operation_id TEXT,resource_id TEXT,kind TEXT,status INTEGER,PRIMARY KEY(owner,route,key),UNIQUE(owner,operation_id));
CREATE TABLE IF NOT EXISTS allocations(task_id TEXT,operation_id TEXT,kind TEXT,state TEXT,reserved TEXT,usage TEXT,details TEXT,PRIMARY KEY(task_id,operation_id));
CREATE TABLE IF NOT EXISTS children(delegation_id TEXT PRIMARY KEY,task_id TEXT,document TEXT);
CREATE TABLE IF NOT EXISTS actions(task_id TEXT,operation_id TEXT,digest TEXT,state TEXT,result TEXT,effect TEXT,intent TEXT,PRIMARY KEY(task_id,operation_id));
CREATE TABLE IF NOT EXISTS events(task_id TEXT,sequence INTEGER,document TEXT,PRIMARY KEY(task_id,sequence));
CREATE TABLE IF NOT EXISTS audit(task_id TEXT,kind TEXT,document TEXT,created_at TEXT);
CREATE TABLE IF NOT EXISTS content_classes(task_id TEXT, class TEXT, PRIMARY KEY(task_id,class));
CREATE TABLE IF NOT EXISTS content_releases(task_id TEXT, component TEXT, destination TEXT, digest TEXT, policy_revision TEXT, PRIMARY KEY(task_id,component));
CREATE TABLE IF NOT EXISTS artifacts(id TEXT PRIMARY KEY,task_id TEXT,manifest TEXT,content BLOB,released INTEGER);
CREATE TABLE IF NOT EXISTS runtimes(task_id TEXT PRIMARY KEY REFERENCES tasks(id),attempt_id TEXT UNIQUE NOT NULL);
CREATE TABLE IF NOT EXISTS retired_paths(id TEXT PRIMARY KEY,retry_at TEXT);
CREATE INDEX IF NOT EXISTS tasks_by_session ON tasks(session_id);
CREATE INDEX IF NOT EXISTS indeterminate_tasks ON tasks(id) WHERE state='indeterminate';
CREATE INDEX IF NOT EXISTS operation_resources ON operations(kind,resource_id);
CREATE INDEX IF NOT EXISTS children_by_task ON children(task_id);
CREATE INDEX IF NOT EXISTS audit_by_task ON audit(task_id);
CREATE INDEX IF NOT EXISTS content_intake_retention ON audit(created_at) WHERE task_id IS NULL;
CREATE INDEX IF NOT EXISTS content_recovery_intake ON audit(json_extract(document,'$.transfer_id'))
  WHERE task_id IS NULL AND kind='content_recovery';
CREATE INDEX IF NOT EXISTS artifacts_by_task ON artifacts(task_id);
PRAGMA user_version={STORAGE_SCHEMA_VERSION};
""")
        self.db.execute(
            f"CREATE INDEX IF NOT EXISTS active_tasks ON tasks(session_id, id) WHERE {ACTIVE_TASKS}"
        )
        self.db.execute(
            f"CREATE INDEX IF NOT EXISTS session_expiry ON sessions({RETENTION_UNTIL}, id)"
        )
        self.db.execute(
            f"CREATE INDEX IF NOT EXISTS resolved_tasks ON events(task_id) WHERE {RESOLUTION_EVENT}"
        )
        self.db.execute(
            "CREATE INDEX IF NOT EXISTS retired_paths_due ON retired_paths(retry_at,id)"
        )
        self.initialize_totals()

    def initialize_totals(self):
        # These are derived indexes over the immutable events and durable allocation ledger.
        with self.transaction():
            tables = {
                row[0]
                for row in self.db.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' "
                    "AND name IN ('ledger_totals','diagnostic_totals')"
                )
            }
            if "ledger_totals" not in tables:
                self.db.execute(
                    "CREATE TABLE ledger_totals(task_id TEXT PRIMARY KEY,held TEXT,spent TEXT)"
                )
                held = budget_sql(lambda key: f"sum({budget_field(held_budget('a'), key)})")
                spent = budget_sql(lambda key: f"sum({budget_field('a.usage', key)})")
                self.db.execute(
                    f"INSERT INTO ledger_totals SELECT task_id,{held},{spent} "
                    "FROM allocations a GROUP BY task_id"
                )
                added_held = budget_sql(
                    lambda key: (
                        f"{budget_field('ledger_totals.held', key)}+"
                        f"{budget_field('excluded.held', key)}"
                    )
                )
                added_spent = budget_sql(
                    lambda key: (
                        f"{budget_field('ledger_totals.spent', key)}+"
                        f"{budget_field('excluded.spent', key)}"
                    )
                )
                self.db.execute(f"""
                    CREATE TRIGGER ledger_insert AFTER INSERT ON allocations BEGIN
                        INSERT INTO ledger_totals VALUES(NEW.task_id,{held_budget("NEW")},NEW.usage)
                        ON CONFLICT(task_id) DO UPDATE SET held={added_held},spent={added_spent};
                    END
                """)
                for trigger, operation, delta in (
                    ("ledger_update", "UPDATE OF state,reserved,usage", "NEW"),
                    ("ledger_delete", "DELETE", None),
                ):
                    fields = []
                    for column, previous, current in (
                        ("held", held_budget("OLD"), held_budget(delta) if delta else None),
                        ("spent", "OLD.usage", "NEW.usage" if delta else None),
                    ):
                        value = adjust_budget(column, previous, current)
                        fields.append(f"{column}={value}")
                    self.db.execute(f"""
                        CREATE TRIGGER {trigger} AFTER {operation} ON allocations BEGIN
                            UPDATE ledger_totals SET {",".join(fields)} WHERE task_id=OLD.task_id;
                        END
                    """)
            if "diagnostic_totals" not in tables:
                self.db.execute(
                    "CREATE TABLE diagnostic_totals(task_id TEXT PRIMARY KEY,content_bytes INTEGER)"
                )
                self.db.execute(
                    f"INSERT INTO diagnostic_totals SELECT task_id,sum({event_bytes('e')}) "
                    "FROM events e GROUP BY task_id"
                )
                self.db.execute(f"""
                    CREATE TRIGGER diagnostic_insert AFTER INSERT ON events BEGIN
                        INSERT INTO diagnostic_totals VALUES(NEW.task_id,{event_bytes("NEW")})
                        ON CONFLICT(task_id) DO UPDATE SET
                            content_bytes=content_bytes+excluded.content_bytes;
                    END
                """)
                self.db.execute(f"""
                    CREATE TRIGGER diagnostic_delete AFTER DELETE ON events BEGIN
                        UPDATE diagnostic_totals SET content_bytes=content_bytes-{event_bytes("OLD")}
                        WHERE task_id=OLD.task_id;
                    END
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

    def start_runtime(self, task_id, attempt_id):
        self.db.execute("INSERT INTO runtimes VALUES(?,?)", (task_id, attempt_id))

    def runtime_attempts(self):
        return self.db.execute("SELECT task_id,attempt_id FROM runtimes").fetchall()

    def finish_runtime(self, attempt_id):
        self.db.execute("DELETE FROM runtimes WHERE attempt_id=?", (attempt_id,))

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
        _, current = self.task(document["task_id"])
        require(current["status"] not in TERMINAL, "task_state_conflict", 409)
        document["revision"] = current["revision"] + 1
        document["updated_at"] = instant()
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
        query = f"SELECT id FROM tasks WHERE {ACTIVE_TASKS}"
        rows = (
            self.db.execute(query)
            if session_id is None
            else self.db.execute(query + " AND session_id=?", (session_id,))
        )
        return [row["id"] for row in rows]

    def unresolved(self, after, limit):
        return [
            row["id"]
            for row in self.db.execute(
                f"SELECT id FROM tasks WHERE state='indeterminate' AND id>? AND NOT EXISTS "
                f"(SELECT 1 FROM events WHERE task_id=tasks.id AND {RESOLUTION_EVENT}) "
                "ORDER BY id LIMIT ?",
                (after, limit),
            )
        ]

    def retire_sessions(self, now, limit):
        with self.transaction():
            sessions = self.db.execute(
                f"SELECT id FROM sessions WHERE {RETENTION_UNTIL}<=? AND NOT EXISTS "
                f"(SELECT 1 FROM tasks WHERE session_id=sessions.id AND ({ACTIVE_TASKS} "
                "OR EXISTS (SELECT 1 FROM runtimes WHERE task_id=tasks.id) "
                "OR (state='indeterminate' AND NOT EXISTS "
                f"(SELECT 1 FROM events WHERE task_id=tasks.id AND {RESOLUTION_EVENT})))) "
                f"ORDER BY {RETENTION_UNTIL}, id LIMIT ?",
                (now, limit),
            ).fetchall()
            for (session_id,) in sessions:
                task_ids = "SELECT id FROM tasks WHERE session_id=?"
                self.db.execute("INSERT INTO retired_paths VALUES(?,?)", (session_id, now))
                for table in (
                    "allocations",
                    "actions",
                    "children",
                    "audit",
                    "content_classes",
                    "content_releases",
                    "events",
                    "artifacts",
                    "ledger_totals",
                    "diagnostic_totals",
                ):
                    self.db.execute(
                        f"DELETE FROM {table} WHERE task_id IN ({task_ids})", (session_id,)
                    )
                self.db.execute(
                    f"DELETE FROM operations WHERE kind='task' AND resource_id IN ({task_ids})",
                    (session_id,),
                )
                self.db.execute(
                    "DELETE FROM operations WHERE kind='session' AND resource_id=?", (session_id,)
                )
                self.db.execute("DELETE FROM tasks WHERE session_id=?", (session_id,))
                self.db.execute("DELETE FROM sessions WHERE id=?", (session_id,))

    def due_paths(self, now, limit):
        return self.db.execute(
            "SELECT id FROM retired_paths WHERE retry_at<=? ORDER BY retry_at,id LIMIT ?",
            (now, limit),
        ).fetchall()

    def finish_path(self, resource_id, *, retry_at=None):
        if retry_at is None:
            self.db.execute("DELETE FROM retired_paths WHERE id=?", (resource_id,))
        else:
            self.db.execute(
                "UPDATE retired_paths SET retry_at=? WHERE id=?",
                (retry_at, resource_id),
            )

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
            "INSERT INTO audit VALUES(?,?,?,?)", (task_id, kind, encode(document), instant())
        )

    def reserve_content_recovery(self, record, *, per_transfer, per_task):
        if not per_transfer or not per_task:
            return False
        task_id = record["task_id"]
        transfer_id = record["transfer_id"]
        with self.transaction():
            scope = (
                "task_id=?"
                if task_id
                else ("task_id IS NULL AND json_extract(document,'$.transfer_id')=?")
            )
            total, matching = self.db.execute(
                "SELECT count(*), count(*) FILTER (WHERE json_extract(document,'$.transfer_id')=? "
                "AND json_extract(document,'$.action')=?) FROM audit "
                f"WHERE kind='content_recovery' AND {scope}",
                (transfer_id, record["action"], task_id or transfer_id),
            ).fetchone()
            if total >= per_task or matching >= per_transfer:
                return False
            self.event(task_id, "content_recovery", record)
        return True

    def adopt_intake_recovery(self, task_id, transfer_id):
        self.db.execute(
            "UPDATE audit SET task_id=?, document=json_set(document,'$.task_id',?) "
            "WHERE kind='content_recovery' AND task_id IS NULL "
            "AND json_extract(document,'$.transfer_id')=?",
            (task_id, task_id, transfer_id),
        )

    def content_classes(self, task_id):
        return {
            row[0]
            for row in self.db.execute(
                "SELECT class FROM content_classes WHERE task_id=?", (task_id,)
            )
        }

    def add_content_classes(self, task_id, classes):
        self.db.executemany(
            "INSERT OR IGNORE INTO content_classes VALUES(?,?)",
            [(task_id, name) for name in sorted(classes)],
        )

    def usage(self, task_id, *, reserved=False):
        column = "held" if reserved else "spent"
        row = self.db.execute(
            f"SELECT {column} FROM ledger_totals WHERE task_id=?", (task_id,)
        ).fetchone()
        return parse_json(row[0]) if row else zero()

    def diagnostic_bytes(self, task_id):
        row = self.db.execute(
            "SELECT content_bytes FROM diagnostic_totals WHERE task_id=?", (task_id,)
        ).fetchone()
        return row[0] if row else 0

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
        reserved = parse_json(row["reserved"])
        require(
            usage.keys() == reserved.keys()
            and all(
                type(value) is int and 0 <= value <= reserved[key] for key, value in usage.items()
            ),
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
            f"SELECT 1 FROM children WHERE task_id=? AND {PENDING_CHILD} LIMIT 1",
            (task_id,),
        ).fetchone()
        action = self.db.execute(
            "SELECT 1 FROM actions WHERE task_id=? AND state='started' AND effect!='none'",
            (task_id,),
        ).fetchone()
        return bool(child or action)

    def effect_disposition(self, task_id):
        if self.uncertain(task_id):
            return "unknown"
        known = self.db.execute(
            "SELECT 1 FROM actions WHERE task_id=? AND state='finished' AND effect!='none' "
            "UNION ALL SELECT 1 FROM children WHERE task_id=? "
            "AND json_extract(document,'$.effect_disposition')='known' LIMIT 1",
            (task_id, task_id),
        ).fetchone()
        return "known" if known else "none"

    def save_child(self, child):
        self.db.execute(
            "INSERT INTO children VALUES(?,?,?) ON CONFLICT(delegation_id) DO UPDATE SET document=excluded.document",
            (child["delegation_id"], child["parent_task_id"], encode(child)),
        )

    def children(self, task_id, *, pending=False):
        query = "SELECT document FROM children WHERE task_id=?"
        if pending:
            query += f" AND {PENDING_CHILD}"
        return [parse_json(x[0]) for x in self.db.execute(query, (task_id,))]
