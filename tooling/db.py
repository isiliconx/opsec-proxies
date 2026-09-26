"""SQLite store. WAL, thread-safe via a lock, one file under data/.

Tables:
  proxies    every endpoint ever seen, keyed by (scheme,host,port,user)
  sources    which feed it came from, and when
  tests      per-proxy test history (grade, latency, exit ip, verdict)
  geo        cached geo/asn lookups
  parcels    user-imported proxy batches
  jobs       run bookkeeping
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Iterable

SCHEMA = """
CREATE TABLE IF NOT EXISTS proxies (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  scheme        TEXT NOT NULL,
  host          TEXT NOT NULL,
  port          INTEGER NOT NULL,
  user          TEXT NOT NULL DEFAULT '',
  password      TEXT NOT NULL DEFAULT '',
  is_private    INTEGER NOT NULL DEFAULT 0,
  first_seen    REAL NOT NULL,
  last_seen     REAL NOT NULL,
  origin        TEXT NOT NULL DEFAULT 'harvest',   -- harvest | import | range | api
  parcel_id     INTEGER,
  UNIQUE(scheme, host, port, user)
);
CREATE INDEX IF NOT EXISTS ix_proxies_last ON proxies(last_seen DESC);
CREATE INDEX IF NOT EXISTS ix_proxies_origin ON proxies(origin);

CREATE TABLE IF NOT EXISTS sources (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  name      TEXT UNIQUE NOT NULL,
  url       TEXT NOT NULL,
  kind      TEXT NOT NULL,
  last_run  REAL,
  last_count INTEGER DEFAULT 0,
  last_status TEXT DEFAULT '',
  enabled   INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS tests (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  proxy_id    INTEGER NOT NULL,
  at          REAL NOT NULL,
  verdict     TEXT NOT NULL,          -- alive | dead | slow | transparent | dnsfail | blocked | unknown
  grade       TEXT NOT NULL DEFAULT 'C',  -- A|B|C|D  (A = residential+fast+reliable)
  latency_ms  REAL DEFAULT 0,
  exit_ip     TEXT DEFAULT '',
  country     TEXT DEFAULT '',
  cc          TEXT DEFAULT '',
  asn         TEXT DEFAULT '',
  isp         TEXT DEFAULT '',
  hosting     INTEGER DEFAULT 0,
  tls_ok      INTEGER DEFAULT 0,
  success_ratio REAL DEFAULT 0,
  samples     INTEGER DEFAULT 0,
  error       TEXT DEFAULT '',
  evidence    TEXT DEFAULT '',        -- json of banner/head/body snippet (trimmed)
  FOREIGN KEY(proxy_id) REFERENCES proxies(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS ix_tests_proxy ON tests(proxy_id, at DESC);
CREATE INDEX IF NOT EXISTS ix_tests_grade ON tests(grade, at DESC);

CREATE TABLE IF NOT EXISTS geo (
  ip        TEXT PRIMARY KEY,
  at        REAL NOT NULL,
  country   TEXT, cc TEXT, city TEXT, region TEXT,
  isp TEXT, org TEXT, asn TEXT, asname TEXT,
  hosting INTEGER DEFAULT 0, proxy INTEGER DEFAULT 0, mobile INTEGER DEFAULT 0,
  source   TEXT
);

CREATE TABLE IF NOT EXISTS parcels (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  label     TEXT NOT NULL,
  file      TEXT,
  count     INTEGER DEFAULT 0,
  added     REAL NOT NULL,
  scheme    TEXT DEFAULT 'auto',
  note      TEXT DEFAULT '',
  status    TEXT DEFAULT 'pending',   -- pending | testing | done | failed
  passed    INTEGER DEFAULT 0,
  failed    INTEGER DEFAULT 0
);

-- A proxy can be in many parcels (same endpoint re-imported), so the link is
-- its own table rather than a single parcel_id column on proxies.
CREATE TABLE IF NOT EXISTS parcel_links (
  parcel_id INTEGER NOT NULL,
  proxy_id  INTEGER NOT NULL,
  PRIMARY KEY (parcel_id, proxy_id),
  FOREIGN KEY(parcel_id) REFERENCES parcels(id) ON DELETE CASCADE,
  FOREIGN KEY(proxy_id) REFERENCES proxies(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS ix_links_proxy ON parcel_links(proxy_id);

CREATE TABLE IF NOT EXISTS jobs (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  stage     TEXT NOT NULL,
  started   REAL NOT NULL,
  finished  REAL,
  ok        INTEGER DEFAULT 0,
  total     INTEGER DEFAULT 0,
  note      TEXT DEFAULT ''
);
"""


class DB:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False, timeout=30)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.commit()
                self._conn.close()
            except Exception:
                pass

    # ---------------------------------------------------------------- proxies
    def upsert_proxies(self, rows: Iterable[tuple], origin: str = "harvest", parcel_id: int | None = None) -> int:
        """rows: (scheme, host, port, user, password, is_private). Returns rows written."""
        rows = list(rows)
        n = 0
        with self._lock:
            cur = self._conn.cursor()
            now = time.time()
            cur.executemany(
                """INSERT INTO proxies(scheme,host,port,user,password,is_private,first_seen,last_seen,origin,parcel_id)
                   VALUES(?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(scheme,host,port,user) DO UPDATE SET last_seen=excluded.last_seen""",
                [(s, h, p, u, pw, 1 if priv else 0, now, now, origin, parcel_id) for (s, h, p, u, pw, priv) in rows])
            n = cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
            self._conn.commit()
            if parcel_id is not None:
                self.link_parcel(parcel_id, rows)
        return n

    def proxy_count(self, origin: str | None = None) -> int:
        with self._lock:
            if origin:
                r = self._conn.execute("SELECT COUNT(*) c FROM proxies WHERE origin=?", (origin,)).fetchone()
            else:
                r = self._conn.execute("SELECT COUNT(*) c FROM proxies").fetchone()
        return r["c"]

    def iter_proxies(self, batch: int = 5000, since: float | None = None, origin: str | None = None):
        """Generator of sqlite Rows in id order, paged so we never hold all in RAM."""
        last = 0
        while True:
            q = "SELECT * FROM proxies WHERE id > ?"
            args: list[Any] = [last]
            if since:
                q += " AND last_seen >= ?"
                args.append(since)
            if origin:
                q += " AND origin = ?"
                args.append(origin)
            q += " ORDER BY id LIMIT ?"
            args.append(batch)
            with self._lock:
                rows = self._conn.execute(q, args).fetchall()
            if not rows:
                return
            for r in rows:
                yield r
            last = rows[-1]["id"]

    def latest_test(self, proxy_id: int) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM tests WHERE proxy_id=? ORDER BY at DESC LIMIT 1", (proxy_id,)).fetchone()

    def add_test(self, proxy_id: int, **kw) -> int:
        cols = ("verdict", "grade", "latency_ms", "exit_ip", "country", "cc", "asn", "isp", "hosting",
                "tls_ok", "success_ratio", "samples", "error", "evidence")
        vals = [kw.get(c) for c in cols]
        with self._lock:
            cur = self._conn.execute(
                f"INSERT INTO tests(proxy_id,at,{','.join(cols)}) VALUES(?,?,{','.join('?' * len(cols))})",
                [proxy_id, time.time(), *vals])
            self._conn.commit()
            return cur.lastrowid

    def best_grade(self, proxy_id: int, min_ratio: float = 0.0) -> str:
        """Best grade in the last 6 hours that still meets the ratio floor."""
        since = time.time() - 6 * 3600
        with self._lock:
            r = self._conn.execute(
                """SELECT grade, MAX(success_ratio) r FROM tests
                   WHERE proxy_id=? AND at>=? AND success_ratio>=?
                   GROUP BY grade ORDER BY CASE grade WHEN 'A' THEN 0 WHEN 'B' THEN 1 WHEN 'C' THEN 2 ELSE 3 END
                   LIMIT 1""", (proxy_id, since, min_ratio)).fetchone()
        return r["grade"] if r else ""

    def live_pool(self, min_grade: str = "B", limit: int = 20000, countries: str = "",
                  exclude_dc: bool = False) -> list[sqlite3.Row]:
        """Most recent successful test per proxy, filtered. The pool the egress uses."""
        order = {"A": 0, "B": 1, "C": 2, "D": 3}
        maxord = order.get(min_grade, 2)
        cc = [c.strip().upper() for c in countries.split(",") if c.strip()]
        with self._lock:
            rows = self._conn.execute(
                """SELECT p.*, t.grade, t.latency_ms, t.exit_ip, t.country, t.cc, t.asn, t.isp, t.hosting,
                          t.success_ratio, t.at AS tested_at
                   FROM proxies p
                   JOIN tests t ON t.id = (
                        SELECT id FROM tests WHERE proxy_id=p.id AND verdict IN ('alive','slow')
                        ORDER BY at DESC LIMIT 1)
                   WHERE t.at >= ?
                   ORDER BY t.latency_ms ASC""", (time.time() - 3600,)).fetchall()
        out = []
        for r in rows:
            if order.get(r["grade"], 3) > maxord:
                continue
            if cc and (r["cc"] or "").upper() not in cc:
                continue
            if exclude_dc and (r["hosting"] or not r["grade"]):
                continue
            out.append(r)
            if len(out) >= limit:
                break
        return out

    def stats(self) -> dict:
        with self._lock:
            c = self._conn
            total = c.execute("SELECT COUNT(*) c FROM proxies").fetchone()["c"]
            by_origin = {r["origin"]: r["c"] for r in c.execute(
                "SELECT origin, COUNT(*) c FROM proxies GROUP BY origin").fetchall()}
            graded = {r["grade"]: r["c"] for r in c.execute(
                "SELECT grade, COUNT(*) c FROM tests WHERE at >= ? GROUP BY grade",
                (time.time() - 3600,)).fetchall()}
            verdicts = {r["verdict"]: r["c"] for r in c.execute(
                "SELECT verdict, COUNT(*) c FROM tests WHERE at >= ? GROUP BY verdict",
                (time.time() - 3600,)).fetchall()}
            countries = c.execute(
                """SELECT cc, COUNT(*) n FROM tests WHERE at>=? AND cc != ''
                   GROUP BY cc ORDER BY n DESC LIMIT 40""", (time.time() - 86400,)).fetchall()
            return {"total": total, "by_origin": by_origin, "grades_1h": graded,
                    "verdicts_1h": verdicts,
                    "countries": {r["cc"]: r["n"] for r in countries}}

    # ---------------------------------------------------------------- geo
    def geo_get(self, ip: str) -> dict | None:
        with self._lock:
            r = self._conn.execute("SELECT * FROM geo WHERE ip=?", (ip,)).fetchone()
        return dict(r) if r else None

    def geo_put(self, info: dict) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT INTO geo(ip,at,country,cc,city,region,isp,org,asn,asname,hosting,proxy,mobile,source)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(ip) DO UPDATE SET at=excluded.at, country=excluded.country, cc=excluded.cc,
                     city=excluded.city, region=excluded.region, isp=excluded.isp, org=excluded.org,
                     asn=excluded.asn, asname=excluded.asname, hosting=excluded.hosting,
                     proxy=excluded.proxy, mobile=excluded.mobile, source=excluded.source""",
                (info.get("ip", ""), time.time(), info.get("country", ""), info.get("cc", ""),
                 info.get("city", ""), info.get("region", ""), info.get("isp", ""), info.get("org", ""),
                 info.get("asn", ""), info.get("asname", ""), 1 if info.get("hosting") else 0,
                 1 if info.get("proxy") else 0, 1 if info.get("mobile") else 0, info.get("source", "")))
            self._conn.commit()

    # ---------------------------------------------------------------- parcels
    def add_parcel(self, label: str, file: str | None, count: int, scheme: str = "auto",
                   note: str = "") -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO parcels(label,file,count,added,scheme,note) VALUES(?,?,?,?,?,?)",
                (label, file, count, time.time(), scheme, note))
            self._conn.commit()
            return cur.lastrowid

    def link_parcel(self, parcel_id: int, rows: Iterable[tuple]) -> int:
        """Attach (scheme,host,port,user,password,is_private) rows to a parcel."""
        with self._lock:
            ids = []
            for s, h, p, u, _pw, priv in rows:
                r = self._conn.execute(
                    "SELECT id FROM proxies WHERE scheme=? AND host=? AND port=? AND user=?",
                    (s, h, p, u or "")).fetchone()
                if r:
                    ids.append((parcel_id, r["id"]))
            self._conn.executemany(
                "INSERT OR IGNORE INTO parcel_links(parcel_id,proxy_id) VALUES(?,?)", ids)
            self._conn.commit()
            return len(ids)

    def list_parcels(self) -> list[dict]:
        with self._lock:
            return [dict(r) for r in self._conn.execute(
                "SELECT * FROM parcels ORDER BY added DESC").fetchall()]

    def set_parcel_status(self, pid: int, status: str, passed: int = 0, failed: int = 0) -> None:
        with self._lock:
            self._conn.execute("UPDATE parcels SET status=?,passed=?,failed=? WHERE id=?",
                               (status, passed, failed, pid))
            self._conn.commit()

    def parcel_proxies(self, pid: int):
        with self._lock:
            return self._conn.execute(
                """SELECT p.* FROM proxies p
                   JOIN parcel_links l ON l.proxy_id = p.id
                   WHERE l.parcel_id = ? ORDER BY p.id""", (pid,)).fetchall()

    # ---------------------------------------------------------------- sources / jobs
    def touch_source(self, name: str, url: str, kind: str, count: int, status: str) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT INTO sources(name,url,kind,last_run,last_count,last_status) VALUES(?,?,?,?,?,?)
                   ON CONFLICT(name) DO UPDATE SET last_run=excluded.last_run,
                     last_count=excluded.last_count, last_status=excluded.last_status""",
                (name, url, kind, time.time(), count, status))
            self._conn.commit()

    def start_job(self, stage: str, total: int = 0) -> int:
        with self._lock:
            cur = self._conn.execute("INSERT INTO jobs(stage,started,total) VALUES(?,?,?)",
                                     (stage, time.time(), total))
            self._conn.commit()
            return cur.lastrowid

    def finish_job(self, jid: int, ok: int, note: str = "") -> None:
        with self._lock:
            self._conn.execute("UPDATE jobs SET finished=?,ok=?,note=? WHERE id=?",
                               (time.time(), ok, note, jid))
            self._conn.commit()
