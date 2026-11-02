"""Durable storage for COMPESA (host independent).

WHY THIS EXISTS
---------------
COMPESA keeps its data in one SQLite file (data/compesa.db) plus an uploads/ folder. That is perfect on a
normal computer, but hosts such as Render's free plan give the app a *temporary* disk that is thrown away
on every restart / spin-down / redeploy. The next boot starts from the copy stored in Git, so everything
registered since then "disappears".

WHAT IT DOES
------------
Set DATABASE_URL to any free Postgres (Neon, Supabase, Railway, Aiven, your own server...). Then:

  * on boot      -> the newest copy of the database + uploads is downloaded from Postgres BEFORE the app
                    opens SQLite (so the app always starts from the real data, never from a stale file);
  * while running-> every committed change is detected (a few seconds later) and the database is
                    uploaded again; new / changed / deleted files in uploads/ are mirrored too;
  * on shutdown  -> a final upload is forced, so a normal stop or restart loses nothing.

The app itself keeps using SQLite (fast, no code changes in the ~150 queries); Postgres is the safe
"vault" behind it. Without DATABASE_URL nothing changes (plain local SQLite, e.g. on your own PC).

SAFETY RULES
------------
  * If DATABASE_URL is set but Postgres cannot be reached at boot, the app REFUSES to start. Starting from
    a stale local file and uploading it later would overwrite good data with old data.
  * Uploads use a revision number. If two copies of the app ever write to the same Postgres, the older
    copy of the database is kept as 'db.prev' instead of being silently lost.
"""
import gzip
import hashlib
import logging
import os
import re
import sqlite3
import tempfile
import threading
import time
from pathlib import Path

log = logging.getLogger('compesa.persist')

DEBOUNCE_SECONDS = float(os.getenv('COMPESA_SYNC_DEBOUNCE', '3'))   # push this long after the last write
MAX_DELAY_SECONDS = float(os.getenv('COMPESA_SYNC_MAX_DELAY', '30'))  # ...but never wait longer than this
POLL_SECONDS = 1.0
MAX_UPLOAD_BYTES = 25 * 1024 * 1024
SKIP_PREFIXES = ('qr_', '.', '_')   # qr_<id>.png is a cache that is regenerated on demand

_DDL = '''create table if not exists compesa_blobs(
  key text primary key,
  data bytea not null,
  rev bigint not null default 1,
  sha256 text,
  size bigint,
  updated_at timestamptz not null default now())'''


class _State:
    enabled = False          # DATABASE_URL present
    ready = False            # boot restore finished -> syncing allowed
    rev = None               # revision of the remote 'db' row we last saw / wrote
    last_hash = None         # sha256 of the last database snapshot that is safely in Postgres
    last_push = None         # unix time of last successful database push
    last_error = ''
    conflicts = 0
    uploads = {}             # name -> (size, mtime_ns) already mirrored
    db_path = None
    uploads_dir = None


S = _State()
_lock = threading.RLock()
_stop = threading.Event()
_thread = None


def database_url():
    raw = (os.getenv('DATABASE_URL') or os.getenv('COMPESA_DATABASE_URL') or '').strip()
    # Neon's "copy" button gives:  psql 'postgresql://user:pass@host/db?sslmode=require'
    # People paste all of that, with quotes. Keep only the postgresql://... part.
    m = re.search(r'postgres(?:ql)?://[^\s\'"]+', raw)
    return m.group(0) if m else raw.strip('\'" ')


def _connect():
    import psycopg   # imported lazily so a plain local run does not need it
    # prepare_threshold=None: works behind PgBouncer / Supabase "transaction" poolers too.
    return psycopg.connect(database_url(), connect_timeout=15, autocommit=True, prepare_threshold=None)


def _safe_name(name):
    n = Path(name).name
    if not n or n.startswith('.') or n != name:
        return None
    return n


def _sig(db_path):
    """Cheap change detector: size + mtime of the database and its WAL file."""
    out = []
    for suffix in ('', '-wal'):
        try:
            st = os.stat(str(db_path) + suffix)
            out.append((st.st_size, st.st_mtime_ns))
        except FileNotFoundError:
            out.append(None)
    return tuple(out)


# ----------------------------------------------------------------------------- boot restore
def restore_on_boot(db_path, uploads_dir):
    """Call BEFORE the app opens SQLite. Downloads the newest database + uploads from Postgres."""
    S.db_path, S.uploads_dir = Path(db_path), Path(uploads_dir)
    S.enabled = bool(database_url())
    if not S.enabled:
        if os.getenv('RENDER') or os.getenv('DYNO') or os.getenv('RAILWAY_ENVIRONMENT') or os.getenv('FLY_APP_NAME'):
            log.error('DATABASE_URL is NOT set on a cloud host: data will be LOST on every restart. '
                      'Set DATABASE_URL to a free Postgres (see README).')
        else:
            log.info('Durable sync disabled (no DATABASE_URL): using the local SQLite file only.')
        return

    last_exc = None
    con = None
    for attempt in range(6):
        try:
            con = _connect()
            con.execute(_DDL)
            break
        except Exception as ex:   # database waking up (Neon), network blip...
            last_exc = ex
            log.warning('Postgres not reachable yet (%s), retrying...', ex)
            time.sleep(min(2 ** attempt, 12))
    if con is None:
        raise RuntimeError('DATABASE_URL is set but Postgres is unreachable, so the app will not start '
                           '(starting from an old local copy could overwrite your real data). '
                           f'Last error: {last_exc}')
    try:
        row = con.execute("select data, rev, sha256 from compesa_blobs where key='db'").fetchone()
        S.db_path.parent.mkdir(parents=True, exist_ok=True)
        S.uploads_dir.mkdir(parents=True, exist_ok=True)
        if row:
            raw = gzip.decompress(bytes(row[0]))
            if raw[:16] != b'SQLite format 3\x00':
                raise RuntimeError("The database stored in Postgres is not a valid SQLite file.")
            tmp = S.db_path.with_name(S.db_path.name + '.restoring')
            tmp.write_bytes(raw)
            for suffix in ('-wal', '-shm'):
                Path(str(S.db_path) + suffix).unlink(missing_ok=True)
            os.replace(tmp, S.db_path)
            S.rev, S.last_hash = int(row[1]), row[2] or hashlib.sha256(raw).hexdigest()
            log.info('Restored database from Postgres (rev %s, %.1f KB).', S.rev, len(raw) / 1024)
        else:
            S.rev, S.last_hash = None, None
            log.info('Postgres has no database yet: the local one will be uploaded as the first copy.')

        S.uploads = {}
        for key, data in con.execute("select key, data from compesa_blobs where key like 'upload/%'").fetchall():
            name = _safe_name(key[len('upload/'):])
            if not name:
                continue
            p = S.uploads_dir / name
            p.write_bytes(bytes(data))
            st = p.stat()
            S.uploads[name] = (st.st_size, st.st_mtime_ns)
        if S.uploads:
            log.info('Restored %d uploaded file(s) from Postgres.', len(S.uploads))
        S.ready = True
        S.last_error = ''
    finally:
        con.close()


# ----------------------------------------------------------------------------- pushing
def _snapshot_bytes():
    fd, tmp = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    try:
        src = sqlite3.connect(S.db_path, timeout=30)
        dst = sqlite3.connect(tmp)
        with dst:
            src.backup(dst)
        src.close(); dst.close()
        return Path(tmp).read_bytes()
    finally:
        Path(tmp).unlink(missing_ok=True)


def push_db(force=False):
    """Upload the current database if it changed since the last upload. Returns True if uploaded."""
    with _lock:
        if not (S.enabled and S.ready):
            return False
        raw = _snapshot_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        if digest == S.last_hash and not force:
            return False
        gz = gzip.compress(raw, 6)
        con = _connect()
        try:
            row = None
            if S.rev is None:
                row = con.execute("insert into compesa_blobs(key,data,rev,sha256,size) values('db',%s,1,%s,%s) "
                                  "on conflict (key) do nothing returning rev", (gz, digest, len(raw))).fetchone()
            else:
                row = con.execute("update compesa_blobs set data=%s, rev=rev+1, sha256=%s, size=%s, updated_at=now() "
                                  "where key='db' and rev=%s returning rev", (gz, digest, len(raw), S.rev)).fetchone()
            if row is None:
                # Somebody else (another running copy of the app) wrote in between. Keep their version as
                # 'db.prev' and then write ours, so nothing is destroyed silently.
                S.conflicts += 1
                log.warning('Postgres database changed under us (another copy of the app is writing?). '
                            'Keeping the other version as db.prev and writing ours.')
                con.execute("insert into compesa_blobs(key,data,rev,sha256,size) "
                            "select 'db.prev', data, rev, sha256, size from compesa_blobs where key='db' "
                            "on conflict (key) do update set data=excluded.data, rev=excluded.rev, "
                            "sha256=excluded.sha256, size=excluded.size, updated_at=now()")
                row = con.execute("insert into compesa_blobs(key,data,rev,sha256,size) values('db',%s,1,%s,%s) "
                                  "on conflict (key) do update set data=excluded.data, rev=compesa_blobs.rev+1, "
                                  "sha256=excluded.sha256, size=excluded.size, updated_at=now() returning rev",
                                  (gz, digest, len(raw))).fetchone()
            S.rev, S.last_hash, S.last_push, S.last_error = int(row[0]), digest, time.time(), ''
            log.info('Database mirrored to Postgres (rev %s, %.1f KB).', S.rev, len(raw) / 1024)
            return True
        finally:
            con.close()


def push_uploads():
    """Mirror new / changed / deleted files of uploads/ to Postgres."""
    with _lock:
        if not (S.enabled and S.ready) or S.uploads_dir is None:
            return 0
        current = {}
        for p in S.uploads_dir.iterdir():
            if p.is_file() and not p.name.startswith(SKIP_PREFIXES):
                st = p.stat()
                current[p.name] = (st.st_size, st.st_mtime_ns)
        changed = [n for n, v in current.items() if S.uploads.get(n) != v]
        gone = [n for n in S.uploads if n not in current]
        if not changed and not gone:
            return 0
        con = _connect()
        n = 0
        try:
            for name in changed:
                p = S.uploads_dir / name
                try:
                    data = p.read_bytes()
                except FileNotFoundError:
                    continue
                if len(data) > MAX_UPLOAD_BYTES:
                    log.warning('Upload %s is larger than %d MB and is not mirrored.', name, MAX_UPLOAD_BYTES // 1048576)
                    S.uploads[name] = current[name]
                    continue
                con.execute("insert into compesa_blobs(key,data,sha256,size) values(%s,%s,%s,%s) "
                            "on conflict (key) do update set data=excluded.data, sha256=excluded.sha256, "
                            "size=excluded.size, rev=compesa_blobs.rev+1, updated_at=now()",
                            ('upload/' + name, data, hashlib.sha256(data).hexdigest(), len(data)))
                S.uploads[name] = current[name]
                n += 1
            for name in gone:
                con.execute("delete from compesa_blobs where key=%s", ('upload/' + name,))
                S.uploads.pop(name, None)
                n += 1
        finally:
            con.close()
        return n


def flush():
    """Force everything to Postgres now (used on shutdown). Never raises."""
    try:
        push_db()
        push_uploads()
    except Exception as ex:
        S.last_error = f'{type(ex).__name__}: {ex}'
        log.exception('Final sync failed')


# ----------------------------------------------------------------------------- background loop
def _loop():
    last_sig = None
    first_dirty = None
    last_change = None
    uploads_due = 0.0
    backoff = 0.0
    while not _stop.wait(POLL_SECONDS if backoff == 0 else backoff):
        try:
            now = time.time()
            sig = _sig(S.db_path)
            if sig != last_sig:
                last_sig = sig
                last_change = now
                first_dirty = first_dirty or now
            if first_dirty and (now - last_change >= DEBOUNCE_SECONDS or now - first_dirty >= MAX_DELAY_SECONDS):
                push_db()
                first_dirty = None
            if now >= uploads_due:
                push_uploads()
                uploads_due = now + 8
            backoff = 0.0
        except Exception as ex:
            S.last_error = f'{type(ex).__name__}: {ex}'
            log.warning('Sync to Postgres failed (%s). Will retry.', ex)
            first_dirty = first_dirty or time.time()
            last_change = time.time() - DEBOUNCE_SECONDS   # retry as soon as the backoff is over
            backoff = min((backoff or 2) * 2, 30)


def start():
    """Start the background sync. Call after the database has been opened/initialised."""
    global _thread
    if not (S.enabled and S.ready) or _thread is not None:
        return
    _stop.clear()
    _thread = threading.Thread(target=_loop, name='compesa-sync', daemon=True)
    _thread.start()
    log.info('Durable sync running (database + uploads -> Postgres).')


def stop_and_flush():
    _stop.set()
    if _thread is not None:
        _thread.join(timeout=5)
    flush()


def status():
    return {
        'enabled': S.enabled,
        'ready': S.ready,
        'revision': S.rev,
        'last_push_seconds_ago': None if not S.last_push else int(time.time() - S.last_push),
        'files_mirrored': len(S.uploads),
        'conflicts': S.conflicts,
        'last_error': S.last_error,
    }
