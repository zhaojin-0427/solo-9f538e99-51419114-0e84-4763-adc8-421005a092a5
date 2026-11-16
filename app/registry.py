"""Immutable file registry.

Write ordering guarantees that no observable state can reference a missing or
half-written artifact:

1. Payload is streamed to a private temp file outside the visible store and
   hashed while streaming.
2. Under a cross-process SQLite write lock the parent edge is re-validated,
   the artifact is published with ``link(2)`` (never clobbering), and the
   registry row is inserted in the same transaction.
3. Any failure rolls the row back and unlinks the freshly published artifact.
   A process death in the middle can leave an orphan artifact, but it has no
   registry row, so it is neither downloadable nor listed; the next startup
   sweep removes it under the same lock.

Revocation flips one row inside an immediate transaction. Eligibility is
derived from the parent chain at read time rather than cached, and downloads
re-check it, so every descendant of a revoked file is blocked the moment the
revoke commits.
"""

from __future__ import annotations

import csv
import hashlib
import os
import re
import secrets
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timezone

from .db import connect, get_file, init_database

KINDS = ("raw", "cleaned", "summary")
KIND_LABELS = {"raw": "原始测量", "cleaned": "清洗表", "summary": "批次汇总"}
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
MAX_BYTES_DEFAULT = 20 * 1024 * 1024
MAX_ROWS = 5_000_000
_CHUNK = 256 * 1024
csv.field_size_limit(1_000_000)


class RegistryError(Exception):
    """A user-correctable rejection. ``code`` is a stable machine identifier."""

    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


@dataclass(frozen=True)
class UploadResult:
    file_id: str
    kind: str
    parent_id: str | None
    sha256: str
    size_bytes: int


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _storage_path(storage_dir: str, stored_name: str) -> str:
    return os.path.join(storage_dir, "files", stored_name)


def _validate_csv(path: str) -> None:
    """Reject empty or non-text payloads; counts rows without buffering."""
    rows = 0
    columns = 0
    try:
        with open(path, "r", encoding="utf-8-sig", newline="") as fh:
            reader = csv.reader(fh)
            for row in reader:
                if not any(cell.strip() for cell in row):
                    continue
                if rows == 0:
                    columns = len(row)
                rows += 1
                if rows > MAX_ROWS:
                    raise RegistryError("too_many_rows", "CSV 行数超过上限", 413)
    except (UnicodeDecodeError, csv.Error) as exc:
        raise RegistryError(
            "not_csv", "文件不是可解析的 UTF-8 CSV 文本（请勿上传二进制或编码错误的文件）", 415
        ) from exc
    if rows == 0:
        raise RegistryError("empty_csv", "CSV 为空，未发现任何数据行", 422)
    if columns == 0:
        raise RegistryError("empty_csv", "CSV 表头为空", 422)


def _resolve_parent(
    conn: sqlite3.Connection, kind: str, parent_id: str | None
) -> sqlite3.Row | None:
    if kind == "raw":
        if parent_id:
            raise RegistryError("unexpected_parent", "原始测量不得登记父文件", 422)
        return None

    if not parent_id:
        raise RegistryError(
            "parent_required", f"{KIND_LABELS[kind]}必须登记其派生的父文件 ID", 422
        )
    if not ID_RE.match(parent_id):
        raise RegistryError("invalid_parent_id", "父文件 ID 格式不合法", 422)

    allowed = ("raw",) if kind == "cleaned" else ("cleaned", "summary")
    parent = get_file(conn, parent_id)
    if parent is None:
        raise RegistryError(
            "parent_not_found",
            f"父文件 {parent_id} 未登记，不能引用不存在或尚未提交的父项",
            409,
        )
    if parent["kind"] not in allowed:
        expected = " 或 ".join(KIND_LABELS[k] for k in allowed)
        raise RegistryError(
            "parent_kind_mismatch",
            f"{KIND_LABELS[kind]}的父项必须是{expected}，{parent_id} 是{KIND_LABELS[parent['kind']]}",
            422,
        )
    if parent["revoked_at"] is not None:
        raise RegistryError(
            "parent_revoked", f"父文件 {parent_id} 已撤销，不能登记新的派生件", 409
        )
    # "Available" means live *and* not silently disabled by an ancestor. A new
    # child must not be attached to a node that already fails closed upstream.
    ancestor = _blocking_row(parent_id, {r["id"]: r for r in conn.execute("SELECT * FROM files")})
    if ancestor is not None:
        raise RegistryError(
            "parent_blocked",
            f"父文件 {parent_id} 因上游 {ancestor['id']} 已撤销而停止下载，不能在其下登记新派生件",
            409,
        )
    return parent


def _publish_artifact(tmp_path: str, final_path: str) -> None:
    """Move a validated payload into the visible store without clobbering.

    Split out so tests can inject a disk failure between write and register.
    """
    os.makedirs(os.path.dirname(final_path), exist_ok=True)
    try:
        os.link(tmp_path, final_path)
    except FileExistsError:
        raise
    os.unlink(tmp_path)


def _insert_file_row(
    conn: sqlite3.Connection,
    *,
    file_id: str,
    kind: str,
    filename: str,
    sha256: str,
    size: int,
    parent_id: str | None,
) -> None:
    """Persist the registry row. Split out so tests can inject a DB failure."""
    now = utc_now()
    conn.execute(
        """INSERT INTO files
           (id, kind, original_filename, stored_name, sha256, size_bytes,
            parent_id, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (file_id, kind, filename, file_id, sha256, size, parent_id, now),
    )
    conn.execute(
        "INSERT INTO events (file_id, action, at, detail) VALUES (?, 'register', ?, ?)",
        (file_id, now, parent_id),
    )


def register_upload(
    *,
    file_id: str,
    kind: str,
    parent_id: str | None,
    filename: str,
    stream,
    database_path: str,
    storage_dir: str,
    max_bytes: int = MAX_BYTES_DEFAULT,
) -> UploadResult:
    """Stream, validate, persist and register one artifact atomically."""
    file_id = (file_id or "").strip()
    kind = (kind or "").strip()
    parent_id = (parent_id or "").strip() or None
    filename = (filename or "").strip()

    if not ID_RE.match(file_id):
        raise RegistryError(
            "invalid_id", "文件 ID 只能含字母、数字、点、下划线和连字符，且以字母或数字开头", 422
        )
    if kind not in KINDS:
        raise RegistryError("invalid_kind", "未知的文件类型", 422)
    if not filename:
        raise RegistryError("missing_filename", "上传文件缺少文件名", 422)
    if len(filename) > 255:
        raise RegistryError("filename_too_long", "文件名过长", 422)
    display_name = "".join(ch for ch in filename if ch.isprintable()).strip()
    if not display_name:
        raise RegistryError("missing_filename", "文件名不含可打印字符", 422)

    init_database(database_path, storage_dir)

    tmp_dir = os.path.join(storage_dir, ".tmp")
    tmp_path = os.path.join(tmp_dir, f"{secrets.token_hex(16)}.part")
    final_path = _storage_path(storage_dir, file_id)
    digest = hashlib.sha256()
    size = 0
    published = False
    committed = False

    try:
        with open(tmp_path, "wb") as out:
            while True:
                chunk = stream.read(_CHUNK)
                if not chunk:
                    break
                size += len(chunk)
                if size > max_bytes:
                    raise RegistryError(
                        "too_large", f"文件超过 {max_bytes // (1024 * 1024)} MiB 上限", 413
                    )
                if b"\x00" in chunk:
                    raise RegistryError("not_csv", "文件含二进制内容，不是文本 CSV", 415)
                digest.update(chunk)
                out.write(chunk)
            out.flush()
            os.fsync(out.fileno())
        if size == 0:
            raise RegistryError("empty_file", "上传内容为空", 422)

        _validate_csv(tmp_path)

        conn = connect(database_path)
        try:
            conn.execute("BEGIN IMMEDIATE")  # serializes all registry writers
            try:
                if get_file(conn, file_id) is not None:
                    raise RegistryError(
                        "duplicate_id",
                        f"文件 ID {file_id} 已被登记；登记不可覆盖，修复件请使用新 ID",
                        409,
                    )
                # Re-validate after taking the lock: a concurrent revoke either
                # committed before this point (we reject) or waits behind us.
                _resolve_parent(conn, kind, parent_id)

                # An artifact with this name but no registry row can only be an
                # orphan from a crash between publish and commit (no other
                # writer can be in flight, we hold the write lock). Reclaim it.
                if os.path.isfile(final_path):
                    try:
                        os.unlink(final_path)
                    except OSError as exc:
                        raise RegistryError(
                            "publish_failed", "无法清理上次失败遗留的载荷，请重试", 500
                        ) from exc

                try:
                    _publish_artifact(tmp_path, final_path)
                except FileExistsError as exc:
                    raise RegistryError(
                        "duplicate_id", f"文件 ID {file_id} 的载荷已存在", 409
                    ) from exc
                published = True

                try:
                    _insert_file_row(
                        conn,
                        file_id=file_id,
                        kind=kind,
                        filename=display_name,
                        sha256=digest.hexdigest(),
                        size=size,
                        parent_id=parent_id,
                    )
                except sqlite3.IntegrityError as exc:
                    raise RegistryError(
                        "duplicate_id", f"文件 ID {file_id} 登记冲突", 409
                    ) from exc
                conn.execute("COMMIT")
                committed = True
            except BaseException:
                # COMMIT may have succeeded and still raised (e.g. a fsync
                # error reported after the write lock was released). Verify the
                # registry row before deleting bytes: deleting a committed
                # artifact would turn a successful registration into a broken
                # download. rollback() is a no-op if no transaction is open.
                if not committed:
                    try:
                        conn.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                    row_exists = get_file(conn, file_id) is not None
                    if published and not row_exists:
                        try:
                            os.unlink(final_path)
                        except OSError:
                            pass
                raise
        finally:
            conn.close()

        return UploadResult(file_id, kind, parent_id, digest.hexdigest(), size)
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def revoke_file(
    *,
    file_id: str,
    revoked_by: str,
    database_path: str,
    storage_dir: str,
) -> sqlite3.Row:
    """Atomically mark a live file revoked. A second revoke is refused."""
    init_database(database_path, storage_dir)
    file_id = (file_id or "").strip()
    revoked_by = (revoked_by or "").strip()
    if not ID_RE.match(file_id):
        raise RegistryError("invalid_id", "文件 ID 格式不合法", 422)
    if not revoked_by:
        raise RegistryError("missing_operator", "请填写撤销操作人（质控员）", 422)
    if len(revoked_by) > 120:
        raise RegistryError("operator_too_long", "操作人名称过长", 422)

    conn = connect(database_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = get_file(conn, file_id)
            if row is None:
                raise RegistryError("not_found", f"文件 {file_id} 未登记", 404)
            if row["revoked_at"] is not None:
                raise RegistryError(
                    "already_revoked", f"文件 {file_id} 已于 {row['revoked_at']} 被撤销", 409
                )
            cur = conn.execute(
                "UPDATE files SET revoked_at = ?, revoked_by = ? "
                "WHERE id = ? AND revoked_at IS NULL",
                (utc_now(), revoked_by, file_id),
            )
            if cur.rowcount != 1:
                raise RegistryError("already_revoked", "撤销未生效，文件状态已变化", 409)
            conn.execute(
                "INSERT INTO events (file_id, action, at, detail) VALUES (?, 'revoke', ?, ?)",
                (file_id, utc_now(), revoked_by),
            )
            conn.execute("COMMIT")
        except BaseException:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        return get_file(conn, file_id)
    finally:
        conn.close()


def _children_map(conn: sqlite3.Connection) -> dict[str | None, list[sqlite3.Row]]:
    children: dict[str | None, list[sqlite3.Row]] = {}
    for row in conn.execute("SELECT * FROM files ORDER BY created_at, id"):
        children.setdefault(row["parent_id"], []).append(row)
    return children


def _descendants(
    file_id: str, children: dict[str | None, list[sqlite3.Row]]
) -> list[sqlite3.Row]:
    """Breadth-first descendants excluding the node itself, cycle-safe."""
    out: list[sqlite3.Row] = []
    seen = {file_id}
    queue = [file_id]
    while queue:
        parent = queue.pop(0)
        for child in children.get(parent, []):
            if child["id"] in seen:
                continue
            seen.add(child["id"])
            out.append(child)
            queue.append(child["id"])
    return out


def _blocking_row(
    file_id: str, by_id: dict[str, sqlite3.Row]
) -> sqlite3.Row | dict | None:
    """Walk upward; return the first revoked ancestor, else None.

    Fails closed: an unresolvable parent yields a synthetic blocker so a
    dangling edge can never produce a downloadable file.
    """
    seen = {file_id}
    current = by_id.get(file_id)
    while current is not None and current["parent_id"] is not None:
        parent_id = current["parent_id"]
        if parent_id in seen:
            return {"id": parent_id, "revoked_at": "cycle", "original_filename": "(循环)"}
        seen.add(parent_id)
        parent = by_id.get(parent_id)
        if parent is None:
            return {
                "id": parent_id,
                "revoked_at": "unknown",
                "original_filename": "(缺失)",
            }
        if parent["revoked_at"] is not None:
            return parent
        current = parent
    return None


def blocking_ancestor(conn: sqlite3.Connection, file_id: str):
    by_id = {r["id"]: r for r in conn.execute("SELECT * FROM files").fetchall()}
    return _blocking_row(file_id, by_id)


def list_files(conn: sqlite3.Connection) -> list[dict]:
    """Return every file enriched with derived eligibility and blocker info."""
    rows = conn.execute("SELECT * FROM files ORDER BY created_at, id").fetchall()
    by_id = {row["id"]: row for row in rows}
    children = _children_map(conn)
    enriched = []
    for row in rows:
        blocker = _blocking_row(row["id"], by_id)
        enriched.append(
            {
                "row": row,
                "eligible": row["revoked_at"] is None and blocker is None,
                "blocker": blocker,
                "children": children.get(row["id"], []),
                "descendant_count": len(_descendants(row["id"], children)),
            }
        )
    return enriched


def impact_report(conn: sqlite3.Connection, file_id: str) -> dict:
    children = _children_map(conn)
    target = get_file(conn, file_id)
    if target is None:
        raise RegistryError("not_found", f"文件 {file_id} 未登记", 404)
    all_desc = _descendants(file_id, children)
    depth: dict[str, int] = {}
    frontier = [(file_id, 0)]
    while frontier:
        node, level = frontier.pop(0)
        for child in children.get(node, []):
            if child["id"] not in depth:
                depth[child["id"]] = level + 1
                frontier.append((child["id"], level + 1))
    return {
        "target": target,
        "direct": [r for r in all_desc if r["parent_id"] == file_id],
        "indirect": [r for r in all_desc if r["parent_id"] != file_id],
        "all": all_desc,
        "depth": depth,
    }


def lineage(conn: sqlite3.Connection, file_id: str) -> list[sqlite3.Row]:
    """Ancestors of ``file_id``, root first, followed by the file itself."""
    chain: list[sqlite3.Row] = []
    seen: set[str] = set()
    current = get_file(conn, file_id)
    while current is not None and current["id"] not in seen:
        seen.add(current["id"])
        chain.append(current)
        current = get_file(conn, current["parent_id"]) if current["parent_id"] else None
    chain.reverse()
    return chain


def download_state(
    conn: sqlite3.Connection, file_id: str, storage_dir: str
) -> dict | None:
    """Full download decision: ok / revoked / missing, plus the blocking row.

    The decision is made per request from live registry state, so a restart
    (or a stale page) can never resurrect a revoked artifact.
    """
    row = get_file(conn, file_id)
    if row is None:
        return None
    if row["revoked_at"] is not None:
        return {"status": "revoked", "row": row, "blocker": row, "path": None}
    blocker = blocking_ancestor(conn, file_id)
    if blocker is not None:
        return {"status": "revoked", "row": row, "blocker": blocker, "path": None}
    path = _storage_path(storage_dir, row["stored_name"])
    try:
        stat = os.stat(path)
    except OSError:
        return {"status": "missing", "row": row, "blocker": None, "path": None}
    if not os.path.isfile(path) or stat.st_size != row["size_bytes"]:
        # A truncated/replaced payload must not be served as if it were the
        # registered artifact. Fail closed; an operator can re-register or
        # restore from backup.
        return {"status": "missing", "row": row, "blocker": None, "path": None}
    return {"status": "ok", "row": row, "blocker": None, "path": path}


def sweep_incomplete_writes(
    database_path: str, storage_dir: str, tmp_max_age_seconds: float = 3600
) -> list[str]:
    """Remove unregistered artifacts and stale temp files left by a crash.

    Artifact removal happens under the registry write lock, so no in-flight
    upload can be between publish and commit while we look. Temp files are
    written *before* that lock is taken, so only ones older than
    ``tmp_max_age_seconds`` are removed; an upload from another process may
    still be streaming into a fresh one. The registry row is the source of
    truth: an unregistered artifact was never visible to users.
    """
    init_database(database_path, storage_dir)
    files_dir = os.path.join(storage_dir, "files")
    tmp_dir = os.path.join(storage_dir, ".tmp")
    removed: list[str] = []
    now = time.time()

    conn = connect(database_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            registered = {
                r["stored_name"] for r in conn.execute("SELECT stored_name FROM files")
            }
            for name in os.listdir(files_dir):
                if name in registered:
                    continue
                path = os.path.join(files_dir, name)
                try:
                    os.unlink(path)
                    removed.append(path)
                except OSError:
                    pass
            for name in os.listdir(tmp_dir):
                path = os.path.join(tmp_dir, name)
                try:
                    if now - os.stat(path).st_mtime < tmp_max_age_seconds:
                        continue
                    os.unlink(path)
                    removed.append(path)
                except OSError:
                    pass
        finally:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
    finally:
        conn.close()
    return removed


def events_for(conn: sqlite3.Connection, file_id: str) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM events WHERE file_id = ? ORDER BY id", (file_id,)
    ).fetchall()


def read_csv_preview(path: str, limit: int = 6) -> tuple[list[str], list[str]]:
    """Small browser preview; never needed for correctness."""
    try:
        with open(path, "r", encoding="utf-8-sig", newline="") as fh:
            reader = csv.reader(fh)
            table = []
            for line in reader:
                if not any(cell.strip() for cell in line):
                    continue
                table.append(line[:20])
                if len(table) > limit:
                    break
    except (OSError, UnicodeDecodeError, csv.Error):
        return [], []
    if not table:
        return [], []
    return table[0], table[1:]
