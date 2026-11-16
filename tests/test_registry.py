import io
import os
import sqlite3
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app  # noqa: E402
from app import registry  # noqa: E402
from app.db import connect  # noqa: E402


RAW = b"sample_id,timepoint_months,assay_pct\nS-001,0,99.8\nS-001,3,99.4\n"
CLEAN = b"sample_id,timepoint_months,assay_pct,flag\nS-001,0,99.8,ok\n"
SUMMARY = b"condition,timepoint_months,mean_assay_pct\n25C/60RH,0,99.8\n"


@pytest.fixture()
def app(tmp_path):
    application = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test",
            "DATABASE_PATH": str(tmp_path / "registry.db"),
            "STORAGE_DIR": str(tmp_path / "storage"),
            "MAX_UPLOAD_BYTES": 1024 * 1024,
        }
    )
    application.config["TMP_ROOT"] = tmp_path
    return application


@pytest.fixture()
def client(app):
    return app.test_client()


def csrf(client):
    """Fetch a token the way a browser would (rendered into the page)."""
    client.get("/")
    with client.session_transaction() as session:
        return session["_csrf_token"]


def upload(client, file_id, kind="raw", parent=None, payload=RAW, filename="data.csv"):
    data = {
        "file_id": file_id,
        "kind": kind,
        "parent_id": parent or "",
        "csrf_token": csrf(client),
        "file": (io.BytesIO(payload), filename),
    }
    return client.post("/upload", data=data, content_type="multipart/form-data")


def revoke(client, file_id, operator="质控-李"):
    return client.post(
        f"/files/{file_id}/revoke",
        data={"operator": operator, "csrf_token": csrf(client)},
    )


def rows(app):
    conn = connect(app.config["DATABASE_PATH"])
    try:
        return {r["id"]: dict(r) for r in conn.execute("SELECT * FROM files")}
    finally:
        conn.close()


def stored_files(app):
    path = os.path.join(app.config["STORAGE_DIR"], "files")
    return sorted(os.listdir(path)) if os.path.isdir(path) else []


def test_upload_download_and_metadata(client, app):
    response = upload(client, "RAW-001")
    assert response.status_code == 302
    body = client.get("/download/RAW-001")
    assert body.status_code == 200
    assert body.data == RAW
    assert body.headers["X-Content-Type-Options"] == "nosniff"
    record = rows(app)["RAW-001"]
    assert record["kind"] == "raw"
    assert record["parent_id"] is None
    assert record["revoked_at"] is None
    assert len(record["sha256"]) == 64


def test_requires_parent_for_derived_and_rejects_unregistered(client, app):
    assert upload(client, "CLEAN-X", "cleaned", "MISSING").status_code == 409
    assert upload(client, "CLEAN-X", "cleaned", None).status_code == 422
    assert upload(client, "SUM-X", "summary", "MISSING").status_code == 409
    assert rows(app) == {}
    assert stored_files(app) == []


def test_parent_kind_rules(client, app):
    upload(client, "RAW-1")
    upload(client, "CLEAN-1", "cleaned", "RAW-1")
    upload(client, "SUM-1", "summary", "CLEAN-1")
    # A revision summary may chain onto a summary, but nothing may chain from a summary.
    upload(client, "SUM-2", "summary", "SUM-1")
    assert upload(client, "CLEAN-2", "cleaned", "CLEAN-1").status_code == 422
    assert upload(client, "SUM-3", "summary", "RAW-1").status_code == 422
    assert upload(client, "RAW-2", "raw", "RAW-1").status_code == 422
    assert upload(client, "SUM-4", "summary", "SUM-2").status_code == 302


def test_revoke_blocks_direct_and_indirect_descendants(client, app):
    upload(client, "RAW-1")
    upload(client, "CLEAN-1", "cleaned", "RAW-1")
    upload(client, "SUM-1", "summary", "CLEAN-1")
    upload(client, "SUM-2", "summary", "SUM-1")
    upload(client, "RAW-OTHER")
    upload(client, "CLEAN-OTHER", "cleaned", "RAW-OTHER")

    assert client.get("/download/SUM-2").status_code == 200
    response = revoke(client, "RAW-1")
    assert response.status_code == 302

    for file_id in ("RAW-1", "CLEAN-1", "SUM-1", "SUM-2"):
        blocked = client.get(f"/download/{file_id}")
        assert blocked.status_code == 410, file_id
        assert "下载已停止" in blocked.get_data(as_text=True)
    # Unrelated branch untouched.
    assert client.get("/download/CLEAN-OTHER").status_code == 200

    detail = client.get("/files/RAW-1").get_data(as_text=True)
    assert "CLEAN-1" in detail and "SUM-2" in detail
    index = client.get("/").get_data(as_text=True)
    assert "已停止下载" in index
    assert "已撤销" in index


def test_revoking_mid_chain_blocks_only_its_subtree(client, app):
    upload(client, "RAW-1")
    upload(client, "CLEAN-1", "cleaned", "RAW-1")
    upload(client, "SUM-1", "summary", "CLEAN-1")
    revoke(client, "CLEAN-1")
    assert client.get("/download/RAW-1").status_code == 200
    assert client.get("/download/CLEAN-1").status_code == 410
    assert client.get("/download/SUM-1").status_code == 410


def test_revoked_parent_cannot_be_referenced_by_new_file(client, app):
    upload(client, "RAW-1")
    revoke(client, "RAW-1")
    response = upload(client, "CLEAN-1", "cleaned", "RAW-1")
    assert response.status_code == 409
    assert "已撤销" in response.get_data(as_text=True)
    assert "CLEAN-1" not in rows(app)
    assert stored_files(app) == ["RAW-1"]


def test_repair_uses_new_id_and_old_derived_stay_blocked(client, app):
    upload(client, "RAW-1")
    upload(client, "CLEAN-1", "cleaned", "RAW-1")
    revoke(client, "RAW-1")

    upload(client, "RAW-1-FIX")
    upload(client, "CLEAN-1-FIX", "cleaned", "RAW-1-FIX")
    assert client.get("/download/RAW-1-FIX").status_code == 200
    assert client.get("/download/CLEAN-1-FIX").status_code == 200
    assert client.get("/download/CLEAN-1").status_code == 410
    # The old IDs remain registered, immutable, and still blocked.
    assert set(rows(app)) == {"RAW-1", "CLEAN-1", "RAW-1-FIX", "CLEAN-1-FIX"}


def test_duplicate_id_never_overwrites(client, app):
    assert upload(client, "RAW-1").status_code == 302
    before = rows(app)["RAW-1"]
    response = upload(client, "RAW-1", payload=b"a,b\n1,2\n")
    assert response.status_code == 409
    after = rows(app)["RAW-1"]
    assert before == after
    assert client.get("/download/RAW-1").data == RAW


def test_identity_and_dependencies_are_immutable(app, client):
    upload(client, "RAW-1")
    upload(client, "CLEAN-1", "cleaned", "RAW-1")
    upload(client, "RAW-2")
    conn = connect(app.config["DATABASE_PATH"])
    try:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE files SET parent_id = 'RAW-2' WHERE id = 'CLEAN-1'")
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE files SET id = 'X' WHERE id = 'RAW-1'")
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE files SET original_filename = 'x.csv' WHERE id = 'RAW-1'")
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("DELETE FROM files WHERE id = 'RAW-1'")
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE events SET detail = 'tampered'")
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("DELETE FROM events")
    finally:
        conn.close()


def test_revocation_is_one_way(app, client):
    upload(client, "RAW-1")
    revoke(client, "RAW-1", "质控-王")
    conn = connect(app.config["DATABASE_PATH"])
    try:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE files SET revoked_at = NULL WHERE id = 'RAW-1'")
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE files SET revoked_by = 'someone' WHERE id = 'RAW-1'")
    finally:
        conn.close()
    second = revoke(client, "RAW-1", "质控-王")
    assert second.status_code == 302
    with client.session_transaction() as session:
        assert any("已于" in m for _, m in session.get("_flashes", []))


def test_revoke_requires_operator(client, app):
    upload(client, "RAW-1")
    revoke(client, "RAW-1", "")
    assert rows(app)["RAW-1"]["revoked_at"] is None
    assert client.get("/download/RAW-1").status_code == 200


def test_reject_non_csv_and_empty(client, app):
    assert upload(client, "RAW-1", payload=b"").status_code == 422
    binary = upload(client, "RAW-2", payload=b"\x00\x01\x02binary")
    assert binary.status_code == 415
    assert rows(app) == {}
    assert stored_files(app) == []


def test_oversized_upload_rejected_without_trace(client, app):
    app.config["MAX_UPLOAD_BYTES"] = 16
    app.config["MAX_CONTENT_LENGTH"] = 64 * 1024
    response = upload(client, "RAW-BIG", payload=b"a,b\n" + b"1,2\n" * 100)
    assert response.status_code == 413
    assert rows(app) == {}
    assert stored_files(app) == []


def test_db_failure_rolls_back_artifact(app, client, monkeypatch):
    real_insert = registry._insert_file_row

    def broken(conn, **kwargs):
        raise sqlite3.OperationalError("simulated disk/db failure")

    monkeypatch.setattr(registry, "_insert_file_row", broken)
    with pytest.raises(sqlite3.OperationalError):
        registry.register_upload(
            file_id="RAW-1",
            kind="raw",
            parent_id=None,
            filename="raw.csv",
            stream=io.BytesIO(RAW),
            database_path=app.config["DATABASE_PATH"],
            storage_dir=app.config["STORAGE_DIR"],
        )
    monkeypatch.setattr(registry, "_insert_file_row", real_insert)
    assert rows(app) == {}
    assert stored_files(app) == []
    # A retry with the same ID must succeed: no stale artifact or lock.
    assert upload(client, "RAW-1").status_code == 302
    assert client.get("/download/RAW-1").data == RAW


def test_publish_failure_leaves_nothing_visible(app, tmp_path, monkeypatch):
    def fail(tmp_path_, final_path):
        raise OSError("simulated disk full")

    monkeypatch.setattr(registry, "_publish_artifact", fail)
    with pytest.raises(OSError):
        registry.register_upload(
            file_id="RAW-1",
            kind="raw",
            parent_id=None,
            filename="raw.csv",
            stream=io.BytesIO(RAW),
            database_path=app.config["DATABASE_PATH"],
            storage_dir=app.config["STORAGE_DIR"],
        )
    assert rows(app) == {}
    assert stored_files(app) == []
    assert os.listdir(os.path.join(app.config["STORAGE_DIR"], ".tmp")) == []


def test_startup_sweep_removes_orphans_and_keeps_registered(app, client):
    upload(client, "RAW-1")
    storage = app.config["STORAGE_DIR"]
    orphan = os.path.join(storage, "files", "CRASH-ORPHAN")
    with open(orphan, "wb") as fh:
        fh.write(b"partial")
    temp = os.path.join(storage, ".tmp", "dead.part")
    with open(temp, "wb") as fh:
        fh.write(b"partial")

    removed = registry.sweep_incomplete_writes(app.config["DATABASE_PATH"], storage)
    # Fresh temp files may belong to an upload still streaming elsewhere.
    assert removed == [orphan]
    assert os.path.exists(temp)
    assert stored_files(app) == ["RAW-1"]
    assert client.get("/download/RAW-1").status_code == 200

    stale = registry.sweep_incomplete_writes(
        app.config["DATABASE_PATH"], storage, tmp_max_age_seconds=0
    )
    assert stale == [temp]
    assert os.listdir(os.path.join(storage, ".tmp")) == []


def test_restart_preserves_download_eligibility(tmp_path):
    config = {
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "registry.db"),
        "STORAGE_DIR": str(tmp_path / "storage"),
    }
    first = create_app(config)
    c1 = first.test_client()
    upload(c1, "RAW-1")
    upload(c1, "CLEAN-1", "cleaned", "RAW-1")
    upload(c1, "RAW-2")
    revoke(c1, "RAW-1")

    second = create_app(dict(config, SECRET_KEY="other"))
    c2 = second.test_client()
    assert c2.get("/download/RAW-1").status_code == 410
    assert c2.get("/download/CLEAN-1").status_code == 410
    assert c2.get("/download/RAW-2").status_code == 200
    assert c2.get("/healthz").json == {"status": "ok"}


def test_missing_artifact_fails_closed(app, client):
    upload(client, "RAW-1")
    os.unlink(os.path.join(app.config["STORAGE_DIR"], "files", "RAW-1"))
    response = client.get("/download/RAW-1")
    assert response.status_code == 410
    assert "载荷缺失" in response.get_data(as_text=True)


def test_download_unknown_id_is_404(client):
    assert client.get("/download/NOPE").status_code == 404
    assert client.get("/files/NOPE").status_code == 404


def test_concurrent_upload_vs_revoke_never_exposes_revoked_parent(tmp_path):
    """Race a child registration against revoking its parent many times.

    Acceptable outcomes only: (a) the child is rejected because the revoke
    committed first, or (b) the child registered first and is therefore blocked
    once the revoke commits. A live child pointing at a revoked parent is a
    failure, as is a child row whose register event follows the parent's revoke
    event.
    """
    config = {
        "DATABASE_PATH": str(tmp_path / "registry.db"),
        "STORAGE_DIR": str(tmp_path / "storage"),
    }
    create_app(config)
    attempts = 25
    violations = []

    for i in range(attempts):
        parent = f"RAW-{i}"
        child = f"CLEAN-{i}"
        registry.register_upload(
            file_id=parent,
            kind="raw",
            parent_id=None,
            filename="raw.csv",
            stream=io.BytesIO(RAW),
            database_path=config["DATABASE_PATH"],
            storage_dir=config["STORAGE_DIR"],
        )
        barrier = threading.Barrier(2)

        def do_revoke():
            barrier.wait()
            if i % 2:
                # Give the competing upload a head start on half the rounds so
                # both serialization orders are actually exercised.
                time.sleep(0.03)
            registry.revoke_file(
                file_id=parent,
                revoked_by="racer",
                database_path=config["DATABASE_PATH"],
                storage_dir=config["STORAGE_DIR"],
            )

        def do_upload():
            barrier.wait()
            if not i % 2:
                time.sleep(0.03)
            try:
                registry.register_upload(
                    file_id=child,
                    kind="cleaned",
                    parent_id=parent,
                    filename="clean.csv",
                    stream=io.BytesIO(CLEAN),
                    database_path=config["DATABASE_PATH"],
                    storage_dir=config["STORAGE_DIR"],
                )
            except registry.RegistryError as exc:
                if exc.code not in ("parent_revoked", "parent_not_found"):
                    violations.append(f"{child}: unexpected {exc.code}")

        threads = [threading.Thread(target=do_revoke), threading.Thread(target=do_upload)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        conn = connect(config["DATABASE_PATH"])
        try:
            child_row = conn.execute("SELECT * FROM files WHERE id = ?", (child,)).fetchone()
            events = {
                (r["file_id"], r["action"]): r["id"]
                for r in conn.execute(
                    "SELECT id, file_id, action FROM events WHERE file_id IN (?, ?)", (parent, child)
                )
            }
            if child_row is not None:
                if not registry.download_state(
                    conn, child, config["STORAGE_DIR"]
                )["status"] == "revoked":
                    violations.append(f"{child}: still downloadable after parent revoke")
                if events.get((child, "register"), 0) > events.get((parent, "revoke"), 10**9):
                    violations.append(f"{child}: registered after parent revoke committed")
        finally:
            conn.close()

    assert not violations, violations[:5]
    # Both orderings must be exercised for this test to prove anything: at
    # least one child registered before the revoke and was blocked afterwards.
    conn = connect(config["DATABASE_PATH"])
    try:
        total_children = conn.execute("SELECT COUNT(*) FROM files WHERE kind = 'cleaned'").fetchone()[0]
    finally:
        conn.close()
    assert 0 < total_children < attempts, (
        f"race never produced the upload-first ordering ({total_children}/{attempts}); "
        "widen the jitter window"
    )


def test_orphan_artifact_is_reclaimed_on_retry(app, client):
    """A crash between publish and commit leaves no row; a retry may reuse the ID."""
    storage = app.config["STORAGE_DIR"]
    orphan = os.path.join(storage, "files", "RAW-1")
    with open(orphan, "wb") as fh:
        fh.write(b"stale partial payload")

    assert upload(client, "RAW-1").status_code == 302
    assert client.get("/download/RAW-1").data == RAW
    assert rows(app)["RAW-1"]["size_bytes"] == len(RAW)


def test_blocked_page_shows_blocking_chain(client, app):
    upload(client, "RAW-1")
    upload(client, "CLEAN-1", "cleaned", "RAW-1")
    upload(client, "SUM-1", "summary", "CLEAN-1")
    revoke(client, "RAW-1")
    body = client.get("/download/CLEAN-1").get_data(as_text=True)
    assert "阻断路径" in body
    for file_id in ("RAW-1", "CLEAN-1"):
        assert file_id in body
    assert "受影响下游链" in body and "SUM-1" in body

    leaf = client.get("/download/SUM-1").get_data(as_text=True)
    assert "阻断路径" in leaf and "RAW-1" in leaf


def test_real_disk_full_style_failure_leaves_no_registry_row(app, client, monkeypatch):
    """Simulate the visible store rejecting the rename: nothing may be visible."""
    import errno

    def enospc(src, dst):
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(registry.os, "link", enospc)
    response = upload(client, "RAW-1")
    assert response.status_code == 500
    assert rows(app) == {}
    assert stored_files(app) == []
    assert os.listdir(os.path.join(app.config["STORAGE_DIR"], ".tmp")) == []


def test_csrf_required_for_state_changes(client, app):
    def attempt(token=None):
        data = {
            "file_id": "RAW-1",
            "kind": "raw",
            "parent_id": "",
            "file": (io.BytesIO(RAW), "a.csv"),
        }
        if token is not None:
            data["csrf_token"] = token
        return client.post("/upload", data=data, content_type="multipart/form-data")

    assert attempt().status_code == 400
    assert rows(app) == {}
    keys = client.get("/").get_data(as_text=True)
    assert 'name="csrf_token"' in keys
    with client.session_transaction() as session:
        token = session["_csrf_token"]
    assert attempt(token).status_code == 302
    assert (
        client.post("/files/RAW-1/revoke", data={"operator": "x", "csrf_token": "wrong"}).status_code
        == 400
    )
    assert rows(app)["RAW-1"]["revoked_at"] is None


def test_cannot_attach_child_to_upstream_blocked_parent(client, app):
    upload(client, "RAW-1")
    upload(client, "CLEAN-1", "cleaned", "RAW-1")
    revoke(client, "RAW-1")
    response = upload(client, "SUM-1", "summary", "CLEAN-1")
    assert response.status_code == 409
    assert "上游" in response.get_data(as_text=True)
    assert "SUM-1" not in rows(app)


def test_commit_error_after_durable_commit_keeps_artifact(app, client, monkeypatch):
    """If COMMIT raised after the row became durable, the bytes must survive."""
    # Simulate a COMMIT that durably succeeds and then reports an error: run
    # the real commit, then raise. Deleting the artifact in that case would
    # break a registration that actually happened.
    real_commit = sqlite3.Connection.commit
    original_connect = registry.connect

    def flaky_connect(path):
        real = original_connect(path)

        def commit_then_raise():
            real_commit(real)
            raise sqlite3.OperationalError("simulated late commit failure")

        class Proxy:
            def __init__(self, wrapped):
                self._wrapped = wrapped

            def __getattr__(self, name):
                return getattr(self._wrapped, name)

            def execute(self, sql, *args):
                if sql.strip().upper() == "COMMIT":
                    return commit_then_raise()
                return self._wrapped.execute(sql, *args)

            def close(self):
                self._wrapped.close()

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                self._wrapped.close()

        return Proxy(real)

    monkeypatch.setattr(registry, "connect", flaky_connect)
    with pytest.raises(sqlite3.OperationalError):
        registry.register_upload(
            file_id="RAW-1",
            kind="raw",
            parent_id=None,
            filename="raw.csv",
            stream=io.BytesIO(RAW),
            database_path=app.config["DATABASE_PATH"],
            storage_dir=app.config["STORAGE_DIR"],
        )
    monkeypatch.setattr(registry, "connect", original_connect)
    # The registration is durable and the payload must still be downloadable.
    assert "RAW-1" in rows(app)
    assert client.get("/download/RAW-1").data == RAW


def test_truncated_payload_is_not_served(app, client):
    upload(client, "RAW-1")
    path = os.path.join(app.config["STORAGE_DIR"], "files", "RAW-1")
    with open(path, "r+b") as fh:
        fh.truncate(3)
    response = client.get("/download/RAW-1")
    assert response.status_code == 410
    assert "载荷缺失" in response.get_data(as_text=True)


def test_pages_have_no_inline_scripts_and_js_is_served(client, app):
    """CSP forbids inline script; the confirm dialog must live in app.js."""
    upload(client, "RAW-1")
    detail = client.get("/files/RAW-1").get_data(as_text=True)
    assert "<script>" not in detail
    assert "onsubmit=" not in detail
    assert "app.js" in detail
    js = client.get("/static/app.js")
    assert js.status_code == 200
    assert b"revoke-form" in js.data
    csp = client.get("/").headers["Content-Security-Policy"]
    assert "script-src 'self'" in csp
