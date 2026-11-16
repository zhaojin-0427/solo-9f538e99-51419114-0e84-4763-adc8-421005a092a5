"""Flask entrypoint for the stability-trial file registry."""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime

from flask import (
    Flask,
    abort,
    flash,
    get_flashed_messages,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)

from . import csrf, registry
from .db import close_db, get_db, get_file, init_database
from .registry import KIND_LABELS, KINDS, RegistryError

_DEFAULT_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY", "dev-only-change-me"),
        DATABASE_PATH=os.environ.get(
            "DATABASE_PATH", os.path.join(_DEFAULT_DATA_DIR, "registry.db")
        ),
        STORAGE_DIR=os.environ.get(
            "STORAGE_DIR", os.path.join(_DEFAULT_DATA_DIR, "storage")
        ),
        MAX_UPLOAD_BYTES=int(os.environ.get("MAX_UPLOAD_BYTES", str(20 * 1024 * 1024))),
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_HTTPONLY=True,
    )
    if test_config:
        app.config.update(test_config)
    app.config["MAX_CONTENT_LENGTH"] = app.config["MAX_UPLOAD_BYTES"] + 512 * 1024

    os.makedirs(app.config["STORAGE_DIR"], exist_ok=True)
    init_database(app.config["DATABASE_PATH"], app.config["STORAGE_DIR"])
    registry.sweep_incomplete_writes(
        app.config["DATABASE_PATH"], app.config["STORAGE_DIR"]
    )
    app.teardown_appcontext(close_db)

    app.jinja_env.globals["csrf_token"] = csrf.token

    @app.before_request
    def protect_posts():
        if request.method == "POST" and not csrf.valid():
            abort(
                400,
                description="表单已过期或来源不受信任，请返回页面重新提交。",
            )

    @app.after_request
    def security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self'; img-src 'self' data:; "
            "script-src 'self'; form-action 'self'; base-uri 'none'; object-src 'none'",
        )
        return response

    def index_context(error=None, form=None, status=200):
        files = registry.list_files(get_db())
        stats = {
            "total": len(files),
            "raw": sum(1 for f in files if f["row"]["kind"] == "raw"),
            "blocked": sum(1 for f in files if not f["eligible"]),
            "revoked": sum(1 for f in files if f["row"]["revoked_at"] is not None),
        }
        body = render_template(
            "index.html",
            files=files,
            stats=stats,
            kinds=KINDS,
            kind_labels=KIND_LABELS,
            messages=get_flashed_messages(with_categories=True),
            form=form or {},
            error=error,
            max_mb=app.config["MAX_UPLOAD_BYTES"] // (1024 * 1024),
        )
        return (body, status) if status != 200 else body

    @app.get("/healthz")
    def healthz():
        get_db().execute("SELECT 1").fetchone()
        return {"status": "ok"}

    @app.get("/")
    def index():
        return index_context()

    @app.post("/upload")
    def upload():
        form = {
            "file_id": request.form.get("file_id", "").strip(),
            "kind": request.form.get("kind", "").strip(),
            "parent_id": request.form.get("parent_id", "").strip(),
        }
        upload_file = request.files.get("file")
        if upload_file is None or not upload_file.filename:
            return index_context(
                error={"code": "missing_file", "message": "请选择要上传的 CSV 文件"},
                form=form,
                status=422,
            )

        try:
            result = registry.register_upload(
                file_id=form["file_id"],
                kind=form["kind"],
                parent_id=form["parent_id"],
                filename=upload_file.filename,
                stream=upload_file.stream,
                database_path=app.config["DATABASE_PATH"],
                storage_dir=app.config["STORAGE_DIR"],
                max_bytes=app.config["MAX_UPLOAD_BYTES"],
            )
        except RegistryError as exc:
            app.logger.info("upload rejected: %s (%s)", exc.code, exc.message)
            return index_context(
                error={"code": exc.code, "message": exc.message}, form=form, status=exc.status
            )
        except sqlite3.OperationalError:
            app.logger.exception("registry write failed")
            return index_context(
                error={
                    "code": "db_busy",
                    "message": "登记数据库繁忙或写入失败，本次上传未登记，请重试",
                },
                form=form,
                status=503,
            )
        except Exception:
            app.logger.exception("upload failed")
            return index_context(
                error={
                    "code": "internal",
                    "message": "写盘或登记失败，本次上传未生效（未产生可下载文件）",
                },
                form=form,
                status=500,
            )

        flash(
            f"已登记 {result.file_id}（{KIND_LABELS[result.kind]}），依赖已锁定、不可修改。",
            "success",
        )
        return redirect(url_for("file_detail", file_id=result.file_id))

    @app.get("/files/<file_id>")
    def file_detail(file_id):
        conn = get_db()
        row = get_file(conn, file_id)
        if row is None:
            abort(404)
        files = registry.list_files(conn)
        entry = next((f for f in files if f["row"]["id"] == file_id), None)
        if entry is None:  # pragma: no cover - defensive
            abort(404)
        impact = registry.impact_report(conn, file_id)
        path = os.path.join(app.config["STORAGE_DIR"], "files", row["stored_name"])
        header, preview = (
            registry.read_csv_preview(path) if os.path.isfile(path) else ([], [])
        )
        return render_template(
            "detail.html",
            entry=entry,
            impact=impact,
            lineage=registry.lineage(conn, file_id),
            header=header,
            preview=preview,
            events=registry.events_for(conn, file_id),
            kind_labels=KIND_LABELS,
            messages=get_flashed_messages(with_categories=True),
        )

    @app.post("/files/<file_id>/revoke")
    def revoke(file_id):
        operator = request.form.get("operator", "").strip()
        try:
            row = registry.revoke_file(
                file_id=file_id,
                revoked_by=operator,
                database_path=app.config["DATABASE_PATH"],
                storage_dir=app.config["STORAGE_DIR"],
            )
        except RegistryError as exc:
            flash(exc.message, "error")
            if exc.code == "not_found":
                abort(404)
            return redirect(url_for("file_detail", file_id=file_id))
        except sqlite3.OperationalError:
            app.logger.exception("revoke failed")
            flash("撤销未生效：数据库繁忙，请重试", "error")
            return redirect(url_for("file_detail", file_id=file_id))

        affected = len(registry.impact_report(get_db(), file_id)["all"])
        flash(
            f"已撤销 {row['id']}（质控员：{row['revoked_by']}）。"
            f"直接或间接依赖它的 {affected} 个文件已立即停止下载。",
            "warning" if affected else "success",
        )
        return redirect(url_for("file_detail", file_id=file_id))

    @app.get("/download/<file_id>")
    def download(file_id):
        conn = get_db()
        state = registry.download_state(conn, file_id, app.config["STORAGE_DIR"])
        if state is None:
            abort(404)
        if state["status"] != "ok":
            return (
                render_template(
                    "blocked.html",
                    row=state["row"],
                    blocker=state["blocker"],
                    missing=state["status"] == "missing",
                    lineage=registry.lineage(conn, file_id),
                    impact=registry.impact_report(conn, file_id),
                    kind_labels=KIND_LABELS,
                ),
                410,
            )
        row, path = state["row"], state["path"]
        return send_file(
            path,
            mimetype="text/csv",
            as_attachment=True,
            download_name=row["original_filename"],
            etag=row["sha256"],
            last_modified=datetime.fromisoformat(row["created_at"]),
        )

    @app.errorhandler(400)
    def bad_request(error):
        return (
            render_template(
                "error.html",
                code=400,
                title="请求被拒绝",
                message=getattr(error, "description", "请求不合法。"),
            ),
            400,
        )

    @app.errorhandler(404)
    def not_found(_error):
        return (
            render_template(
                "error.html",
                code=404,
                title="未找到",
                message="该文件 ID 未登记，或页面不存在。",
            ),
            404,
        )

    @app.errorhandler(413)
    def too_large(_error):
        return (
            render_template(
                "error.html",
                code=413,
                title="上传过大",
                message=f"单个文件上限为 {app.config['MAX_UPLOAD_BYTES'] // (1024 * 1024)} MiB。",
            ),
            413,
        )

    @app.errorhandler(500)
    def server_error(_error):
        return (
            render_template(
                "error.html",
                code=500,
                title="服务错误",
                message="请求未完成。写入类操作已整体回滚，不会留下可下载的半成品。",
            ),
            500,
        )

    return app
