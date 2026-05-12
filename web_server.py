# -*- coding: utf-8 -*-
"""
Web 版串口日志分析：Flask 后端，复用 desktop_serial_log_analyzer 全部业务逻辑。
启动：python web_server.py          → http://127.0.0.1:5000
      python web_server.py --port 8080
"""
from __future__ import annotations

import json
import os
import queue
import re
import tempfile
import threading
import time
import uuid
import webbrowser
from pathlib import Path

from flask import Flask, Response, jsonify, request, send_from_directory

from desktop_serial_log_analyzer import (
    APP_AUTHOR,
    APP_VERSION,
    DISCLAIMER_TEXT,
    WorkerConfig,
    _BUILTIN_RULE_CATEGORIES,
    _USER_RULES_PATH,
    _cursor_submit,
    _default_cleaning_prompt,
    _rule_import_prompt,
    _rules_from_llm_response,
    _run_analyze,
    _tabular_rules_source_to_plain,
    apply_cursor_env_to_dotenv,
)
from serial_alert_rules import (
    RAW_ALERT_RULE_DEFINITIONS,
    load_user_rules_raw,
    save_user_rules_raw,
)

app = Flask(__name__, static_folder="static")

_UPLOAD_DIR = Path(tempfile.gettempdir()) / "serial_log_web_uploads"
_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

_last_result: str = ""
_analysis_lock = threading.Lock()


@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


# ── Config ──────────────────────────────────────────────────────────

_CONFIG_KEYS = [
    "CURSOR_API_KEY",
    "CURSOR_GITHUB_REPO",
    "CURSOR_GITHUB_REF",
    "CURSOR_MODEL",
    "CURSOR_SUMMARY_MAX_CHARS",
    "CURSOR_CLEAN_MAX_CHARS",
]


@app.route("/api/config", methods=["GET"])
def get_config():
    cfg = {}
    for k in _CONFIG_KEYS:
        v = os.environ.get(k, "")
        if k == "CURSOR_API_KEY" and v:
            cfg[k] = v[:8] + "****" + v[-4:] if len(v) > 12 else "****"
        else:
            cfg[k] = v
    return jsonify(cfg)


@app.route("/api/config", methods=["POST"])
def save_config():
    data = request.get_json(force=True) or {}
    updates = {}
    for k in _CONFIG_KEYS:
        if k in data:
            updates[k] = str(data[k]).strip()
    if not updates:
        return jsonify({"error": "无有效配置项"}), 400
    apply_cursor_env_to_dotenv(updates)
    return jsonify({"ok": True, "saved": list(updates.keys())})


@app.route("/api/config/raw_key", methods=["GET"])
def get_raw_key():
    """Return full unmasked API key (for the settings form to re-save)."""
    return jsonify({"CURSOR_API_KEY": os.environ.get("CURSOR_API_KEY", "")})


# ── Rules ───────────────────────────────────────────────────────────

@app.route("/api/rules", methods=["GET"])
def list_rules():
    builtin = [
        {"source": "内置", "priority": p, "category": c, "label": l, "pattern": pat}
        for p, c, l, pat in RAW_ALERT_RULE_DEFINITIONS
    ]
    user = load_user_rules_raw(_USER_RULES_PATH)
    custom = [
        {"source": "自定义", "priority": r["priority"], "category": r["category"],
         "label": r["label"], "pattern": r["pattern"]}
        for r in user
    ]
    return jsonify({"rules": builtin + custom, "builtin_count": len(builtin)})


@app.route("/api/rules", methods=["POST"])
def add_rule():
    data = request.get_json(force=True) or {}
    try:
        pri = int(data.get("priority", 5))
    except (TypeError, ValueError):
        return jsonify({"error": "优先级必须是整数"}), 400
    cat = str(data.get("category", "")).strip()
    pat = str(data.get("pattern", "")).strip()
    lbl = str(data.get("label", "")).strip() or cat
    if not cat or not pat:
        return jsonify({"error": "请填写 category 与 pattern"}), 400
    try:
        re.compile(pat, re.IGNORECASE)
    except re.error as e:
        return jsonify({"error": f"正则无效：{e}"}), 400

    items = load_user_rules_raw(_USER_RULES_PATH)
    items.append({"priority": pri, "category": cat, "label": lbl, "pattern": pat})
    save_user_rules_raw(_USER_RULES_PATH, items)
    return jsonify({"ok": True, "total_custom": len(items)})


@app.route("/api/rules/<int:idx>", methods=["DELETE"])
def delete_rule(idx: int):
    items = load_user_rules_raw(_USER_RULES_PATH)
    if idx < 0 or idx >= len(items):
        return jsonify({"error": "索引越界"}), 404
    removed = items.pop(idx)
    save_user_rules_raw(_USER_RULES_PATH, items)
    return jsonify({"ok": True, "removed": removed["category"]})


@app.route("/api/rules/import", methods=["POST"])
def import_rules():
    if "file" not in request.files:
        return jsonify({"error": "请上传文件"}), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "文件名为空"}), 400
    suf = Path(f.filename).suffix.lower()
    if suf not in (".xlsx", ".xlsm", ".csv"):
        return jsonify({"error": "仅支持 .xlsx/.xlsm/.csv"}), 400

    api_key = os.environ.get("CURSOR_API_KEY", "").strip()
    repo = os.environ.get("CURSOR_GITHUB_REPO", "").strip()
    if not api_key or not repo:
        return jsonify({"error": "请先配置 CURSOR_API_KEY 与 CURSOR_GITHUB_REPO"}), 400

    tmp = _UPLOAD_DIR / f"{uuid.uuid4().hex}{suf}"
    try:
        f.save(str(tmp))
        plain = _tabular_rules_source_to_plain(tmp)
        llm_text = _cursor_submit(_rule_import_prompt(plain))
        new_items = _rules_from_llm_response(llm_text)
        if not new_items:
            return jsonify({"error": "模型未返回任何可用规则"}), 422
    except Exception as e:
        return jsonify({"error": str(e)[:1600]}), 500
    finally:
        tmp.unlink(missing_ok=True)

    existing = load_user_rules_raw(_USER_RULES_PATH)
    reserved: set[str] = {x["category"] for x in existing} | set(_BUILTIN_RULE_CATEGORIES)
    added: list[dict] = []
    for it in new_items:
        c = it["category"]
        if c in reserved:
            base, n = c, 2
            while f"{base}_{n}" in reserved:
                n += 1
            c = f"{base}_{n}"
        it["category"] = c
        reserved.add(c)
        added.append(it)
    merged = existing + added
    save_user_rules_raw(_USER_RULES_PATH, merged)
    return jsonify({"ok": True, "added": len(added), "rules": added})


# ── Analyze (SSE) ──────────────────────────────────────────────────

@app.route("/api/analyze", methods=["POST"])
def analyze():
    global _last_result
    if _analysis_lock.locked():
        return jsonify({"error": "已有分析任务在运行"}), 409

    if "file" not in request.files:
        return jsonify({"error": "请上传日志文件"}), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "文件名为空"}), 400

    notes = request.form.get("analysis_notes", "")
    clean_prompt = request.form.get("clean_prompt", "") or _default_cleaning_prompt()
    try:
        max_chars = int(request.form.get("summary_max_chars", "90000"))
    except ValueError:
        max_chars = 90000

    suf = Path(f.filename).suffix
    tmp = _UPLOAD_DIR / f"{uuid.uuid4().hex}{suf}"
    f.save(str(tmp))

    cfg = WorkerConfig(
        file_path=tmp,
        max_chars=max_chars,
        user_clean_prompt=clean_prompt,
        user_analysis_notes=notes,
    )

    q: queue.Queue = queue.Queue()

    def run():
        try:
            with _analysis_lock:
                _run_analyze(cfg, q)
        finally:
            tmp.unlink(missing_ok=True)

    t = threading.Thread(target=run, daemon=True)
    t.start()

    def generate():
        global _last_result
        while True:
            try:
                msg = q.get(timeout=2)
            except queue.Empty:
                if not t.is_alive():
                    yield "data: " + json.dumps({"type": "error", "msg": "分析线程意外退出"}) + "\n\n"
                    break
                yield "data: " + json.dumps({"type": "heartbeat"}) + "\n\n"
                continue

            kind = msg[0]
            if kind == "progress":
                pct, text = msg[1], msg[2]
                yield "data: " + json.dumps({"type": "progress", "pct": pct, "msg": text}) + "\n\n"
            elif kind == "ok":
                result = msg[1]
                _last_result = result
                yield "data: " + json.dumps({"type": "ok", "result": result}) + "\n\n"
                break
            elif kind == "err":
                yield "data: " + json.dumps({"type": "error", "msg": msg[1]}) + "\n\n"
                break

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/api/result/download")
def download_result():
    if not _last_result.strip():
        return jsonify({"error": "暂无结果"}), 404
    from datetime import datetime
    ts = datetime.now().strftime("%Y%m%d_%H%M")
    return Response(
        _last_result,
        mimetype="text/plain; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename=serial_analysis_{ts}.txt"},
    )


# ── Bug Records (DB) ────────────────────────────────────────────────

def _json_serial(obj):
    from datetime import datetime, date
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    return str(obj)


@app.route("/api/bugs", methods=["GET"])
def api_list_bugs():
    try:
        from db_manager import list_bugs, count_bugs, init_db
        init_db()
        verdict = request.args.get("verdict")
        source = request.args.get("source")
        limit = int(request.args.get("limit", "200"))
        offset = int(request.args.get("offset", "0"))
        rows = list_bugs(limit=limit, offset=offset, verdict=verdict, source_file=source)
        stats = count_bugs()
        return Response(
            json.dumps({"bugs": rows, "stats": stats}, default=_json_serial, ensure_ascii=False),
            mimetype="application/json",
        )
    except Exception as e:
        return jsonify({"error": str(e)[:800]}), 500


@app.route("/api/bugs/<int:bug_id>", methods=["GET", "DELETE"])
def api_bug_detail(bug_id: int):
    if request.method == "DELETE":
        try:
            from db_manager import delete_bug
            ok = delete_bug(bug_id)
            return jsonify({"ok": ok})
        except Exception as e:
            return jsonify({"error": str(e)[:500]}), 500
    try:
        from db_manager import get_bug
        b = get_bug(bug_id)
        if not b:
            return jsonify({"error": "未找到"}), 404
        return Response(
            json.dumps({"bug": b}, default=_json_serial, ensure_ascii=False),
            mimetype="application/json",
        )
    except Exception as e:
        return jsonify({"error": str(e)[:500]}), 500


@app.route("/api/bugs/<int:bug_id>/verdict", methods=["PUT"])
def api_update_verdict(bug_id: int):
    try:
        from db_manager import update_verdict
        data = request.get_json(force=True) or {}
        v = data.get("verdict", "待定")
        notes = data.get("notes", "")
        if v not in ("待定", "确认", "误报", "忽略"):
            return jsonify({"error": "verdict 须为 待定/确认/误报/忽略"}), 400
        ok = update_verdict(bug_id, v, notes)
        return jsonify({"ok": ok})
    except Exception as e:
        return jsonify({"error": str(e)[:500]}), 500


@app.route("/api/bugs/test", methods=["GET"])
def api_test_db():
    try:
        from db_manager import test_connection
        ok, msg = test_connection()
        return jsonify({"ok": ok, "msg": msg})
    except Exception as e:
        return jsonify({"ok": False, "msg": str(e)[:500]})


# ── Meta ────────────────────────────────────────────────────────────

@app.route("/api/about")
def about():
    return jsonify({"version": APP_VERSION, "author": APP_AUTHOR, "disclaimer": DISCLAIMER_TEXT})


# ── Main ────────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description="串口日志分析 Web 版")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()

    url = f"http://{args.host}:{args.port}"
    if not args.no_browser:
        threading.Timer(1.2, lambda: webbrowser.open(url)).start()
    print(f"\n  串口日志分析 Web → {url}\n")
    app.run(host=args.host, port=args.port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
