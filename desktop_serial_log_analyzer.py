# -*- coding: utf-8 -*-
"""
桌面 GUI（tkinter）：打开串口/设备 .log/.txt，规则扫描 + Cloud 清洗节选 + Cursor 总结。
清洗文案、节选/材料体量：菜单「设置」；串口匹配规则与表格导入：菜单「规则」。依赖：requests、python-dotenv、pypdf（仅 .pdf）、openpyxl（.xlsx/.xlsm）、csv（.csv 规则导入）。

运行：python desktop_serial_log_analyzer.py
"""
from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
import queue
import re
import sys
import threading
import traceback
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk
import tkinter as tk

import requests
from dotenv import load_dotenv

from serial_alert_rules import (
    RAW_ALERT_RULE_DEFINITIONS,
    load_user_rules_raw,
    save_user_rules_raw,
)

_BUILTIN_RULE_CATEGORIES: frozenset[str] = frozenset(t[1] for t in RAW_ALERT_RULE_DEFINITIONS)

def _app_root() -> Path:
    """源码：项目目录；PyInstaller exe：exe 所在目录（.env / 用户规则与输出持久化）。"""
    if getattr(sys, "frozen", False) and getattr(sys, "executable", None):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


_ROOT = _app_root()
load_dotenv(_ROOT / ".env")
load_dotenv(Path.cwd() / ".env")

# ----- 内联：日志解析 + Cursor Cloud（原独立 summarize_*.py）-----

_INTERESTING = re.compile(
    r"(ERROR|ERR\b|FATAL|CRITICAL|\bWARN(?:ING)?\b|"
    r"异常|错误|失败|告警|Traceback|\bException\b)",
    re.I,
)
_TS_HEAD = re.compile(
    r"^(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?|\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s*"
)


@dataclass
class Incident:
    seq: int
    ts: str
    source_file: str
    tags: list[str]
    log_line: str
    analysis: str = ""


def _read_file_text(path: Path) -> str:
    suf = path.suffix.lower()
    if suf == ".pdf":
        from pypdf import PdfReader

        reader = PdfReader(str(path))
        chunks: list[str] = []
        for page in reader.pages:
            chunks.append(page.extract_text() or "")
        return "\n".join(chunks)
    raw = path.read_bytes()
    for enc in ("utf-8-sig", "utf-8", "gb18030", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def _line_ts(line: str) -> str:
    m = _TS_HEAD.match(line.strip())
    return m.group(1).strip() if m else ""


def _line_tags(line: str) -> list[str]:
    tags: list[str] = []
    low = line.lower()
    if "traceback" in low:
        tags.append("TRACEBACK")
    if re.search(r"\bexception\b", low):
        tags.append("EXCEPTION")
    for kw in ("fatal", "critical", "error", "err", "warning", "warn"):
        if re.search(rf"\b{re.escape(kw)}\b", low):
            tags.append(kw.upper())
    for zh in ("异常", "错误", "失败", "告警"):
        if zh in line:
            tags.append(zh)
    return tags


def bug_type_cn(tags: list[str]) -> str:
    blob = " ".join(tags).lower()
    if "timeout" in blob or "超时" in blob:
        return "超时/无响应"
    if "memory" in blob or "oom" in blob or "内存" in blob:
        return "内存/资源"
    if "network" in blob or "socket" in blob or "连接" in blob:
        return "网络/连接"
    if "traceback" in blob or "exception" in blob:
        return "异常/栈"
    if "error" in blob or "err" in blob or "错误" in blob or "异常" in blob:
        return "运行错误"
    if "warn" in blob or "warning" in blob or "告警" in blob:
        return "告警"
    return "其他"


def severity_from_tags(tags: list[str], log_line: str) -> str:
    blob = (" ".join(tags) + " " + log_line).upper()
    if any(x in blob for x in ("FATAL", "CRITICAL", "严重", "崩溃")):
        return "高"
    if any(
        x in blob
        for x in ("ERROR", " ERR", "EXCEPTION", "TRACEBACK", "错误", "异常", "失败")
    ):
        return "中"
    if any(x in blob for x in ("WARN", "WARNING", "告警")):
        return "低"
    return "提示"


def short_title(log_line: str, max_len: int = 72) -> str:
    s = (log_line or "").strip().replace("\n", " ")
    if len(s) <= max_len:
        return s
    return s[: max_len - 1] + "\u2026"


def parse_report_text(text: str, source_file: str) -> list[Incident]:
    out: list[Incident] = []
    seq = 0
    for line in text.splitlines():
        line_r = line.rstrip("\n\r")
        if not line_r.strip():
            continue
        if not _INTERESTING.search(line_r):
            continue
        seq += 1
        tags = _line_tags(line_r)
        if not tags:
            tags = ["SIGNAL"]
        out.append(
            Incident(
                seq=seq,
                ts=_line_ts(line_r),
                source_file=source_file,
                tags=tags,
                log_line=line_r.strip(),
                analysis="",
            )
        )
    return out


CURSOR_API_BASE = "https://api.cursor.com"
_agent_id_cache: str | None = None


def _T(*parts: str) -> str:
    return "".join(parts)


def _cursor_basic_auth_header(api_key: str) -> str:
    token = base64.b64encode(f"{api_key}:".encode()).decode("ascii")
    return f"Basic {token}"


def _normalize_github_repo_url(url: str) -> str:
    u = (url or "").strip().rstrip("/")
    if len(u) >= 4 and u.lower().endswith(".git"):
        return u[:-4].rstrip("/")
    return u


def _is_ref_validation_error(detail: str) -> bool:
    s = (detail or "").lower()
    return (
        "validation_error" in s
        and "branch" in s
        and ("does not exist" in s or "verify existence" in s)
    )


def _candidate_starting_refs(primary_ref: str) -> list[str]:
    refs = [primary_ref.strip() if primary_ref else "", "main", "master", ""]
    out: list[str] = []
    seen: set[str] = set()
    for r in refs:
        if r in seen:
            continue
        seen.add(r)
        out.append(r)
    return out


def _repair_mojibake_text(text: str) -> str:
    if not isinstance(text, str) or not text:
        return text
    mojibake_hits = ("\u00c3", "\u00c2", "\u00e6", "\u00e5", "\u00e4")
    if not any(ch in text for ch in mojibake_hits):
        return text
    try:
        fixed = text.encode("latin1", errors="strict").decode("utf-8", errors="strict")
        if fixed.count("\ufffd") <= text.count("\ufffd"):
            return fixed
    except Exception:
        return text
    return text


def _parse_sse_stream(response: requests.Response):
    event_name = None
    for raw in response.iter_lines(decode_unicode=False):
        if raw is None:
            continue
        if isinstance(raw, bytes):
            line = raw.decode("utf-8", errors="replace").strip()
        else:
            line = str(raw).strip()
        if not line:
            continue
        if line.startswith("event:"):
            event_name = line[6:].strip()
            continue
        if line.startswith("data:"):
            payload = line[5:].strip()
            if payload == "{}" or not payload:
                yield event_name, {}
                continue
            try:
                data = json.loads(payload)
            except json.JSONDecodeError:
                continue
            yield event_name, data
            event_name = None


def _cursor_stream_collect(agent_id: str, run_id: str, api_key: str) -> str:
    url = f"{CURSOR_API_BASE}/v1/agents/{agent_id}/runs/{run_id}/stream"
    headers = {
        "Authorization": _cursor_basic_auth_header(api_key),
        "Accept": "text/event-stream",
    }
    parts: list[str] = []
    with requests.get(url, headers=headers, stream=True, timeout=600) as resp:
        resp.encoding = "utf-8"
        resp.raise_for_status()
        for event_name, data in _parse_sse_stream(resp):
            if event_name == "assistant" and isinstance(data, dict) and "text" in data:
                parts.append(_repair_mojibake_text(data["text"]))
            elif event_name == "result":
                break
    return "".join(parts)


def _cursor_submit(prompt: str) -> str:
    global _agent_id_cache

    api_key = os.environ.get("CURSOR_API_KEY", "").strip()
    github_repo_raw = os.environ.get("CURSOR_GITHUB_REPO", "").strip()
    github_repo = _normalize_github_repo_url(github_repo_raw)
    if not api_key:
        raise SystemExit("Set CURSOR_API_KEY (.env).")
    if not github_repo:
        raise SystemExit("Set CURSOR_GITHUB_REPO (cloneable GitHub URL).")

    ref = os.environ.get("CURSOR_GITHUB_REF", "main").strip() or "main"
    model = os.environ.get("CURSOR_MODEL", "").strip() or None
    headers = {
        "Authorization": _cursor_basic_auth_header(api_key),
        "Content-Type": "application/json",
    }

    agent_id = _agent_id_cache
    if agent_id is None:
        last_error = None
        r = None
        for ref_try in _candidate_starting_refs(ref):
            repo_cfg = {"url": github_repo}
            if ref_try:
                repo_cfg["startingRef"] = ref_try
            body = {
                "prompt": {"text": prompt},
                "repos": [repo_cfg],
                "autoCreatePR": False,
            }
            if model:
                body["model"] = {"id": model}
            r = requests.post(
                f"{CURSOR_API_BASE}/v1/agents",
                headers=headers,
                json=body,
                timeout=120,
            )
            try:
                r.raise_for_status()
                payload = r.json()
                agent_id = payload["agent"]["id"]
                run_id = payload["run"]["id"]
                _agent_id_cache = agent_id
                return _cursor_stream_collect(agent_id, run_id, api_key)
            except requests.HTTPError as e:
                try:
                    detail = r.text[:1200]
                except Exception:
                    detail = str(e)
                if _is_ref_validation_error(detail):
                    last_error = e
                    continue
                raise RuntimeError(f"Cursor create agent failed: {e}\n{detail}") from e
        if last_error is not None:
            raise RuntimeError(f"Cursor branch/ref failed after retries: {last_error}") from last_error
        raise RuntimeError("Cursor agent create failed")

    r = requests.post(
        f"{CURSOR_API_BASE}/v1/agents/{agent_id}/runs",
        headers=headers,
        json={"prompt": {"text": prompt}},
        timeout=120,
    )
    r.raise_for_status()
    run_id = r.json()["run"]["id"]
    return _cursor_stream_collect(agent_id, run_id, api_key)


def _xlsx_workbook_to_plain(path: Path, max_chars: int = 36_000) -> str:
    """将工作簿各表导出为可读纯文本（制表符分列），供 Cursor 提取串口匹配规则。"""
    try:
        from openpyxl import load_workbook
    except ImportError as e:
        raise RuntimeError("缺少 openpyxl，请执行：pip install openpyxl") from e
    # 部分工作簿在 read_only 下仅迭代到首行，故用常规模式以保证压测类 xlsx 读全。
    wb = load_workbook(str(path), read_only=False, data_only=True)
    parts: list[str] = []
    try:
        for sheet_name in wb.sheetnames:
            ws = wb[sheet_name]
            parts.append(f"\n## 工作表：{sheet_name}\n")
            for row in ws.iter_rows(values_only=True):
                cells: list[str] = []
                for c in row or ():
                    if c is None:
                        cells.append("")
                    else:
                        s = str(c).strip().replace("\r\n", "\n").replace("\r", "\n")
                        if "\n" in s:
                            s = re.sub(r"\s+", " ", s)
                        cells.append(s)
                if any(x for x in cells):
                    line = "\t".join(cells).strip()
                    if line:
                        parts.append(line + "\n")
    finally:
        wb.close()
    blob = "".join(parts).strip()
    if not blob:
        raise RuntimeError("Excel 中无有效文本单元格。")
    if len(blob) > max_chars:
        blob = (
            blob[:max_chars].rstrip()
            + "\n\n（以上内容因长度限制已截断，请仅基于已给片段归纳规则。）\n"
        )
    return blob


def _csv_file_to_plain(path: Path, max_chars: int = 36_000) -> str:
    """将 CSV 解码为与 xlsx 导出风格一致的纯文本（制表符分列），供 Cursor 提取规则。"""
    raw = path.read_bytes()
    text: str | None = None
    for enc in ("utf-8-sig", "utf-8", "gb18030", "latin-1"):
        try:
            text = raw.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    if text is None:
        text = raw.decode("utf-8", errors="replace")

    sample = text[:8192]
    dialect: type[csv.Dialect] | csv.Dialect = csv.excel
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
    except csv.Error:
        first = sample.splitlines()[0] if sample else ""
        if first.count("\t") >= first.count(",") and "\t" in first:
            dialect = csv.excel_tab

    parts: list[str] = [f"\n## 文件：{path.name}（CSV）\n"]
    total = len(parts[0])
    f = io.StringIO(text)
    reader = csv.reader(f, dialect=dialect)
    for row in reader:
        cells: list[str] = []
        for c in row:
            s = (c or "").strip().replace("\r\n", "\n").replace("\r", "\n")
            if "\n" in s:
                s = re.sub(r"\s+", " ", s)
            cells.append(s)
        if not any(cells):
            continue
        line = "\t".join(cells).strip()
        if not line:
            continue
        chunk = line + "\n"
        if total + len(chunk) > max_chars:
            parts.append("\n（以上内容因长度限制已截断，请仅基于已给片段归纳规则。）\n")
            break
        parts.append(chunk)
        total += len(chunk)

    blob = "".join(parts).strip()
    body = blob
    marker = f"## 文件：{path.name}（CSV）"
    if marker in body:
        body = body.split(marker, 1)[-1].strip()
    if not body:
        raise RuntimeError("CSV 中无有效数据行。")
    return blob


def _tabular_rules_source_to_plain(path: Path, max_chars: int = 36_000) -> str:
    suf = path.suffix.lower()
    if suf == ".csv":
        return _csv_file_to_plain(path, max_chars)
    if suf in (".xlsx", ".xlsm"):
        return _xlsx_workbook_to_plain(path, max_chars)
    raise RuntimeError("仅支持 .xlsx、.xlsm 或 .csv 文件。")


_RULE_IMPORT_INSTRUCTIONS = (
    "你是嵌入式串口日志匹配规则设计助手。下面文本来自「压测/稳定性测试用例」等表格："
    "Excel 多工作表导出，或 CSV 按行分列；其中常含「主要日志」「异常日志」「关键日志」「关注的日志」等段落，"
    "以及用 | 分隔的关键字列表。\n\n"
    "任务：从中提炼若干条用于在设备串口 log 单行文本上做正则匹配的告警规则。\n"
    "硬性要求：\n"
    "1) 只输出一个 JSON 数组本体，不要用 Markdown 代码围栏，不要附加解释性文字。\n"
    "2) 数组元素为对象，字段：priority（整数，默认 5，数字越小越优先）、"
    "category（英文小写与下划线组成的唯一键，如 ble_bind_fail）、"
    "label（中文简短显示名）、pattern（Python re 可用的正则字符串；默认忽略大小写，"
    "若未写 (?i) 前缀则仍按忽略大小写编译）。\n"
    "3) 每条规则聚焦一类现象；可把文档里用 | 列举的同组关键词合并为一条 alternation 正则。\n"
    "4) 总条数不超过 48；不要编造文档未提及的现象。\n"
    "5) pattern 必须合法，避免无转义的裸反斜杠错误；优先用非捕获组 (?:...) 控制分支。\n\n"
    "示例（仅说明格式，勿照抄）：\n"
    '[{"priority":5,"category":"mqtt_publish_err","label":"MQTT发布失败",'
    '"pattern":"(?i)(mqtt.+(fail|err)|publish.+fail)"}]\n\n'
)


def _rule_import_prompt(table_plain: str) -> str:
    return _RULE_IMPORT_INSTRUCTIONS + "--- 表格导出 ---\n\n" + table_plain


def _parse_json_array_from_llm(text: str) -> list:
    t = (text or "").strip()
    if not t:
        raise ValueError("模型返回为空。")
    m = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", t, re.I)
    if m:
        t = m.group(1).strip()
    start = t.find("[")
    if start < 0:
        raise ValueError("未在模型输出中找到 JSON 数组（以 [ 开头）。")
    dec = json.JSONDecoder()
    try:
        data, _end = dec.raw_decode(t, start)
    except json.JSONDecodeError as e:
        raise ValueError(f"JSON 解析失败：{e}") from e
    if not isinstance(data, list):
        raise ValueError("顶层 JSON 须为数组。")
    return data


def _slug_rule_category(raw: str, fallback: str) -> str:
    s = (raw or "").strip().lower()
    s = re.sub(r"[^a-z0-9_]+", "_", s)
    s = re.sub(r"_+", "_", s).strip("_")
    if not s:
        fb = re.sub(r"[^a-z0-9_]+", "_", (fallback or "").lower())
        fb = re.sub(r"_+", "_", fb).strip("_")[:32]
        if fb:
            s = fb
        else:
            h = hashlib.md5((fallback or "rule").encode("utf-8")).hexdigest()[:10]
            s = "case_" + h
    return s[:64]


def _coerce_imported_rule_dict(obj: object, seq: int) -> dict:
    if not isinstance(obj, dict):
        raise ValueError(f"第 {seq} 条规则不是 JSON 对象。")
    cat_raw = str(obj.get("category", "")).strip()
    pat = str(obj.get("pattern", "")).strip()
    lbl = str(obj.get("label", "")).strip() or cat_raw or f"规则{seq}"
    pri_raw = obj.get("priority", 5)
    try:
        pri = int(pri_raw)
    except (TypeError, ValueError):
        pri = 5
    if not pat:
        raise ValueError(f"第 {seq} 条缺少 pattern。")
    try:
        re.compile(pat, re.I)
    except re.error as e:
        raise ValueError(f"第 {seq} 条正则无效：{e}") from e
    cat = _slug_rule_category(cat_raw, lbl)
    return {"priority": pri, "category": cat, "label": lbl, "pattern": pat}


def _rules_from_llm_response(text: str) -> list[dict]:
    arr = _parse_json_array_from_llm(text)
    out: list[dict] = []
    for i, it in enumerate(arr, start=1):
        out.append(_coerce_imported_rule_dict(it, i))
    return out


def _incident_block(inc: Incident) -> str:
    sev = severity_from_tags(inc.tags, inc.log_line)
    btype = bug_type_cn(inc.tags)
    title = short_title(inc.log_line)
    ana = inc.analysis.strip() if inc.analysis else ""
    lines = [
        f"- [{inc.seq}] ts={inc.ts} file={inc.source_file}",
        f"  type={btype} sev_hint={sev} title_hint={title}",
        f"  log: {inc.log_line}",
    ]
    if ana:
        lines.append(f"  analysis: {ana}")
    return "\n".join(lines)


def build_material_for_prompt(
    incidents: list[Incident],
    max_chars: int,
) -> tuple[str, bool]:
    header = "## Parsed incidents (structured)\n\n"
    total = header
    truncated = False
    for inc in incidents:
        block = _incident_block(inc) + "\n\n"
        if len(total) + len(block) > max_chars:
            truncated = True
            break
        total += block
    return total.strip(), truncated


def build_summarize_prompt_serial(
    material: str,
    log_files: list[str],
    truncated: bool,
    structured: bool,
) -> str:
    note_trunc = ""
    if truncated:
        note_trunc = (
            "\n"
            "\u6ce8\u610f\uff1a\u6750\u6599\u5df2\u622a\u65ad\uff0c\u8bf7\u5728\u6587\u9996\u8bf4\u660e\u300c\u6750\u6599\u5df2\u622a\u65ad\u300d\u5e76\u57fa\u4e8e\u5df2\u7ed9\u5185\u5bb9\u603b\u7ed3\u3002\n"
        )
    mat_desc = (
        "\u7ed3\u6784\u5316\u544a\u8b66/\u5206\u6790\u6761\u76ee"
        if structured
        else (
            "\u539f\u6587\u8282\u9009"
            "\uff08\u672a\u80fd\u89e3\u6790\u884c\u53f7\u683c\u5f0f\uff09"
        )
    )
    return _T(
        "\u4f60\u662f\u5d4c\u5165\u5f0f/\u8bbe\u5907\u65e5\u5fd7\u5206\u6790\u4e13\u5bb6\u3002"
        "\u4ee5\u4e0b\u4e3a\u4ece\u4e32\u53e3\u539f\u59cb\u65e5\u5fd7\u6587\u4ef6\u4e2d\u63d0\u53d6\u7684",
        mat_desc,
        "\u3002\n\n",
        "\u6d89\u53ca\u7684\u6587\u4ef6\uff1a\n",
        "\n".join(f"- {x}" for x in log_files),
        note_trunc,
        "\n\n",
        "\u8bf7\u4ec5\u7528\u7b80\u4f53\u4e2d\u6587\u8f93\u51fa\u7eaf\u6587\u672c\u3002\u6309\u4e0b\u5217\u7ed3\u6784\u64b0\u5199\u4fbf\u4e8e\u62f7\u8d1d\u5230 Bug \u5355/\u90ae\u4ef6\uff1a\n",
        "\n1) \u6982\u8981\u4e00\u6bb5\n",
        "2) \u6309\u4e25\u91cd\u7a0b\u5ea6\u5f52\u7eb3\uff08\u5408\u5e76\u540c\u7c7b\uff09\n",
        "3) Bug \u6e05\u5355\u6bcf\u6761\u5fc5\u542b\u5b57\u6bb5\uff1a",
        "\u3010Bug\u7f16\u53f7\u3011 ",
        "\u3010\u6807\u9898\u3011 ",
        "\u3010\u4e25\u91cd\u7ea7\u522b\u3011 ",
        "\u3010\u7c7b\u578b\u3011 ",
        "\u3010\u65f6\u95f4\u3011 ",
        "\u3010\u8bc1\u636e/\u539f\u6587\u3011 ",
        "\u3010\u5206\u6790\u7ed3\u8bba\u3011\n",
        "4) \u540e\u7eed\u6392\u67e5\u987a\u5e8f\uff08\u5e8f\u53f7\u5217\u8868\uff09\n\n",
        "--- material ---\n",
        material,
    )


_USER_RULES_PATH = _ROOT / "serial_rules_user.json"

APP_VERSION = "V 0.2"
APP_AUTHOR = "zhoujun@glazero.com"
DISCLAIMER_TEXT = (
    "本次分析结果只对本次导入的串口 log 有效；\n"
    "具体结果需由测试人员复现、验证后再作结论。"
)


def apply_cursor_env_to_dotenv(updates: dict[str, str]) -> None:
    """将 Cursor 相关变量写入项目根目录 .env（同名键覆盖；值为空则删除该键）。"""
    env_path = _ROOT / ".env"
    keys = set(updates.keys())
    kept: list[str] = []
    if env_path.exists():
        for raw in env_path.read_text(encoding="utf-8").splitlines():
            s = raw.strip()
            if not s or s.startswith("#"):
                kept.append(raw)
                continue
            if "=" in s:
                k = s.split("=", 1)[0].strip()
                if k in keys:
                    continue
            kept.append(raw)
    for k, v in updates.items():
        v = (v or "").strip()
        if v:
            kept.append(f"{k}={v}")
    env_path.parent.mkdir(parents=True, exist_ok=True)
    env_path.write_text("\n".join(kept).rstrip() + "\n", encoding="utf-8")
    for k, v in updates.items():
        vs = (v or "").strip()
        if vs:
            os.environ[k] = vs
        else:
            os.environ.pop(k, None)
    try:
        load_dotenv(env_path, override=True)
    except TypeError:
        load_dotenv(env_path)
    try:
        load_dotenv(Path.cwd() / ".env", override=True)
    except TypeError:
        load_dotenv(Path.cwd() / ".env")


def _default_cleaning_prompt() -> str:
    return (
        "你是嵌入式串口日志清洗助手。下面是一段原始日志节选（可能含噪声、重复前缀、ANSI 颜色码已尽量去除）。\n"
        "请用简体中文输出：\n"
        "1) 你认为的噪声类型简述；\n"
        "2) 对节选做「规范化重排」（合并明显重复心跳、保留关键时间顺序），输出重排后的正文，不要编造不存在的日志。\n"
        "仅基于给定节选作答。\n\n"
        "--- excerpt ---\n"
    )


@dataclass
class WorkerConfig:
    file_path: Path
    max_chars: int
    user_clean_prompt: str
    user_analysis_notes: str


def _run_analyze(cfg: WorkerConfig, q: queue.Queue) -> None:
    from serial_alert_rules import build_compiled_rules, match_log_alerts_for_rules

    def _raw_material(cleaned: str, budget: int, name: str) -> tuple[str, bool]:
        truncated = False
        head = "## raw excerpt: " + name + "\n\n" + cleaned.strip()
        if len(head) > budget:
            material = head[:budget].strip()
            truncated = True
        else:
            material = head.strip()
        if not material:
            raise RuntimeError("无有效文本")
        return material, truncated

    try:
        q.put(("progress", 5, "读取文件…"))
        raw = _read_file_text(cfg.file_path)
        if not raw.strip():
            q.put(("err", "文件为空或无法解码。"))
            return

        q.put(("progress", 15, "规范化换行（不做本地清洗）…"))
        cleaned = raw.replace("\r\n", "\n").replace("\r", "\n")

        rules = build_compiled_rules(
            env_json_path=None,
            user_json_path=_USER_RULES_PATH,
        )

        q.put(("progress", 28, "规则扫描…"))
        buf: list[str] = []
        hit_lines = 0
        for i, line in enumerate(cleaned.splitlines(), 1):
            hits = match_log_alerts_for_rules(line, rules)
            if not hits:
                continue
            hit_lines += 1
            if len(buf) < 120:
                labs = "、".join(h["label"] for h in hits)
                buf.append(f"行 {i}: [{labs}] {line[:400]}{'…' if len(line) > 400 else ''}")
        if not buf:
            rule_block = "（本文件未命中内置/自定义规则关键字模式）"
        else:
            rule_block = "\n".join(buf)

        q.put(("progress", 40, "解析异常行（关键词/栈）…"))
        incidents: list[Incident] = parse_report_text(cleaned, cfg.file_path.name)

        q.put(("progress", 48, "调用 Cloud 清洗节选…"))
        try:
            clean_limit = int(os.environ.get("CURSOR_CLEAN_MAX_CHARS", "24000"))
        except ValueError:
            clean_limit = 24000
        clean_limit = max(1000, min(clean_limit, 80_000))
        excerpt = cleaned[:clean_limit]
        cp = (cfg.user_clean_prompt or _default_cleaning_prompt()).strip()
        try:
            llm_clean_summary = _cursor_submit(cp + excerpt).strip()
        except Exception as e:
            llm_clean_summary = f"（Cloud 清洗失败：{e}）"

        q.put(("progress", 62, "组装分析材料…"))
        budget = max(4000, min(cfg.max_chars, 240_000))
        if incidents:
            material, truncated = build_material_for_prompt(incidents, budget)
        else:
            material, truncated = _raw_material(cleaned, budget, cfg.file_path.name)

        prefix_parts: list[str] = []

        # 持续学习：注入历史人工判别作为上下文
        try:
            from db_manager import get_learning_context
            learning_ctx = get_learning_context()
            if learning_ctx:
                prefix_parts.append(learning_ctx)
                q.put(("progress", 63, "已加载历史判别经验…"))
        except Exception:
            pass

        if cfg.user_analysis_notes.strip():
            prefix_parts.append(
                "## 用户侧重点（清洗/分析）\n\n" + cfg.user_analysis_notes.strip()
            )
        prefix_parts.append(
            f"## 规则命中摘要（共约 {hit_lines} 行触发规则）\n\n" + rule_block
        )
        prefix_parts.append("## Cloud 清洗输出\n\n" + (llm_clean_summary or "（Cloud 未返回内容）"))
        material = "\n\n".join(prefix_parts) + "\n\n---\n\n" + material

        structured = bool(incidents)
        prompt = build_summarize_prompt_serial(
            material,
            [cfg.file_path.name],
            truncated,
            structured,
        )

        q.put(("progress", 72, "调用 Cursor Cloud 生成总结（可能较久）…"))
        summary = _cursor_submit(prompt)
        if not summary or not summary.strip():
            q.put(("err", "Cursor 返回空内容。"))
            return

        q.put(("progress", 95, "保存 Bug 到数据库…"))
        db_count = 0
        try:
            from db_manager import save_bugs_from_summary
            db_count = save_bugs_from_summary(summary, cfg.file_path.name)
        except Exception as db_err:
            q.put(("progress", 95, f"数据库写入跳过（{db_err}）"))

        q.put(("progress", 100, "完成"))
        meta = (
            f"=== meta ===\n"
            f"generated: {datetime.now().isoformat(timespec='seconds')}\n"
            f"source: {cfg.file_path}\n"
            f"parsed_incidents: {len(incidents)}\n"
            f"structured_mode: {structured}\n"
            f"material_truncated: {truncated}\n"
            f"rule_hit_lines: {hit_lines}\n"
            f"bugs_saved_to_db: {db_count}\n\n"
            f"=== Cursor summary ===\n\n"
        )
        q.put(("ok", meta + summary.strip()))
    except Exception as e:
        q.put(("err", f"{e}\n\n{traceback.format_exc()}"))


def _tk_font_ui() -> tuple[str, int]:
    return ("Microsoft YaHei UI", 9)


def _tk_font_ui_small() -> tuple[str, int]:
    return ("Microsoft YaHei UI", 8)


def _tk_font_mono() -> tuple[str, int]:
    """等宽 + 中文回退。"""
    return ("Microsoft YaHei UI", 9)


def _tk_font_result() -> tuple[str, int]:
    """结果区略小字号，小窗口内多显示几行。"""
    return ("Microsoft YaHei UI", 8)


def _pick_mono_family(root: tk.Tk) -> str:
    try:
        fams = set(str(x) for x in root.tk.call("font", "families"))
    except tk.TclError:
        return "Microsoft YaHei UI"
    for name in ("Cascadia Mono", "Consolas", "Lucida Console"):
        if name in fams:
            return name
    return "Microsoft YaHei UI"


def _apply_tk_styles(root: tk.Tk) -> ttk.Style:
    style = ttk.Style()
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    mono_fam = _pick_mono_family(root)
    bg = "#e4e9f2"
    card = "#ffffff"
    fg = "#1e293b"
    muted = "#64748b"
    accent = "#3b82f6"
    accent_dark = "#2563eb"
    border = "#c7d2e0"
    toolbar = "#dce3ee"
    root.configure(background=bg)
    ui = _tk_font_ui()
    ui_sm = _tk_font_ui_small()
    style.configure(".", background=bg, foreground=fg, font=ui)
    style.configure("TFrame", background=bg)
    style.configure("Card.TFrame", background=card, relief="flat")
    style.configure("Shell.TFrame", background=bg)
    style.configure("ToolStrip.TFrame", background=toolbar, relief="flat")
    style.configure("TLabelframe", background=bg, foreground=fg, borderwidth=1, relief="solid")
    style.configure("TLabelframe.Label", background=bg, foreground=accent, font=(ui[0], ui[1], "bold"))
    style.configure("Subtle.TLabel", background=toolbar, foreground=muted, font=ui_sm)
    style.configure("SubtleOnBg.TLabel", background=bg, foreground=muted, font=ui_sm)
    style.configure("PathCard.TLabelframe", background=card)
    style.configure("PathCard.TLabelframe.Label", background=card, foreground=muted, font=(ui[0], 8, "bold"))
    style.configure("Path.TLabel", background=card, foreground=fg, font=ui_sm)
    style.configure("TCheckbutton", background=bg, foreground=fg)
    style.configure("TButton", font=ui, padding=(6, 4))
    style.configure("Secondary.TButton", font=ui, padding=(6, 4))
    style.map("Secondary.TButton", background=[("active", "#cbd5e1")])
    style.configure("Secondary.TButton", background="#f1f5f9", foreground=fg, borderwidth=1)
    style.configure("Accent.TButton", font=(ui[0], ui[1], "bold"), padding=(8, 5))
    style.map(
        "Accent.TButton",
        background=[("active", accent_dark), ("pressed", "#1d4ed8")],
        foreground=[("disabled", "#94a3b8")],
    )
    style.configure("Accent.TButton", background=accent, foreground="white", borderwidth=0)
    style.configure(
        "Treeview",
        font=(mono_fam, 9),
        rowheight=20,
        fieldbackground=card,
        background=card,
        foreground=fg,
        bordercolor=border,
    )
    style.configure("Treeview.Heading", font=(ui[0], 8, "bold"), background="#eef2f7", foreground="#475569")
    style.map("Treeview", background=[("selected", "#dbeafe")], foreground=[("selected", fg)])
    style.configure("TProgressbar", thickness=6, troughcolor="#cbd5e1", background=accent, borderwidth=0)
    style.configure("TSeparator", background=border)
    return style


class MainApp:
    def __init__(self) -> None:
        self.root = tk.Tk()
        self.root.title("串口日志分析")
        _apply_tk_styles(self.root)
        sw, sh = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        max_w = min(720, sw - 32)
        max_h = sh - 32
        self.root.maxsize(max_w, max_h)
        ww = min(640, max(480, sw - 56), max_w)
        wh = min(500, max(360, sh - 80), max_h)
        self.root.geometry(f"{ww}x{wh}")
        self.root.minsize(min(400, ww), min(300, min(wh, max_h)))

        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="文件", menu=file_menu)
        file_menu.add_command(label="打开…", command=self._pick_file)
        settings_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="设置", menu=settings_menu)
        settings_menu.add_command(label="Cursor API 与仓库…", command=self._open_cursor_config)
        settings_menu.add_command(label="清洗与分析材料…", command=self._open_clean_config)
        rules_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="规则", menu=rules_menu)
        rules_menu.add_command(label="串口匹配规则…", command=self._open_rules_config)
        rules_menu.add_command(label="从 Excel/CSV 导入规则…", command=self._import_rules_from_xlsx)
        db_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="数据库", menu=db_menu)
        db_menu.add_command(label="Bug 记录…", command=self._open_bug_records)
        db_menu.add_command(label="测试连接…", command=self._test_db_connection)
        menubar.add_command(label="免责声明", command=self._show_disclaimer)
        menubar.add_command(label="关于", command=self._show_about)

        self._current_file: Path | None = None
        self._last_result = ""
        self._msg_q: queue.Queue = queue.Queue()
        self._worker_thread: threading.Thread | None = None
        self._import_thread: threading.Thread | None = None
        self._analysis_notes: str = ""
        self._bug_win: tk.Toplevel | None = None
        self._bug_tree: ttk.Treeview | None = None
        self._clean_prompt_body: str = _default_cleaning_prompt()
        self._clean_win: tk.Toplevel | None = None
        self._rules_win: tk.Toplevel | None = None
        self._tree: ttk.Treeview | None = None

        shell = ttk.Frame(self.root, padding=(6, 5), style="Shell.TFrame")
        shell.pack(fill=tk.BOTH, expand=True)

        path_lf = ttk.LabelFrame(shell, text="当前文件", padding=(5, 4), style="PathCard.TLabelframe")
        path_lf.pack(fill=tk.X, pady=(0, 5))
        self._path_var = tk.StringVar(
            value="未选择文件（文件 → 打开…；规则见「规则」菜单，清洗见「设置」）"
        )
        wrap = min(ww - 20, max(260, sw - 100))
        ttk.Label(path_lf, textvariable=self._path_var, wraplength=wrap, style="Path.TLabel").pack(
            anchor=tk.W, fill=tk.X
        )

        out_lf = ttk.LabelFrame(shell, text="分析结果", padding=(5, 5))
        out_lf.pack(fill=tk.BOTH, expand=True)
        out_lf.columnconfigure(0, weight=1)
        out_lf.rowconfigure(0, weight=1)

        self._result = scrolledtext.ScrolledText(
            out_lf,
            height=1,
            wrap=tk.WORD,
            state=tk.DISABLED,
            font=_tk_font_result(),
            relief=tk.FLAT,
            borderwidth=1,
            highlightthickness=1,
            highlightbackground="#c7d2e0",
            highlightcolor="#3b82f6",
            padx=5,
            pady=5,
            bg="#fafbfc",
            fg="#0f172a",
            insertbackground="#0f172a",
            selectbackground="#bfdbfe",
        )
        self._result.grid(row=0, column=0, sticky=tk.NSEW, pady=(0, 5))

        bot = ttk.Frame(out_lf)
        bot.grid(row=1, column=0, sticky=tk.EW)
        bot.columnconfigure(0, weight=1)

        row_btn = ttk.Frame(bot, style="ToolStrip.TFrame", padding=(0, 4, 0, 2))
        row_btn.grid(row=0, column=0, sticky=tk.EW)
        row_btn.columnconfigure(0, weight=1)
        btn_wrap = ttk.Frame(row_btn, style="ToolStrip.TFrame")
        btn_wrap.grid(row=0, column=0, sticky=tk.W)
        ttk.Button(btn_wrap, text="开始分析", command=self._run, style="Accent.TButton").pack(
            side=tk.LEFT, padx=(0, 6)
        )
        ttk.Button(btn_wrap, text="保存 TXT…", command=self._save_result, style="Secondary.TButton").pack(
            side=tk.LEFT, padx=(0, 4)
        )

        ttk.Separator(bot, orient=tk.HORIZONTAL).grid(row=1, column=0, sticky=tk.EW, pady=(2, 4))

        row_prog = ttk.Frame(bot, style="ToolStrip.TFrame", padding=(0, 0, 0, 4))
        row_prog.grid(row=2, column=0, sticky=tk.EW)
        row_prog.columnconfigure(0, weight=1)
        self._progress = ttk.Progressbar(row_prog, maximum=100, mode="determinate")
        self._progress.grid(row=0, column=0, sticky=tk.EW)

        self._status = tk.StringVar(value="就绪")
        row_stat = ttk.Frame(bot)
        row_stat.grid(row=3, column=0, sticky=tk.EW, pady=(0, 2))
        ttk.Label(row_stat, textvariable=self._status, style="SubtleOnBg.TLabel").pack(anchor=tk.W)

    def _set_result_text(self, s: str) -> None:
        self._result.configure(state=tk.NORMAL)
        self._result.delete("1.0", tk.END)
        self._result.insert(tk.END, s)
        self._result.configure(state=tk.DISABLED)

    def _show_disclaimer(self) -> None:
        messagebox.showinfo("免责声明", DISCLAIMER_TEXT, parent=self.root)

    def _show_about(self) -> None:
        messagebox.showinfo(
            "关于",
            f"作者：{APP_AUTHOR}\n版本：{APP_VERSION}",
            parent=self.root,
        )

    def _open_cursor_config(self) -> None:
        dlg = tk.Toplevel(self.root)
        dlg.title("Cursor API 与仓库")
        dlg.transient(self.root)
        dlg.grab_set()

        keys = (
            ("CURSOR_API_KEY", "API Key（Dashboard → Integrations）", True),
            ("CURSOR_GITHUB_REPO", "GitHub 仓库 URL（可克隆）", False),
            ("CURSOR_GITHUB_REF", "分支 / ref（默认 main）", False),
            ("CURSOR_MODEL", "模型 ID（可选，留空则用账号默认）", False),
        )
        vars_: dict[str, tk.StringVar] = {}
        frm = ttk.Frame(dlg, padding=10)
        frm.pack(fill=tk.BOTH, expand=True)
        for i, (key, label, secret) in enumerate(keys):
            ttk.Label(frm, text=label).grid(row=i, column=0, sticky=tk.NW, pady=4)
            v = tk.StringVar(value=os.environ.get(key, ""))
            vars_[key] = v
            if secret:
                ent = tk.Entry(frm, textvariable=v, width=56, show="*")
            else:
                ent = ttk.Entry(frm, textvariable=v, width=56)
            ent.grid(row=i, column=1, sticky=tk.EW, pady=4)
        frm.columnconfigure(1, weight=1)

        hint = ttk.Label(
            frm,
            text="保存后写入项目目录下的 .env；当前已运行的分析任务需下次「开始分析」后生效。",
            wraplength=520,
        )
        hint.grid(row=len(keys), column=0, columnspan=2, sticky=tk.W, pady=(8, 0))

        def save() -> None:
            apply_cursor_env_to_dotenv({k: vars_[k].get() for k in vars_})
            messagebox.showinfo("配置", "已保存到 .env。", parent=dlg)
            dlg.destroy()

        bf = ttk.Frame(frm)
        bf.grid(row=len(keys) + 1, column=0, columnspan=2, pady=12)
        ttk.Button(bf, text="保存", command=save).pack(side=tk.LEFT, padx=4)
        ttk.Button(bf, text="取消", command=dlg.destroy).pack(side=tk.LEFT, padx=4)

    def _build_clean_settings_window(self) -> None:
        win = tk.Toplevel(self.root)
        win.title("清洗与分析材料")
        win.transient(self.root)
        win.minsize(480, 400)
        win.geometry("600x480")
        body = ttk.Frame(win, padding=10)
        body.pack(fill=tk.BOTH, expand=True)
        body.columnconfigure(0, weight=1)
        body.rowconfigure(1, weight=1)
        body.rowconfigure(3, weight=2)

        ttk.Label(body, text="分析侧重点（可选）", font=(_tk_font_ui()[0], _tk_font_ui()[1], "bold")).grid(
            row=0, column=0, sticky=tk.W
        )
        self._dlg_notes = scrolledtext.ScrolledText(
            body,
            height=4,
            wrap=tk.WORD,
            font=_tk_font_ui(),
            relief=tk.FLAT,
            borderwidth=1,
            highlightthickness=1,
            highlightbackground="#cbd5e1",
            highlightcolor="#2563eb",
            padx=6,
            pady=4,
            bg="#f8fafc",
            fg="#1e293b",
            insertbackground="#1e293b",
        )
        self._dlg_notes.grid(row=1, column=0, sticky=tk.NSEW, pady=(4, 8))

        ttk.Label(body, text="Cloud 清洗 prompt 前缀", font=(_tk_font_ui()[0], _tk_font_ui()[1], "bold")).grid(
            row=2, column=0, sticky=tk.W
        )
        self._dlg_clean_prompt = scrolledtext.ScrolledText(
            body,
            height=8,
            wrap=tk.WORD,
            font=_tk_font_mono(),
            relief=tk.FLAT,
            borderwidth=1,
            highlightthickness=1,
            highlightbackground="#cbd5e1",
            highlightcolor="#2563eb",
            padx=6,
            pady=4,
            bg="#f8fafc",
            fg="#1e293b",
            insertbackground="#1e293b",
        )
        self._dlg_clean_prompt.grid(row=3, column=0, sticky=tk.NSEW, pady=(4, 8))

        env_fr = ttk.LabelFrame(body, text="材料与节选体量（写入项目 .env）", padding=(6, 6))
        env_fr.grid(row=4, column=0, sticky=tk.EW, pady=(0, 8))
        env_fr.columnconfigure(1, weight=1)
        self._env_summary_chars = tk.StringVar(value=os.environ.get("CURSOR_SUMMARY_MAX_CHARS", "90000"))
        self._env_clean_chars = tk.StringVar(value=os.environ.get("CURSOR_CLEAN_MAX_CHARS", "24000"))
        ttk.Label(env_fr, text="CURSOR_SUMMARY_MAX_CHARS").grid(row=0, column=0, sticky=tk.W, pady=2)
        ttk.Entry(env_fr, textvariable=self._env_summary_chars, width=16).grid(
            row=0, column=1, sticky=tk.W, pady=2, padx=(8, 0)
        )
        ttk.Label(env_fr, text="CURSOR_CLEAN_MAX_CHARS").grid(row=1, column=0, sticky=tk.W, pady=2)
        ttk.Entry(env_fr, textvariable=self._env_clean_chars, width=16).grid(
            row=1, column=1, sticky=tk.W, pady=2, padx=(8, 0)
        )
        ttk.Label(
            env_fr,
            text="留空则删除 .env 中该键，下次运行使用内置默认。",
            style="SubtleOnBg.TLabel",
            wraplength=520,
        ).grid(row=2, column=0, columnspan=2, sticky=tk.W, pady=(6, 0))

        def save_clean() -> None:
            s_raw = self._env_summary_chars.get().strip()
            c_raw = self._env_clean_chars.get().strip()
            if s_raw:
                try:
                    v = int(s_raw)
                    if v < 4000 or v > 240_000:
                        messagebox.showwarning(
                            "校验",
                            "CURSOR_SUMMARY_MAX_CHARS 建议在 4000～240000。",
                            parent=win,
                        )
                        return
                except ValueError:
                    messagebox.showwarning("校验", "CURSOR_SUMMARY_MAX_CHARS 须为整数或留空。", parent=win)
                    return
            if c_raw:
                try:
                    cv = int(c_raw)
                    if cv < 1000 or cv > 80_000:
                        messagebox.showwarning(
                            "校验",
                            "CURSOR_CLEAN_MAX_CHARS 建议在 1000～80000。",
                            parent=win,
                        )
                        return
                except ValueError:
                    messagebox.showwarning("校验", "CURSOR_CLEAN_MAX_CHARS 须为整数或留空。", parent=win)
                    return
            self._analysis_notes = self._dlg_notes.get("1.0", tk.END).rstrip("\n")
            self._clean_prompt_body = self._dlg_clean_prompt.get("1.0", tk.END).rstrip("\n")
            apply_cursor_env_to_dotenv(
                {
                    "CURSOR_SUMMARY_MAX_CHARS": s_raw,
                    "CURSOR_CLEAN_MAX_CHARS": c_raw,
                }
            )
            messagebox.showinfo("清洗与分析材料", "已保存文本与 .env 项。", parent=win)

        def close_clean() -> None:
            win.withdraw()

        bf = ttk.Frame(body)
        bf.grid(row=5, column=0, sticky=tk.W, pady=(4, 0))
        ttk.Button(bf, text="保存", command=save_clean).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(bf, text="关闭", command=close_clean).pack(side=tk.LEFT, padx=6)

        win.protocol("WM_DELETE_WINDOW", close_clean)
        self._clean_win = win
        win.withdraw()

    def _open_clean_config(self) -> None:
        if self._clean_win is None or not self._clean_win.winfo_exists():
            self._build_clean_settings_window()
        assert self._clean_win is not None
        w = self._clean_win
        self._dlg_notes.delete("1.0", tk.END)
        self._dlg_notes.insert(tk.END, self._analysis_notes)
        self._dlg_clean_prompt.delete("1.0", tk.END)
        self._dlg_clean_prompt.insert(tk.END, self._clean_prompt_body)
        self._env_summary_chars.set(os.environ.get("CURSOR_SUMMARY_MAX_CHARS", "90000"))
        self._env_clean_chars.set(os.environ.get("CURSOR_CLEAN_MAX_CHARS", "24000"))
        w.deiconify()
        w.lift()

    def _build_rules_window(self) -> None:
        win = tk.Toplevel(self.root)
        win.title("串口匹配规则")
        win.transient(self.root)
        win.minsize(560, 320)
        win.geometry("700x380")
        outer = ttk.Frame(win, padding=8)
        outer.pack(fill=tk.BOTH, expand=True)

        rh = ttk.Frame(outer)
        rh.pack(fill=tk.X, pady=(0, 6))
        ttk.Button(rh, text="添加自定义规则", command=self._add_rule, style="Secondary.TButton").pack(
            side=tk.LEFT, padx=(0, 6)
        )
        ttk.Button(rh, text="删除选中自定义规则", command=self._del_rule, style="Secondary.TButton").pack(
            side=tk.LEFT, padx=6
        )
        ttk.Button(rh, text="刷新列表", command=self._refresh_rules_table, style="Secondary.TButton").pack(
            side=tk.LEFT, padx=6
        )

        rules_lab = ttk.LabelFrame(outer, text="规则（内置 + serial_rules_user.json）", padding=(6, 4))
        rules_lab.pack(fill=tk.BOTH, expand=True)

        cols = ("src", "pri", "cat", "lbl", "pat")
        self._tree = ttk.Treeview(
            rules_lab, columns=cols, show="headings", height=12, selectmode="browse"
        )
        self._tree.heading("src", text="来源")
        self._tree.heading("pri", text="优先级")
        self._tree.heading("cat", text="category")
        self._tree.heading("lbl", text="显示名")
        self._tree.heading("pat", text="pattern")
        self._tree.column("src", width=56, stretch=False)
        self._tree.column("pri", width=52, stretch=False)
        self._tree.column("cat", width=100)
        self._tree.column("lbl", width=140)
        self._tree.column("pat", width=400)
        sy = ttk.Scrollbar(rules_lab, orient=tk.VERTICAL, command=self._tree.yview)
        self._tree.configure(yscrollcommand=sy.set)
        self._tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sy.pack(side=tk.RIGHT, fill=tk.Y)

        def close_rules() -> None:
            win.withdraw()

        win.protocol("WM_DELETE_WINDOW", close_rules)
        bf = ttk.Frame(outer)
        bf.pack(fill=tk.X, pady=(8, 0))
        ttk.Button(bf, text="确定", command=close_rules).pack(side=tk.RIGHT)

        self._rules_win = win
        win.withdraw()

    def _open_rules_config(self) -> None:
        if self._rules_win is None or not self._rules_win.winfo_exists():
            self._build_rules_window()
        self._refresh_rules_table()
        assert self._rules_win is not None
        self._rules_win.deiconify()
        self._rules_win.lift()

    def _pick_file(self) -> None:
        path = filedialog.askopenfilename(
            parent=self.root,
            title="选择串口日志",
            initialdir=str(_ROOT),
            filetypes=[
                ("日志", "*.log"),
                ("文本", "*.txt"),
                ("所有文件", "*.*"),
            ],
        )
        if path:
            self._current_file = Path(path)
            self._path_var.set(str(self._current_file))

    def _refresh_rules_table(self) -> None:
        if self._tree is None:
            return
        for iid in self._tree.get_children():
            self._tree.delete(iid)
        r = 0
        for pri, cat, lbl, pat in RAW_ALERT_RULE_DEFINITIONS:
            self._tree.insert("", tk.END, iid=f"b{r}", values=("内置", str(pri), cat, lbl, pat))
            r += 1
        user_items = load_user_rules_raw(_USER_RULES_PATH)
        for i, it in enumerate(user_items):
            self._tree.insert(
                "",
                tk.END,
                iid=f"u{i}",
                values=(
                    "自定义",
                    str(it["priority"]),
                    it["category"],
                    it["label"],
                    it["pattern"],
                ),
            )

    def _add_rule(self) -> None:
        parent_win = self._rules_win if self._rules_win and self._rules_win.winfo_exists() else self.root
        dlg = tk.Toplevel(parent_win)
        dlg.title("添加自定义规则")
        dlg.transient(parent_win)
        dlg.grab_set()

        pri_v = tk.StringVar(value="5")
        cat_v = tk.StringVar()
        lbl_v = tk.StringVar()
        pat_v = tk.StringVar()

        frm = ttk.Frame(dlg, padding=10)
        frm.pack(fill=tk.BOTH, expand=True)
        ttk.Label(frm, text="优先级（数字越小越优先）").grid(row=0, column=0, sticky=tk.W, pady=2)
        ttk.Entry(frm, textvariable=pri_v, width=8).grid(row=0, column=1, sticky=tk.W)
        ttk.Label(frm, text="category（唯一键）").grid(row=1, column=0, sticky=tk.W, pady=2)
        ttk.Entry(frm, textvariable=cat_v, width=32).grid(row=1, column=1, sticky=tk.W)
        ttk.Label(frm, text="显示名").grid(row=2, column=0, sticky=tk.W, pady=2)
        ttk.Entry(frm, textvariable=lbl_v, width=32).grid(row=2, column=1, sticky=tk.W)
        ttk.Label(frm, text="pattern（正则）").grid(row=3, column=0, sticky=tk.NW, pady=2)
        ttk.Entry(frm, textvariable=pat_v, width=48).grid(row=3, column=1, sticky=tk.W)

        def ok() -> None:
            try:
                p = int(pri_v.get().strip() or "5")
            except ValueError:
                messagebox.showwarning("校验", "优先级必须是整数。", parent=dlg)
                return
            cat = cat_v.get().strip()
            pat = pat_v.get().strip()
            lbl = lbl_v.get().strip() or cat
            if not cat or not pat:
                messagebox.showwarning("校验", "请填写 category 与 pattern。", parent=dlg)
                return
            try:
                re.compile(pat, re.I)
            except re.error as e:
                messagebox.showwarning("校验", f"正则无效：{e}", parent=dlg)
                return
            items = load_user_rules_raw(_USER_RULES_PATH)
            items.append(
                {"priority": p, "category": cat, "label": lbl, "pattern": pat}
            )
            save_user_rules_raw(_USER_RULES_PATH, items)
            dlg.destroy()
            self._refresh_rules_table()

        bf = ttk.Frame(frm)
        bf.grid(row=4, column=0, columnspan=2, pady=10)
        ttk.Button(bf, text="确定", command=ok).pack(side=tk.LEFT, padx=4)
        ttk.Button(bf, text="取消", command=dlg.destroy).pack(side=tk.LEFT, padx=4)

    def _del_rule(self) -> None:
        if self._tree is None:
            return
        parent_win = self._rules_win if self._rules_win and self._rules_win.winfo_exists() else self.root
        sel = self._tree.selection()
        if not sel:
            return
        iid = sel[0]
        if not iid.startswith("u"):
            messagebox.showinfo("提示", "只能删除「自定义」规则。", parent=parent_win)
            return
        try:
            user_idx = int(iid[1:])
        except ValueError:
            return
        items = load_user_rules_raw(_USER_RULES_PATH)
        if 0 <= user_idx < len(items):
            items.pop(user_idx)
            save_user_rules_raw(_USER_RULES_PATH, items)
            self._refresh_rules_table()

    # ── 数据库 Bug 记录 ─────────────────────────────────────────

    def _test_db_connection(self) -> None:
        try:
            from db_manager import test_connection
            ok, msg = test_connection()
            if ok:
                messagebox.showinfo("数据库", msg, parent=self.root)
            else:
                messagebox.showerror("数据库连接失败", msg, parent=self.root)
        except Exception as e:
            messagebox.showerror("数据库", f"无法导入 db_manager：{e}", parent=self.root)

    def _open_bug_records(self) -> None:
        try:
            from db_manager import init_db
            init_db()
        except Exception as e:
            messagebox.showerror("数据库", f"连接失败：{e}", parent=self.root)
            return
        if self._bug_win is not None and self._bug_win.winfo_exists():
            self._bug_win.deiconify()
            self._bug_win.lift()
            self._refresh_bug_table()
            return
        self._build_bug_window()
        self._refresh_bug_table()

    def _build_bug_window(self) -> None:
        win = tk.Toplevel(self.root)
        win.title("Bug 记录（PostgreSQL）")
        win.transient(self.root)
        win.minsize(820, 420)
        win.geometry("960x520")
        outer = ttk.Frame(win, padding=8)
        outer.pack(fill=tk.BOTH, expand=True)

        top = ttk.Frame(outer)
        top.pack(fill=tk.X, pady=(0, 6))
        ttk.Label(top, text="筛选判别：").pack(side=tk.LEFT)
        self._bug_filter_var = tk.StringVar(value="全部")
        cb = ttk.Combobox(
            top, textvariable=self._bug_filter_var, width=10, state="readonly",
            values=["全部", "待定", "确认", "误报", "忽略"],
        )
        cb.pack(side=tk.LEFT, padx=(0, 8))
        cb.bind("<<ComboboxSelected>>", lambda _: self._refresh_bug_table())
        ttk.Button(top, text="刷新", command=self._refresh_bug_table, style="Secondary.TButton").pack(
            side=tk.LEFT, padx=4,
        )
        self._bug_count_var = tk.StringVar()
        ttk.Label(top, textvariable=self._bug_count_var, style="SubtleOnBg.TLabel").pack(side=tk.RIGHT)

        cols = ("id", "bug_no", "title", "severity", "source", "verdict")
        tree = ttk.Treeview(outer, columns=cols, show="headings", height=14, selectmode="browse")
        tree.heading("id", text="ID")
        tree.heading("bug_no", text="Bug编号")
        tree.heading("title", text="标题")
        tree.heading("severity", text="严重级别")
        tree.heading("source", text="来源文件")
        tree.heading("verdict", text="人工判别")
        tree.column("id", width=44, stretch=False)
        tree.column("bug_no", width=76, stretch=False)
        tree.column("title", width=260)
        tree.column("severity", width=64, stretch=False)
        tree.column("source", width=200)
        tree.column("verdict", width=72, stretch=False)
        sy = ttk.Scrollbar(outer, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=sy.set)
        tree.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        sy.pack(side=tk.RIGHT, fill=tk.Y)
        self._bug_tree = tree

        detail = ttk.LabelFrame(outer, text="审核", padding=(8, 6))
        detail.pack(fill=tk.X, pady=(8, 0))

        row1 = ttk.Frame(detail)
        row1.pack(fill=tk.X, pady=(0, 4))
        ttk.Label(row1, text="判别：").pack(side=tk.LEFT)
        self._verdict_var = tk.StringVar(value="待定")
        ttk.Combobox(
            row1, textvariable=self._verdict_var, width=10, state="readonly",
            values=["待定", "确认", "误报", "忽略"],
        ).pack(side=tk.LEFT, padx=(0, 12))
        ttk.Label(row1, text="备注：").pack(side=tk.LEFT)
        self._verdict_notes_var = tk.StringVar()
        ttk.Entry(row1, textvariable=self._verdict_notes_var, width=40).pack(side=tk.LEFT, padx=(0, 12))
        ttk.Button(row1, text="保存判别", command=self._save_verdict, style="Accent.TButton").pack(side=tk.LEFT)
        ttk.Button(row1, text="删除", command=self._delete_bug_record, style="Secondary.TButton").pack(
            side=tk.LEFT, padx=(8, 0),
        )

        self._bug_detail_var = tk.StringVar(value="选中一行查看详情")
        ttk.Label(detail, textvariable=self._bug_detail_var, wraplength=900, style="SubtleOnBg.TLabel").pack(
            anchor=tk.W, fill=tk.X,
        )

        tree.bind("<<TreeviewSelect>>", self._on_bug_select)

        def close():
            win.withdraw()

        win.protocol("WM_DELETE_WINDOW", close)
        self._bug_win = win

    def _refresh_bug_table(self) -> None:
        if self._bug_tree is None:
            return
        for iid in self._bug_tree.get_children():
            self._bug_tree.delete(iid)
        try:
            from db_manager import list_bugs, count_bugs
            flt = self._bug_filter_var.get()
            rows = list_bugs(limit=500, verdict=flt if flt != "全部" else None)
            for r in rows:
                src = r.get("source_file", "")
                if len(src) > 40:
                    src = "…" + src[-38:]
                self._bug_tree.insert(
                    "", tk.END, iid=str(r["id"]),
                    values=(
                        r["id"], r.get("bug_no", ""), r.get("title", "")[:60],
                        r.get("severity", ""), src, r.get("human_verdict", "待定"),
                    ),
                )
            stats = count_bugs()
            self._bug_count_var.set(
                f"共 {stats.get('total',0)} 条 | "
                f"待定 {stats.get('待定',0)} · 确认 {stats.get('确认',0)} · "
                f"误报 {stats.get('误报',0)} · 忽略 {stats.get('忽略',0)}"
            )
        except Exception as e:
            self._bug_count_var.set(f"加载失败：{e}")

    def _on_bug_select(self, _event: object = None) -> None:
        if self._bug_tree is None:
            return
        sel = self._bug_tree.selection()
        if not sel:
            return
        bug_id = int(sel[0])
        try:
            from db_manager import get_bug
            b = get_bug(bug_id)
            if not b:
                return
            self._verdict_var.set(b.get("human_verdict", "待定"))
            self._verdict_notes_var.set(b.get("human_notes", ""))
            detail = (
                f"[{b.get('bug_no','')}] {b.get('title','')}\n"
                f"类型：{b.get('bug_type','')}  时间：{b.get('log_time','')}\n"
                f"结论：{b.get('conclusion','')[:200]}"
            )
            self._bug_detail_var.set(detail)
        except Exception:
            pass

    def _save_verdict(self) -> None:
        if self._bug_tree is None:
            return
        sel = self._bug_tree.selection()
        if not sel:
            messagebox.showinfo("提示", "请先选中一条 Bug。", parent=self._bug_win)
            return
        bug_id = int(sel[0])
        try:
            from db_manager import update_verdict
            ok = update_verdict(bug_id, self._verdict_var.get(), self._verdict_notes_var.get())
            if ok:
                self._refresh_bug_table()
                self._bug_tree.selection_set(str(bug_id))
        except Exception as e:
            messagebox.showerror("保存失败", str(e)[:500], parent=self._bug_win)

    def _delete_bug_record(self) -> None:
        if self._bug_tree is None:
            return
        sel = self._bug_tree.selection()
        if not sel:
            return
        bug_id = int(sel[0])
        if not messagebox.askyesno("确认", f"删除 Bug #{bug_id}？", parent=self._bug_win):
            return
        try:
            from db_manager import delete_bug
            delete_bug(bug_id)
            self._refresh_bug_table()
        except Exception as e:
            messagebox.showerror("删除失败", str(e)[:500], parent=self._bug_win)

    def _import_rules_from_xlsx(self) -> None:
        if self._import_thread is not None and self._import_thread.is_alive():
            messagebox.showinfo("提示", "已有规则导入任务在运行。", parent=self.root)
            return
        if not os.environ.get("CURSOR_API_KEY", "").strip() or not os.environ.get(
            "CURSOR_GITHUB_REPO", ""
        ).strip():
            messagebox.showwarning(
                "未配置 Cursor",
                "请先在「设置 → Cursor API 与仓库…」中填写 CURSOR_API_KEY 与 CURSOR_GITHUB_REPO。",
                parent=self.root,
            )
            return
        path = filedialog.askopenfilename(
            parent=self.root,
            title="选择压测用例等表格文件（Excel 或 CSV）",
            initialdir=str(_ROOT),
            filetypes=[
                ("Excel / CSV", "*.xlsx;*.xlsm;*.csv"),
                ("Excel 工作簿", "*.xlsx;*.xlsm"),
                ("CSV", "*.csv"),
                ("所有文件", "*.*"),
            ],
        )
        if not path:
            return
        src_path = Path(path)
        if not src_path.is_file():
            messagebox.showwarning("提示", "所选路径无效。", parent=self.root)
            return
        if src_path.suffix.lower() not in (".csv", ".xlsx", ".xlsm"):
            messagebox.showwarning("提示", "请选择 .xlsx、.xlsm 或 .csv 文件。", parent=self.root)
            return

        self._status.set("正在读取表格并调用 Cursor 提取规则（可能较久）…")

        def worker() -> None:
            try:
                plain = _tabular_rules_source_to_plain(src_path)
                llm_text = _cursor_submit(_rule_import_prompt(plain))
                new_items = _rules_from_llm_response(llm_text)
                if not new_items:
                    raise ValueError("模型未返回任何可用规则。")
            except Exception as e:
                msg = str(e)
                if len(msg) > 1600:
                    msg = msg[:1600] + "…"

                def on_err() -> None:
                    self._status.set("规则导入失败。")
                    messagebox.showerror("导入失败", msg, parent=self.root)

                self.root.after(0, on_err)
                return

            existing = load_user_rules_raw(_USER_RULES_PATH)
            reserved: set[str] = {x["category"] for x in existing} | set(_BUILTIN_RULE_CATEGORIES)
            added: list[dict] = []
            for it in new_items:
                c = it["category"]
                if c in reserved:
                    base = c
                    n = 2
                    while f"{base}_{n}" in reserved:
                        n += 1
                    c = f"{base}_{n}"
                it["category"] = c
                reserved.add(c)
                added.append(it)
            merged = existing + added

            def on_ok() -> None:
                save_user_rules_raw(_USER_RULES_PATH, merged)
                self._refresh_rules_table()
                self._status.set(f"已导入 {len(added)} 条自定义规则。")
                messagebox.showinfo(
                    "导入完成",
                    f"已从「{src_path.name}」经 Cursor 提取并追加 {len(added)} 条规则到 serial_rules_user.json。\n"
                    f"（若 category 与已有或内置键冲突，已自动加后缀。）",
                    parent=self.root,
                )

            self.root.after(0, on_ok)

        self._import_thread = threading.Thread(target=worker, daemon=True)
        self._import_thread.start()

    def _run(self) -> None:
        if self._worker_thread and self._worker_thread.is_alive():
            messagebox.showinfo("提示", "已有任务在运行。", parent=self.root)
            return
        if not self._current_file or not self._current_file.is_file():
            messagebox.showwarning("提示", "请先选择有效的日志文件。", parent=self.root)
            return
        mc = int(os.environ.get("CURSOR_SUMMARY_MAX_CHARS", "90000"))
        cfg = WorkerConfig(
            file_path=self._current_file,
            max_chars=mc,
            user_clean_prompt=self._clean_prompt_body,
            user_analysis_notes=self._analysis_notes,
        )
        self._set_result_text("")
        self._progress["value"] = 0
        self._status.set("")
        while True:
            try:
                self._msg_q.get_nowait()
            except queue.Empty:
                break

        def thread_target() -> None:
            _run_analyze(cfg, self._msg_q)

        self._worker_thread = threading.Thread(target=thread_target, daemon=True)
        self._worker_thread.start()
        self.root.after(80, self._poll_queue)

    def _poll_queue(self) -> None:
        def drain() -> None:
            try:
                while True:
                    kind, *rest = self._msg_q.get_nowait()
                    if kind == "progress":
                        pct, msg = rest
                        self._progress["value"] = pct
                        self._status.set(msg)
                    elif kind == "ok":
                        text = rest[0]
                        self._last_result = text
                        self._set_result_text(text)
                        self._status.set("完成。")
                    elif kind == "err":
                        err = rest[0]
                        self._set_result_text(err)
                        self._status.set("失败。")
                        messagebox.showerror("错误", err[:800], parent=self.root)
            except queue.Empty:
                pass

        drain()
        alive = self._worker_thread is not None and self._worker_thread.is_alive()
        if alive:
            self.root.after(80, self._poll_queue)
        else:
            drain()

    def _save_result(self) -> None:
        if not self._last_result.strip():
            messagebox.showinfo("提示", "没有可保存的内容。", parent=self.root)
            return
        ts = datetime.now().strftime("%Y%m%d_%H%M")
        default = _ROOT / "bugs" / f"serial_gui_summary_{ts}.txt"
        path = filedialog.asksaveasfilename(
            parent=self.root,
            title="保存分析结果",
            initialfile=default.name,
            initialdir=str(default.parent),
            defaultextension=".txt",
            filetypes=[("文本", "*.txt")],
        )
        if path:
            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(self._last_result, encoding="utf-8")
            self._status.set(f"已保存：{p}")

    def mainloop(self) -> None:
        self.root.mainloop()


def main() -> None:
    MainApp().mainloop()


if __name__ == "__main__":
    main()
