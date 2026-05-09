# backend_web.py
import asyncio
import base64
import json
import os
import re
import threading
import time
from collections import deque
from datetime import datetime
from html import escape as html_escape
from pathlib import Path
from threading import Thread

import requests
from dotenv import load_dotenv

# 从「本文件所在目录」和「当前工作目录」加载 .env，避免只在系统里配了变量但启动服务的进程读不到
_env_root = Path(__file__).resolve().parent
load_dotenv(_env_root / ".env")
load_dotenv(Path.cwd() / ".env")
from fastapi import FastAPI, Form, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse

app = FastAPI()

CURSOR_API_BASE = "https://api.cursor.com"
LLM_BATCH_SIZE = 20

# 全局缓存
log_buffer = {}    # {port: deque} 供 LLM 等逻辑检查会话是否存在（镜像告警条目）
browser_outbox = {}  # {port: deque} WebSocket 只由此队列顺序推送（避免重复刷最后一条）
llm_buffers = {}   # {port: deque}
status_buffer = {} # {port: str} 状态信息
serial_sessions = {}  # {port: {"stop": Event, "serial": Serial}}
serial_reader_threads = {}  # {port: Thread} — 重启采集前先 join，避免旧线程 readline 被关端口误报异常
buffer_lock = threading.Lock()
_llm_loop_ports_lock = threading.Lock()
_llm_loop_ports_started = set()
_cursor_agent_by_port = {}
_llm_warned_missing_key = set()
_llm_warned_missing_repo = set()

LSTM_SEQUENCE_LEN = 5
LSTM_VECTOR_SIZE = 16
_lstm_singleton = None  # lazy: (torch_module, threshold)

# --------- 规则告警（优先于 LSTM；可扩展 JSON，见 SERIAL_ALERT_RULES_JSON）---------
_alert_rules_merge_lock = threading.Lock()
_ALERT_RULES_MERGED = None

# (priority 数值越小越优先展示, category, 显示名, regex)
_ALERT_RULE_DEFINITIONS_RAW: list[tuple[int, str, str, str]] = [
    (
        1,
        "crash",
        "进程/崩溃/看门狗",
        r"(?i)(\b(SIG(SEGV|KILL|ABRT|BUS|ILL|TSTP)|segfault|segmentation\s+fault|core\s*dumps?)\b)"
        r"|(\b(watchdog|hardfault|busfault|memmanage|usagefault)\b)"
        r"|(\b(kernel\s*panic|panic|assert(?:ion)?\s*fail|fatal\s+(?:error|exception)?)\b)"
        r"|(\b(system\s+reset|exception\s+reset|software\s+reset)\b)"
        r"|(\b(task\s+(?:timeout|abort)|scheduler\s+abort)\b)"
        r"|(\b(process|task)\s+(crashed|killed)|\bPROGRAM\s+(?:ABORT|TERMINATED)\b)"
        r"|(崩溃|死机|复位|重启|硬件错误|断言失败|看门狗|异常栈)",
    ),
    (
        1,
        "memory",
        "内存/OOM/分配失败",
        r"(?i)(\b(oom|out[\s_-]*of[\s_-]*memory)\b)"
        r"|(\b(malloc|calloc|realloc)[\w\s]*\s*fail|\ballocation\s+failed\b)"
        r"|(\bheap\s*(corrupt|overflow|underflow)|stack\s*overflow)\b"
        r"|(\binsufficient\s+memory\b|\bunable\s+to\s+allocate\b|\bnomem\b)"
        r"|(\bmemory\s*leak|\bfragmentation\b|\blow\s+memory\b)"
        r"|(内存不足|栈溢出|堆栈溢出|堆损坏|内存分配失败)",
    ),
    (
        2,
        "storage",
        "存储/Flash/文件系统",
        r"(?i)(\b(flash\s*(erase|write|read)?\s*(fail|error)|bad\s*block)\b)"
        r"|(\b(emmc|nand|spi\s*flash)\b.*\b(fail|error)\b)"
        r"|(\b(filesystem|fs)\s*(corrupt|error|readonly)\b)"
        r"|(\bno\s*space\s*left|disk\s*full|write\s*protect)\b"
        r"|(\b(i/o|io)\s*error\b)"
        r"|(无法写入|读写.*失败|存储.*错误|擦除失败)",
    ),
    (
        2,
        "power_thermal",
        "电源/温度",
        r"(?i)(\b(overheat|thermal\s*shutdown|throttl|trip)\b)"
        r"|(\b(brown|under)[\s_-]*voltage|power\s*good\s*fail)\b"
        r"|(过温|过热|欠压|掉电|电源异常)",
    ),
    (
        3,
        "severity",
        "严重级别(FATAL/CRITICAL)",
        r"(?i)(\b(FATAL|CRITICAL)\b|\bpanic\b|\b致命\b|\b严重错误\b)",
    ),
]


def _compile_alert_definitions(
    defs: list[tuple[int, str, str, str]],
) -> list[tuple[int, str, str, re.Pattern]]:
    return [(p, c, lbl, re.compile(rx)) for p, c, lbl, rx in defs]


def _load_merged_alert_rules() -> list[tuple[int, str, str, re.Pattern]]:
    """合并内置规则与 SERIAL_ALERT_RULES_JSON（JSON 列表项: priority, category, label, pattern）。"""
    merged = _compile_alert_definitions(_ALERT_RULE_DEFINITIONS_RAW)
    path = os.environ.get("SERIAL_ALERT_RULES_JSON", "").strip()
    if path:
        try:
            with open(Path(path).expanduser(), encoding="utf-8") as f:
                extra = json.load(f)
            for it in extra:
                merged.append(
                    (
                        int(it.get("priority", 3)),
                        str(it["category"]),
                        str(it["label"]),
                        re.compile(str(it["pattern"]), re.I),
                    )
                )
        except Exception:
            pass
    return merged


def _get_alert_rules():
    global _ALERT_RULES_MERGED
    if _ALERT_RULES_MERGED is not None:
        return _ALERT_RULES_MERGED
    with _alert_rules_merge_lock:
        if _ALERT_RULES_MERGED is None:
            _ALERT_RULES_MERGED = _load_merged_alert_rules()
    return _ALERT_RULES_MERGED


def match_log_alerts(text: str) -> list[dict]:
    """对单行日志做规则匹配；同 category 只保留首次命中。返回按 priority 排序。"""
    if not text or not text.strip():
        return []
    max_chars = int(os.environ.get("SERIAL_ALERT_TEXT_MAXLEN", "8192"))
    if max_chars > 0 and len(text) > max_chars:
        text = text[:max_chars]
    hits: list[dict] = []
    seen_cat: set[str] = set()
    for pri, cat, label, rx in _get_alert_rules():
        if cat in seen_cat:
            continue
        if rx.search(text):
            hits.append({"pri": pri, "cat": cat, "label": label})
            seen_cat.add(cat)
    hits.sort(key=lambda x: x["pri"])
    return hits


def _serial_lstm_web_enabled() -> bool:
    return os.environ.get("SERIAL_ALERT_LSTM", "0").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


def _ensure_lstm():
    global _lstm_singleton
    if _lstm_singleton is not None:
        return _lstm_singleton
    import torch
    import torch.nn as nn

    class LSTMAnomalyDetector(nn.Module):
        def __init__(self, input_size=LSTM_VECTOR_SIZE, hidden_size=32, num_layers=1):
            super().__init__()
            self.lstm = nn.LSTM(input_size, hidden_size, num_layers, batch_first=True)
            self.fc = nn.Linear(hidden_size, input_size)

        def forward(self, x):
            out, _ = self.lstm(x)
            return self.fc(out)

    thr = float(os.environ.get("LSTM_THRESHOLD", "0.5"))
    m = LSTMAnomalyDetector(LSTM_VECTOR_SIZE, 32)
    m.eval()
    _lstm_singleton = (m, thr)
    return _lstm_singleton


def _log_to_vector(log_line: str):
    import numpy as np

    vec = np.zeros(LSTM_VECTOR_SIZE, dtype=np.float32)
    h = abs(hash(log_line))
    for i in range(LSTM_VECTOR_SIZE):
        vec[i] = ((h >> (i * 4)) & 0xF) / 15.0
    return vec


def _lstm_error_and_threshold(vectors):
    """vectors: sequence_length 个长度 LSTM_VECTOR_SIZE 的向量（list[list[float]]）。"""
    import torch

    model, thr = _ensure_lstm()
    seq = torch.tensor([vectors], dtype=torch.float32)
    with torch.no_grad():
        pred = model(seq)
        err = torch.mean((pred - seq) ** 2).item()
    return err, thr


def publish(port: str, entry: dict) -> None:
    """推送到浏览器（顺序、不重复）。"""
    with buffer_lock:
        e = dict(entry)
        e.setdefault("alerts", [])
        e.setdefault("lstm", False)
        e.setdefault("status", status_buffer.get(port, "未知"))
        ob = browser_outbox.get(port)
        if ob is not None:
            ob.append(e)
        if port in log_buffer:
            log_buffer[port].append(e)


def _serial_session_shutdown(port: str) -> None:
    sess = None
    with buffer_lock:
        sess = serial_sessions.pop(port, None)
    if not sess:
        return
    sess["stop"].set()
    ser = sess.get("serial")
    if ser is not None:
        try:
            ser.close()
        except Exception:
            pass


def _serial_timeout() -> float:
    return float(os.environ.get("SERIAL_TIMEOUT", "1"))


def serial_open_configured(serial_mod, port: str, baudrate: int):
    """与助手一致：可走环境变量 parity/位数/STOP/硬件流控；两处打开必须用同一入口。"""
    parity_name = os.environ.get("SERIAL_PARITY", "NONE").strip().upper()
    pmap = {
        "NONE": serial_mod.PARITY_NONE,
        "EVEN": serial_mod.PARITY_EVEN,
        "ODD": serial_mod.PARITY_ODD,
        "MARK": serial_mod.PARITY_MARK,
        "SPACE": serial_mod.PARITY_SPACE,
    }
    parity = pmap.get(parity_name, serial_mod.PARITY_NONE)

    nbytes = int(os.environ.get("SERIAL_BYTESIZE", "8"))
    bmap = {
        5: serial_mod.FIVEBITS,
        6: serial_mod.SIXBITS,
        7: serial_mod.SEVENBITS,
        8: serial_mod.EIGHTBITS,
    }
    bytesize = bmap.get(nbytes, serial_mod.EIGHTBITS)

    stopbits_raw = os.environ.get("SERIAL_STOPBITS", "1").strip()
    stopbits = (
        serial_mod.STOPBITS_TWO
        if stopbits_raw in ("2", "2.0")
        else serial_mod.STOPBITS_ONE
    )

    fc = os.environ.get("SERIAL_FLOW", "").strip().upper()
    rtscts = fc == "RTSCTS"
    xonxoff = fc == "XONXOFF"

    dsrdtr = os.environ.get("SERIAL_DSRDTR", "0").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )

    sto = _serial_timeout()
    wr_raw = os.environ.get("SERIAL_WRITE_TIMEOUT", "").strip()
    write_timeout = float(wr_raw) if wr_raw else sto

    return serial_mod.Serial(
        port=port,
        baudrate=baudrate,
        bytesize=bytesize,
        parity=parity,
        stopbits=stopbits,
        timeout=sto,
        write_timeout=write_timeout,
        xonxoff=xonxoff,
        rtscts=rtscts,
        dsrdtr=dsrdtr,
    )


def _buffer_pop_lines(lines_buf: bytearray, newline_mode: str) -> list[bytes]:
    """从内建缓冲中取完整一行（按换行模式），余下的留在 lines_buf。"""
    out: list[bytes] = []
    nm = (newline_mode or "lf").strip().lower()
    max_buf = int(os.environ.get("SERIAL_BUFFER_MAX", "262144"))

    while lines_buf:
        if len(lines_buf) > max_buf:
            out.append(bytes(lines_buf))
            lines_buf.clear()
            continue

        if nm == "any":
            cands = []
            i = lines_buf.find(b"\r\n")
            if i >= 0:
                cands.append((i, 2))
            i = lines_buf.find(b"\n")
            if i >= 0:
                cands.append((i, 1))
            i = lines_buf.find(b"\r")
            if i >= 0:
                cands.append((i, 1))
            if not cands:
                break
            idx, nbytes = sorted(cands, key=lambda x: (x[0], -x[1]))[0]
            out.append(bytes(lines_buf[:idx]))
            del lines_buf[: idx + nbytes]
            continue

        if nm == "crlf":
            idx = lines_buf.find(b"\r\n")
            if idx < 0:
                break
            out.append(bytes(lines_buf[:idx]))
            del lines_buf[: idx + 2]
            continue

        sep = b"\r" if nm == "cr" else b"\n"
        idx = lines_buf.find(sep)
        if idx < 0:
            break
        out.append(bytes(lines_buf[:idx]))
        del lines_buf[: idx + len(sep)]

    return out


def _serial_idle_flush_ms(read_mode: str) -> float:
    raw = os.environ.get("SERIAL_IDLE_FLUSH_MS")
    if raw is not None and str(raw).strip() != "":
        return float(raw)
    return 120.0 if read_mode == "buffer" else 0.0


def _iter_serial_capture_lines(ser, stop_evt: threading.Event, serial_mod):
    """
    line: pyserial readline（设备必须周期性发 \\n 才像「在读」）。
    buffer: 先读可用字节再累积分行； SERIAL_NEWLINE 支持 lf/cr/crlf/any；
            SERIAL_IDLE_FLUSH_MS 毫秒无新字节时把缓冲区整段吐出（适配无换行协议包）。
    """
    mode = os.environ.get("SERIAL_READ_MODE", "line").strip().lower()
    newline_mode = os.environ.get("SERIAL_NEWLINE", "lf").strip().lower()
    buf = bytearray()
    touched = time.monotonic()
    idle_ms = _serial_idle_flush_ms(mode)

    while not stop_evt.is_set():
        try:
            if mode == "line":
                raw = ser.readline()
            else:
                n = getattr(ser, "in_waiting", 0) or 0
                if n > 0:
                    mx = max(1, int(os.environ.get("SERIAL_CHUNK_MAX", "65536")))
                    raw = ser.read(min(mx, n))
                else:
                    raw = ser.read(1)
        except Exception:
            if stop_evt.is_set():
                return
            raise

        now = time.monotonic()

        if mode == "line":
            if not raw:
                continue
            text = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            if text.strip():
                yield text
            continue

        # buffer
        if raw:
            buf.extend(raw)
            touched = now

        for line_b in _buffer_pop_lines(buf, newline_mode):
            text = line_b.decode("utf-8", errors="replace").strip()
            if text:
                yield text

        mono = time.monotonic()
        if (
            idle_ms > 0
            and buf
            and not stop_evt.is_set()
            and (mono - touched) >= idle_ms / 1000.0
        ):
            lump = buf.decode("utf-8", errors="replace").strip()
            buf.clear()
            touched = time.monotonic()
            if lump:
                yield lump


def start_llm_loop_once(port: str) -> None:
    with _llm_loop_ports_lock:
        if port in _llm_loop_ports_started:
            return
        _llm_loop_ports_started.add(port)
    Thread(target=llm_loop, args=(port,), daemon=True).start()


def _cursor_basic_auth_header(api_key: str) -> str:
    token = base64.b64encode(f"{api_key}:".encode()).decode("ascii")
    return f"Basic {token}"


def _parse_sse_stream(response: requests.Response):
    event_name = None
    for raw in response.iter_lines(decode_unicode=True):
        if raw is None:
            continue
        line = raw.strip()
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
    parts = []
    with requests.get(url, headers=headers, stream=True, timeout=600) as resp:
        resp.raise_for_status()
        for event_name, data in _parse_sse_stream(resp):
            if event_name == "assistant" and isinstance(data, dict) and "text" in data:
                parts.append(data["text"])
            elif event_name == "result":
                break
    return "".join(parts)


def _cursor_submit_prompt(port: str, prompt: str) -> str:
    """与 main.py 一致：Cursor 账号（Dashboard → Integrations 的 API Key）+ Cloud Agent。"""
    api_key = os.environ.get("CURSOR_API_KEY", "").strip()
    if not api_key:
        if port not in _llm_warned_missing_key:
            _llm_warned_missing_key.add(port)
            publish(
                port,
                {
                    "log": f"[{port}] LLM",
                    "lstm": False,
                    "llm": "未设置 CURSOR_API_KEY（请在环境变量中配置，见 Cursor Dashboard → Integrations）",
                },
            )
        return ""

    github_repo = os.environ.get("CURSOR_GITHUB_REPO", "").strip()
    if not github_repo:
        if port not in _llm_warned_missing_repo:
            _llm_warned_missing_repo.add(port)
            publish(
                port,
                {
                    "log": f"[{port}] LLM",
                    "lstm": False,
                    "llm": "未设置 CURSOR_GITHUB_REPO（Cloud Agent 需要可克隆的 GitHub 仓库 URL）",
                },
            )
        return ""

    ref = os.environ.get("CURSOR_GITHUB_REF", "main").strip() or "main"
    model = os.environ.get("CURSOR_MODEL", "").strip() or None
    headers = {
        "Authorization": _cursor_basic_auth_header(api_key),
        "Content-Type": "application/json",
    }

    agent_id = _cursor_agent_by_port.get(port)
    if agent_id is None:
        body = {
            "prompt": {"text": prompt},
            "repos": [{"url": github_repo, "startingRef": ref}],
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
        r.raise_for_status()
        payload = r.json()
        agent_id = payload["agent"]["id"]
        run_id = payload["run"]["id"]
        _cursor_agent_by_port[port] = agent_id
    else:
        r = requests.post(
            f"{CURSOR_API_BASE}/v1/agents/{agent_id}/runs",
            headers=headers,
            json={"prompt": {"text": prompt}},
            timeout=120,
        )
        r.raise_for_status()
        run_id = r.json()["run"]["id"]

    return _cursor_stream_collect(agent_id, run_id, api_key)


def llm_loop(port: str):
    while True:
        batch = None
        with buffer_lock:
            if port in llm_buffers and len(llm_buffers[port]) >= LLM_BATCH_SIZE:
                batch = [llm_buffers[port].popleft() for _ in range(LLM_BATCH_SIZE)]
        if batch:
            logs_text = "\n".join(batch)
            prompt = (
                "分析以下设备串口日志是否异常，如果有，请指出异常位置、原因和严重性：\n"
                f"{logs_text}"
            )
            try:
                text = _cursor_submit_prompt(port, prompt)
                if text:
                    publish(
                        port,
                        {"log": f"[{port}] LLM 分析", "lstm": False, "llm": text},
                    )
            except requests.HTTPError as e:
                detail = ""
                if e.response is not None:
                    try:
                        detail = e.response.text[:500]
                    except Exception:
                        detail = str(e.response)
                publish(
                    port,
                    {"log": f"[{port}] Cursor API 错误", "lstm": False, "llm": f"{e} {detail}"},
                )
            except Exception as e:
                publish(
                    port,
                    {"log": f"[{port}] LLM 调用失败", "lstm": False, "llm": str(e)},
                )
        time.sleep(1)


# ------------------------
# 读取串口（落盘全部行）或文件回放
# ------------------------
def simulate_logs(
    port, mode="serial", file_content=None, baudrate=921600, capture_path=None
):
    browser_outbox[port] = deque(maxlen=500)
    log_buffer[port] = deque(maxlen=100)
    llm_buffers[port] = deque(maxlen=100)
    status_buffer[port] = "运行中"
    start_llm_loop_once(port)

    if mode == "serial":
        import serial as serial_mod

        if not hasattr(serial_mod, "Serial"):
            publish(
                port,
                {
                    "log": f"[{port}] 串口库错误：需要 pyserial",
                    "lstm": False,
                    "llm": "",
                },
            )
            status_buffer[port] = "串口异常"
            return

        _serial_session_shutdown(port)
        stop_evt = threading.Event()
        if not capture_path:
            publish(
                port,
                {"log": f"[{port}] 内部错误：未指定 capture_path", "lstm": False, "llm": ""},
            )
            status_buffer[port] = "串口异常"
            return

        cap_file = Path(capture_path)
        cap_file.parent.mkdir(parents=True, exist_ok=True)

        ser = None
        vec_buf = deque(maxlen=LSTM_SEQUENCE_LEN)
        read_mode_help = (
            os.environ.get("SERIAL_READ_MODE", "line").strip().lower()
            or "line"
        )
        nw_help = (
            os.environ.get("SERIAL_NEWLINE", "lf").strip().lower() or "lf"
        )
        try:
            ser = serial_open_configured(serial_mod, port, baudrate)
            with buffer_lock:
                serial_sessions[port] = {"stop": stop_evt, "serial": ser}

            publish(
                port,
                {
                    "log": (
                        f"[{port}] 串口已打开（read_mode={read_mode_help}, newline={nw_help}, "
                        f"timeout={_serial_timeout()}s）{baudrate}bps → {cap_file}。"
                        "助手能看、脚本没行多半是设备不发 \\n：请改用 SERIAL_READ_MODE=buffer，"
                        "或设 SERIAL_IDLE_FLUSH_MS 在无换行时按空闲分包。"
                    ),
                    "alerts": [],
                    "lstm": False,
                    "llm": "",
                },
            )

            with open(cap_file, "a", encoding="utf-8") as fp:
                for text in _iter_serial_capture_lines(ser, stop_evt, serial_mod):
                    if stop_evt.is_set():
                        break
                    if not text.strip():
                        continue
                    ts = datetime.now().isoformat(timespec="milliseconds")
                    fp.write(f"{ts}\t{text}\n")
                    fp.flush()

                    log_line = f"[{port}] {text}"
                    with buffer_lock:
                        llm_buffers[port].append(log_line)

                    alerts = match_log_alerts(text)
                    lstm_hit = False
                    lstm_note = ""
                    if _serial_lstm_web_enabled():
                        vec_buf.append(_log_to_vector(text))
                        if len(vec_buf) == LSTM_SEQUENCE_LEN:
                            try:
                                vec_rows = [v.tolist() for v in vec_buf]
                                err, thr = _lstm_error_and_threshold(vec_rows)
                                if err > thr:
                                    lstm_hit = True
                                    lstm_note = f"LSTM误差={err:.4f}(阈值={thr})"
                            except Exception as ex_lstm:
                                publish(
                                    port,
                                    {
                                        "log": f"[{port}] LSTM 引擎异常: {ex_lstm}",
                                        "alerts": [],
                                        "lstm": False,
                                        "llm": "",
                                    },
                                )

                    if alerts or lstm_hit:
                        entry = {
                            "log": log_line,
                            "alerts": alerts,
                            "lstm": lstm_hit,
                            "llm": "",
                        }
                        if lstm_note:
                            entry["lstm_note"] = lstm_note
                        publish(port, entry)
        except Exception as e:
            if stop_evt.is_set():
                pass
            else:
                with buffer_lock:
                    status_buffer[port] = "串口异常"
                publish(
                    port,
                    {"log": f"[{port}] 串口读取异常: {e}", "lstm": False, "llm": ""},
                )
        finally:
            with buffer_lock:
                serial_sessions.pop(port, None)
                if status_buffer.get(port) == "运行中":
                    status_buffer[port] = "已停止"
            if ser is not None:
                try:
                    ser.close()
                except Exception:
                    pass

    elif mode == "file":
        for line in file_content.splitlines():
            log_line = f"[{port}] {line}"
            with buffer_lock:
                llm_buffers[port].append(log_line)
            fa = match_log_alerts(line)
            if fa:
                publish(port, {"log": log_line, "alerts": fa, "lstm": False, "llm": ""})
            time.sleep(0.1)
        status_buffer[port] = "已完成"


# ------------------------
# WebSocket 实时推送
# ------------------------
@app.websocket("/ws/logs/{port}")
async def websocket_endpoint(ws: WebSocket, port: str):
    await ws.accept()
    try:
        while True:
            batch = []
            with buffer_lock:
                ob = browser_outbox.get(port)
                if ob:
                    while ob:
                        batch.append(dict(ob.popleft()))
            for payload in batch:
                await ws.send_json(payload)
            await asyncio.sleep(0.05)
    except WebSocketDisconnect:
        pass

# ------------------------
# Cursor 连接状态（供前端展示）
# ------------------------
@app.get("/cursor_status")
def cursor_status():
    api_key = os.environ.get("CURSOR_API_KEY", "").strip()
    github_repo = os.environ.get("CURSOR_GITHUB_REPO", "").strip()
    if not api_key:
        return JSONResponse(
            {
                "state": "no_key",
                "message": (
                    "进程内未读取到 CURSOR_API_KEY。请在项目目录 "
                    f"{_env_root} 下创建 .env 并写入 CURSOR_API_KEY=...，"
                    "或在启动 uvicorn 的终端里先 export/set 该变量后重启服务。"
                ),
            }
        )
    if not github_repo:
        return JSONResponse(
            {
                "state": "no_repo",
                "message": (
                    "未设置 CURSOR_GITHUB_REPO。请在同目录 .env 中写入仓库 URL，"
                    "或设置系统环境变量后重启服务。"
                ),
            }
        )
    try:
        r = requests.get(
            f"{CURSOR_API_BASE}/v1/agents",
            headers={"Authorization": _cursor_basic_auth_header(api_key)},
            params={"limit": 1},
            timeout=8,
        )
        if r.status_code == 200:
            return JSONResponse({"state": "ready", "message": "Cursor API 已连接"})
        if r.status_code in (401, 403):
            return JSONResponse(
                {
                    "state": "auth_error",
                    "message": "API Key 无效或无权访问",
                    "http_status": r.status_code,
                }
            )
        return JSONResponse(
            {
                "state": "error",
                "message": f"API 返回 {r.status_code}",
                "http_status": r.status_code,
            }
        )
    except requests.Timeout:
        return JSONResponse({"state": "offline", "message": "连接 Cursor API 超时"})
    except requests.RequestException as e:
        return JSONResponse(
            {"state": "offline", "message": f"无法连接 Cursor：{type(e).__name__}"}
        )


# ------------------------
# 首页前端
# ------------------------
html = """
<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>智能串口/文件日志监控 Dashboard</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.1/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
<style>
:root {
  --bg: #0f1419;
  --bg-elevated: #1a2332;
  --border: rgba(255,255,255,0.08);
  --text: #e8edf4;
  --muted: #8b9cb3;
  --accent: #6366f1;
  --accent-soft: rgba(99, 102, 241, 0.2);
  --success: #34d399;
  --warn: #fbbf24;
  --danger: #f87171;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  min-height: 100vh;
  font-family: "Segoe UI", system-ui, -apple-system, sans-serif;
  background: radial-gradient(1200px 600px at 10% -10%, rgba(99,102,241,0.25), transparent),
              radial-gradient(800px 400px at 90% 0%, rgba(52,211,153,0.12), transparent),
              var(--bg);
  color: var(--text);
}
.app-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 1rem;
  padding: 1rem 1.5rem;
  background: linear-gradient(135deg, rgba(26,35,50,0.95), rgba(15,20,25,0.98));
  border-bottom: 1px solid var(--border);
  box-shadow: 0 4px 24px rgba(0,0,0,0.35);
}
.app-title {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  font-size: 1.25rem;
  font-weight: 600;
  letter-spacing: -0.02em;
}
.app-title i { color: var(--accent); font-size: 1.5rem; }
.cursor-pill {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.4rem 0.85rem;
  border-radius: 999px;
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  font-size: 0.8125rem;
  color: var(--muted);
  transition: border-color 0.2s, background 0.2s;
}
.cursor-pill[data-state="ready"] { border-color: rgba(52,211,153,0.35); color: var(--success); }
.cursor-pill[data-state="no_key"], .cursor-pill[data-state="no_repo"] { border-color: rgba(251,191,36,0.35); color: var(--warn); }
.cursor-pill[data-state="offline"], .cursor-pill[data-state="auth_error"], .cursor-pill[data-state="error"] {
  border-color: rgba(248,113,113,0.35); color: var(--danger);
}
.cursor-pill[data-state="checking"] { opacity: 0.85; }
.cursor-pill .bi { font-size: 1.1rem; }
.cursor-pill button {
  border: none;
  background: var(--accent-soft);
  color: var(--accent);
  border-radius: 999px;
  padding: 0.15rem 0.5rem;
  font-size: 0.7rem;
  cursor: pointer;
}
.cursor-pill button:hover { filter: brightness(1.15); }
.main-wrap { max-width: 1100px; margin: 0 auto; padding: 1.5rem 1rem 3rem; }
.hero-card {
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  border-radius: 16px;
  padding: 1.25rem 1.5rem;
  margin-bottom: 1.25rem;
  box-shadow: 0 8px 32px rgba(0,0,0,0.25);
}
.controls-row {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.75rem;
  margin-bottom: 1rem;
}
.btn-pill { border-radius: 999px !important; padding-left: 1.1rem !important; padding-right: 1.1rem !important; }
.file-input-wrap {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  flex-wrap: wrap;
}
.file-input-wrap input[type="file"] {
  max-width: 220px;
  background: rgba(0,0,0,0.2);
  border-color: var(--border);
  color: var(--text);
}
.status-line {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.9rem;
  color: var(--muted);
  margin-bottom: 0.75rem;
}
.status-line strong { color: var(--text); font-weight: 600; }
.status-dot {
  width: 8px; height: 8px; border-radius: 50%;
  background: var(--muted);
  flex-shrink: 0;
}
.status-dot.on { background: var(--success); box-shadow: 0 0 8px var(--success); }
.logs-card {
  background: #0c1016;
  border: 1px solid var(--border);
  border-radius: 12px;
  overflow: hidden;
}
.logs-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0.6rem 1rem;
  background: rgba(255,255,255,0.03);
  border-bottom: 1px solid var(--border);
  font-size: 0.8rem;
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: 0.06em;
}
#logs {
  height: min(52vh, 520px);
  overflow-y: auto;
  padding: 0.75rem 1rem;
  font-family: "Cascadia Code", "Consolas", ui-monospace, monospace;
  font-size: 0.8125rem;
  line-height: 1.5;
}
.log {
  padding: 0.45rem 0.5rem;
  margin-bottom: 2px;
  border-radius: 6px;
  border-left: 3px solid transparent;
  background: rgba(255,255,255,0.02);
}
.log:hover { background: rgba(255,255,255,0.05); }
.anomaly { color: #fca5a5; font-weight: 600; }
.alert-tag { display: inline-block; font-size: 0.72rem; font-weight: 600; padding: 0.12rem 0.4rem; border-radius: 4px; margin-left: 0.35rem; vertical-align: middle; }
.alert-tag.crash { background: rgba(248,113,113,0.22); color: #fecaca; border: 1px solid rgba(248,113,113,0.35); }
.alert-tag.memory { background: rgba(251,146,60,0.2); color: #fdba74; border: 1px solid rgba(251,146,60,0.35); }
.alert-tag.storage { background: rgba(234,179,8,0.18); color: #fde047; border: 1px solid rgba(234,179,8,0.35); }
.alert-tag.power_thermal { background: rgba(56,189,248,0.18); color: #7dd3fc; border: 1px solid rgba(56,189,248,0.3); }
.alert-tag.severity { background: rgba(192,132,252,0.2); color: #e9d5ff; border: 1px solid rgba(192,132,252,0.35); }
.alert-tag.custom { background: rgba(148,163,184,0.2); color: #e2e8f0; border: 1px solid rgba(148,163,184,0.3); }
.lstm-ref { font-size: 0.74rem; color: #94a3b8; font-weight: 500; margin-left: 0.35rem; }
.llm { color: #93c5fd; font-weight: 500; white-space: pre-wrap; word-break: break-word; }
.site-footer {
  text-align: center;
  margin-top: 2rem;
  padding-top: 1rem;
  border-top: 1px solid var(--border);
  font-size: 0.75rem;
  color: var(--muted);
}
.spin { animation: spin 0.8s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }
</style>
</head>
<body>
<header class="app-header">
  <div class="app-title">
    <i class="bi bi-activity" aria-hidden="true"></i>
    <span>智能日志监控 Dashboard</span>
  </div>
  <div id="cursorPill" class="cursor-pill" data-state="checking" role="status" title="">
    <i id="cursorIcon" class="bi bi-hourglass-split spin" aria-hidden="true"></i>
    <span id="cursorLabel">Cursor</span>
    <button type="button" id="cursorRefresh" title="刷新连接状态">刷新</button>
  </div>
</header>

<div class="main-wrap">
  <div class="hero-card">
    <div class="controls-row">
      <label class="d-inline-flex align-items-center gap-1 mb-0 text-secondary" style="font-size:0.8rem;" title="与设备管理器中端口名一致，如 COM5">
        <span>端口</span>
        <input type="text" id="serialPortInput" class="form-control form-control-sm" style="max-width:6.5rem;background:rgba(0,0,0,.2);border-color:var(--border);color:var(--text);" value="__SERIAL_PORT_ATTR__" spellcheck="false" />
      </label>
      <button type="button" class="btn btn-primary btn-sm btn-pill" onclick="startSerial()">
        <i class="bi bi-broadcast-pin me-1"></i>串口实时
      </button>
      <button type="button" class="btn btn-outline-danger btn-sm btn-pill" id="btnStopSerial" onclick="stopSerial()" disabled title="断开串口并停止采集">
        <i class="bi bi-stop-circle me-1"></i>停止串口
      </button>
      <form id="fileForm" class="file-input-wrap mb-0">
        <input type="file" id="logFile" class="form-control form-control-sm" accept=".txt,.log,.csv,*/*" />
        <button type="submit" class="btn btn-success btn-sm btn-pill">
          <i class="bi bi-upload me-1"></i>上传日志文件
        </button>
      </form>
    </div>
    <div class="status-line">
      <span class="status-dot" id="runDot"></span>
      <span>任务状态：<strong id="status">未启动</strong></span>
    </div>
    <div class="logs-card">
      <div class="logs-head">
        <span>异常与告警 <span style="font-weight:normal;opacity:.75;text-transform:none;letter-spacing:0;font-size:.68rem;margin-left:.35rem;">（规则：崩溃/OOM/存储等；LSTM 由 SERIAL_ALERT_LSTM 控制）</span></span>
        <span id="cursorHint" class="text-end" style="max-width:55%;font-size:0.72rem;text-transform:none;letter-spacing:0;"></span>
      </div>
      <div id="logs"></div>
    </div>
  </div>
  <footer class="site-footer">Copyright © 2020-2023 北京七人科技有限公司</footer>
</div>

<script>
let ws;
let activePort = null;
let activeMode = null;

function currentSerialPort() {
  const el = document.getElementById("serialPortInput");
  return (el && el.value.trim()) || "COM3";
}

const CURSOR_ICONS = {
  checking: ["bi-hourglass-split", "spin"],
  ready: ["bi-cloud-check-fill", ""],
  no_key: ["bi-key-fill", ""],
  no_repo: ["bi-github", ""],
  offline: ["bi-wifi-off", ""],
  auth_error: ["bi-shield-x", ""],
  error: ["bi-exclamation-triangle-fill", ""],
};

function setCursorUI(state, message) {
  const pill = document.getElementById("cursorPill");
  const icon = document.getElementById("cursorIcon");
  const hint = document.getElementById("cursorHint");
  pill.dataset.state = state;
  pill.title = message || "";
  hint.textContent = message ? "Cursor: " + message : "";
  const [cls, extra] = CURSOR_ICONS[state] || CURSOR_ICONS.error;
  icon.className = "bi " + cls + (extra ? " " + extra : "");
}

async function refreshCursorStatus() {
  setCursorUI("checking", "正在检测 Cursor API…");
  try {
    const r = await fetch("/cursor_status");
    const data = await r.json();
    setCursorUI(data.state, data.message);
  } catch (e) {
    setCursorUI("offline", "本页无法访问 /cursor_status");
  }
}

function updateStatus(msg) {
  document.getElementById("status").textContent = msg;
  const dot = document.getElementById("runDot");
  dot.classList.toggle("on", msg && msg !== "未启动");
}

function wsUrl(port) {
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  return proto + "//" + location.host + "/ws/logs/" + port;
}

function startWebSocket(port) {
  if (ws) { try { ws.close(); } catch (e) {} }
  ws = new WebSocket(wsUrl(port));
  ws.onmessage = function (event) {
    let data = JSON.parse(event.data);
    let div = document.createElement("div");
    div.className = "log";
    let hasRule = data.alerts && data.alerts.length > 0;
    if (hasRule) div.style.borderLeftColor = "rgba(251,146,60,0.85)";
    else if (data.lstm) div.style.borderLeftColor = "rgba(148,163,184,0.55)";
    else if (data.llm) div.style.borderLeftColor = "rgba(147,197,253,0.5)";
    let tagHtml = "";
    const catClass = {
      crash: "crash",
      memory: "memory",
      storage: "storage",
      power_thermal: "power_thermal",
      severity: "severity",
    };
    if (hasRule) {
      for (const a of data.alerts) {
        const cls = "alert-tag " + (catClass[a.cat] || "custom");
        tagHtml +=
          "<span class='" + cls + "'>[" + escapeHtml(a.label) + "]</span>";
      }
    }
    let lstmHtml = "";
    if (data.lstm) {
      lstmHtml +=
        "<span class='lstm-ref'>[LSTM·参考]" +
        (data.lstm_note ? " " + escapeHtml(data.lstm_note) : "") +
        "</span>";
    }
    div.innerHTML =
      escapeHtml(data.log) +
      tagHtml +
      lstmHtml +
      (data.llm ? " <span class='llm'>[LLM分析: " + escapeHtml(data.llm) + "]</span>" : "");
    document.getElementById("logs").appendChild(div);
    let logsDiv = document.getElementById("logs");
    logsDiv.scrollTop = logsDiv.scrollHeight;
    updateStatus(data.status || "运行中");
  };
}

function escapeHtml(s) {
  const d = document.createElement("div");
  d.textContent = s;
  return d.innerHTML;
}

function stopSerial() {
  if (activeMode !== "serial" || !activePort) return;
  fetch("/stop_serial?port=" + encodeURIComponent(activePort))
    .then((res) => res.json())
    .then((data) => {
      document.getElementById("btnStopSerial").disabled = true;
      if (ws) {
        try {
          ws.close();
        } catch (e) {}
        ws = null;
      }
      updateStatus(data.msg || "串口已停止");
      activePort = null;
      activeMode = null;
    })
    .catch(() => updateStatus("停止串口失败"));
}

function startSerial() {
  const p = currentSerialPort();
  fetch("/start_serial?port=" + encodeURIComponent(p))
    .then((res) => res.json())
    .then((data) => {
      if (data.status === "error") {
        updateStatus("串口启动失败: " + data.msg);
        return;
      }
      const capHint = data.capture_file ? " 保存：" + data.capture_file : "";
      const bd = data.baud != null ? " 波特率：" + data.baud : "";
      updateStatus("串口 " + p + " 已启动（规则/LSTM 命中才在下方显示；连接成功会有一条提示）。" + bd + capHint);
      activePort = p;
      activeMode = "serial";
      document.getElementById("btnStopSerial").disabled = false;
      document.getElementById("logs").innerHTML = "";
      startWebSocket(p);
    });
}

document.getElementById("cursorRefresh").addEventListener("click", function (e) {
  e.preventDefault();
  refreshCursorStatus();
});

document.getElementById("fileForm").onsubmit = function (e) {
  e.preventDefault();
  let file = document.getElementById("logFile").files[0];
  if (!file) {
    alert("请选择文件");
    return;
  }
  let reader = new FileReader();
  reader.onload = function () {
    fetch("/start_file?port=file1", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ body: reader.result }),
    })
      .then((res) => res.json())
      .then((data) => {
        if (data.status === "error") {
          updateStatus("文件启动失败: " + data.msg);
          return;
        }
        activePort = "file1";
        activeMode = "file";
        document.getElementById("btnStopSerial").disabled = true;
        document.getElementById("logs").innerHTML = "";
        updateStatus("文件 file1 已启动（仅规则命中行推送页面）");
        startWebSocket("file1");
      });
  };
  reader.readAsText(file);
};

refreshCursorStatus();
setInterval(refreshCursorStatus, 45000);
</script>
</body>
</html>
"""

@app.get("/health")
def health():
    return {"ok": True}


def _default_serial_port() -> str:
    return (os.environ.get("SERIAL_PORT", "COM3").strip() or "COM3")


@app.get("/")
async def get():
    page = html.replace("__SERIAL_PORT_ATTR__", html_escape(_default_serial_port()))
    return HTMLResponse(page)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "backend_web:app",
        host="127.0.0.1",
        port=8000,
        reload=False,
    )

# ------------------------
# 后端接口：启动串口
# ------------------------
@app.get("/start_serial")
async def start_serial(port: str):
    try:
        import serial

        if not hasattr(serial, "Serial"):
            return {
                "status": "error",
                "msg": (
                    '串口库冲突：误装了 PyPI 里的 "serial" 包（不是 pyserial）。'
                    "请执行 pip uninstall serial -y 后重新 pip install pyserial"
                ),
            }
        baud = int(os.environ.get("SERIAL_BAUD", "921600"))
        ser = serial_open_configured(serial, port, baud)
        ser.close()
    except Exception as e:
        return {"status": "error", "msg": f"串口打开失败: {e}"}

    log_root = Path(os.environ.get("SERIAL_CAPTURE_DIR", str(_env_root / "serial_capture")))
    log_root.mkdir(parents=True, exist_ok=True)
    safe = port.replace(":", "_").replace("\\", "_").replace("/", "_")
    capture_fn = log_root / f"{safe}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

    capture_resolved = str(capture_fn.resolve())
    _serial_session_shutdown(port)
    prev_thr = None
    with buffer_lock:
        prev_thr = serial_reader_threads.get(port)
    if prev_thr is not None and prev_thr.is_alive():
        prev_thr.join(timeout=float(os.environ.get("SERIAL_JOIN_TIMEOUT_SEC", "3")))

    def _serial_runner():
        try:
            simulate_logs(port, "serial", None, baud, capture_resolved)
        finally:
            ct = threading.current_thread()
            with buffer_lock:
                if serial_reader_threads.get(port) is ct:
                    serial_reader_threads.pop(port, None)

    t = Thread(target=_serial_runner, daemon=True)
    with buffer_lock:
        serial_reader_threads[port] = t
    t.start()
    return {
        "status": "ok",
        "msg": f"串口 {port} 已启动：全部原始行写入 {capture_fn}",
        "capture_file": str(capture_fn.resolve()),
        "baud": baud,
    }


@app.get("/stop_serial")
def stop_serial(port: str):
    with buffer_lock:
        status_buffer[port] = "已停止"
        if port in llm_buffers:
            llm_buffers[port].clear()
    _serial_session_shutdown(port)
    publish(
        port,
        {"log": f"[{port}] 串口已停止（已断开连接）", "lstm": False, "llm": ""},
    )
    return {"status": "ok", "msg": f"串口 {port} 已停止"}


# ------------------------
# 后端接口：读取文件
# ------------------------
@app.post("/start_file")
async def start_file(port: str, body: str = Form(...)):
    if not body.strip():
        return {"status": "error", "msg": "文件内容为空或无效"}
    Thread(target=simulate_logs, args=(port, "file", body), daemon=True).start()
    return {"status": "ok", "msg": f"文件 {port} 已启动"}