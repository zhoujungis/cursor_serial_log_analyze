import base64
import json
import os
from pathlib import Path

import serial

if not hasattr(serial, "Serial"):
    raise ImportError(
        '检测到错误的 pip 包 "serial"（无 Serial）。请: pip uninstall serial -y '
        "&& pip install pyserial"
    )
import torch
import torch.nn as nn
import numpy as np
from collections import deque
from threading import Thread
import time

import requests
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent / ".env")
load_dotenv(Path.cwd() / ".env")

CURSOR_API_BASE = "https://api.cursor.com"


def _cursor_basic_auth_header(api_key: str) -> str:
    token = base64.b64encode(f"{api_key}:".encode()).decode("ascii")
    return f"Basic {token}"


def _parse_sse_stream(response: requests.Response):
    """Yield (event_name, data_obj) from a Cursor run SSE stream."""
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

# ------------------------
# 1. LSTM 异常检测模型
# ------------------------
class LSTMAnomalyDetector(nn.Module):
    def __init__(self, input_size=16, hidden_size=32, num_layers=1):
        super().__init__()
        self.lstm = nn.LSTM(input_size, hidden_size, num_layers, batch_first=True)
        self.fc = nn.Linear(hidden_size, input_size)

    def forward(self, x):
        out, _ = self.lstm(x)
        out = self.fc(out)
        return out

# ------------------------
# 2. 日志向量化
# ------------------------
def log_to_vector(log_line, vector_size=16):
    vec = np.zeros(vector_size, dtype=np.float32)
    h = abs(hash(log_line))
    for i in range(vector_size):
        vec[i] = ((h >> (i*4)) & 0xF) / 15.0
    return vec

# ------------------------
# 3. 生产级在线 Agent
# ------------------------
class SerialLogAgentOnline:
    def __init__(self, serial_ports, sequence_length=5, mode="serial", log_file_paths=None):
        """
        mode: "serial" 或 "file"
        log_file_paths: dict {port: file_path} 仅在 mode="file" 时使用

        Cursor 账号鉴权（与 Dashboard 中 Integrations 里创建的 API Key 绑定）:
          CURSOR_API_KEY        必填
          CURSOR_GITHUB_REPO    必填，Cloud Agent 需要克隆的仓库 URL，例如 https://github.com/you/repo
          CURSOR_GITHUB_REF     可选，默认 main
          CURSOR_MODEL          可选，显式模型 id；不设置则由账号默认模型决定
        """
        self.ports = serial_ports
        self.sequence_length = sequence_length
        self.buffers = {p: deque(maxlen=sequence_length) for p in serial_ports}
        self.llm_buffers = {p: [] for p in serial_ports}
        self.model = LSTMAnomalyDetector(input_size=16, hidden_size=32)
        # TODO: load trained weights
        # self.model.load_state_dict(torch.load("lstm_online.pth"))
        self.model.eval()
        self.LSTM_THRESHOLD = 0.5
        self.LLM_BATCH_SIZE = 20

        self.mode = mode
        self.log_file_paths = log_file_paths or {}

        self.cursor_api_key = os.environ.get("CURSOR_API_KEY", "").strip()
        self.cursor_github_repo = os.environ.get("CURSOR_GITHUB_REPO", "").strip()
        self.cursor_github_ref = os.environ.get("CURSOR_GITHUB_REF", "main").strip() or "main"
        self.cursor_model = os.environ.get("CURSOR_MODEL", "").strip() or None
        # 每个串口一个 Cloud Agent，避免多路并发时同一 agent 409 busy
        self._cursor_agent_by_port = {}
        self._cursor_auth_headers = (
            {
                "Authorization": _cursor_basic_auth_header(self.cursor_api_key),
                "Content-Type": "application/json",
            }
            if self.cursor_api_key
            else {}
        )

    def _read_logs(self, port, baudrate=921600):
        if self.mode == "serial":
            ser = serial.Serial(port, baudrate, timeout=1)
            print(f"=== 串口 {port} 读取启动 ===")
            while True:
                line = ser.readline().decode(errors='ignore').strip()
                if line:
                    self._process_log(port, line)
                time.sleep(0.01)
        elif self.mode == "file":
            file_path = self.log_file_paths.get(port)
            if not file_path:
                print(f"[{port}] 没有提供 log 文件路径")
                return
            print(f"=== 文件 {file_path} 读取启动 ===")
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        self._process_log(port, line)
                    time.sleep(0.01)

    # LSTM 异常检测线程
    def _lstm_loop(self, port):
        while True:
            if len(self.buffers[port]) == self.sequence_length:
                seq = torch.tensor([list(self.buffers[port])], dtype=torch.float32)
                pred = self.model(seq)
                error = torch.mean((pred - seq)**2).item()
                if error > self.LSTM_THRESHOLD:
                    recent_log = self.llm_buffers[port][-1] if self.llm_buffers[port] else ""
                    print(f"⚠️ [{port}] LSTM 异常 | error={error:.4f} | log={recent_log}")
                    # TODO: 可调用报警
            time.sleep(0.5)

    def _cursor_stream_run(self, port: str, agent_id: str, run_id: str) -> None:
        url = f"{CURSOR_API_BASE}/v1/agents/{agent_id}/runs/{run_id}/stream"
        headers = {
            "Authorization": _cursor_basic_auth_header(self.cursor_api_key),
            "Accept": "text/event-stream",
        }
        with requests.get(url, headers=headers, stream=True, timeout=600) as resp:
            resp.raise_for_status()
            print(f"📌 [{port}] LLM 分析结果:")
            for event_name, data in _parse_sse_stream(resp):
                if event_name == "assistant" and isinstance(data, dict) and "text" in data:
                    print(data["text"], end="", flush=True)
                elif event_name == "error" and isinstance(data, dict):
                    print(f"\n[stream error] {data.get('message', data)}", flush=True)
                elif event_name == "result":
                    break
            print("\n=== 本批分析结束 ===")

    def _cursor_submit_prompt(self, port: str, prompt: str) -> None:
        if not self.cursor_api_key:
            print(f"[{port}] 未设置环境变量 CURSOR_API_KEY，跳过 LLM（在 Cursor Dashboard → Integrations 创建密钥）")
            return
        if not self.cursor_github_repo:
            print(
                f"[{port}] 未设置 CURSOR_GITHUB_REPO。Cloud Agent 需要可访问的 GitHub 仓库 URL，"
                "例如: set CURSOR_GITHUB_REPO=https://github.com/你的用户/某仓库"
            )
            return

        agent_id = self._cursor_agent_by_port.get(port)
        if agent_id is None:
            body = {
                "prompt": {"text": prompt},
                "repos": [
                    {"url": self.cursor_github_repo, "startingRef": self.cursor_github_ref}
                ],
                "autoCreatePR": False,
            }
            if self.cursor_model:
                body["model"] = {"id": self.cursor_model}
            r = requests.post(
                f"{CURSOR_API_BASE}/v1/agents",
                headers=self._cursor_auth_headers,
                json=body,
                timeout=120,
            )
            r.raise_for_status()
            payload = r.json()
            agent_id = payload["agent"]["id"]
            run_id = payload["run"]["id"]
            self._cursor_agent_by_port[port] = agent_id
        else:
            r = requests.post(
                f"{CURSOR_API_BASE}/v1/agents/{agent_id}/runs",
                headers=self._cursor_auth_headers,
                json={"prompt": {"text": prompt}},
                timeout=120,
            )
            r.raise_for_status()
            run_id = r.json()["run"]["id"]

        self._cursor_stream_run(port, agent_id, run_id)

    # 在线 LLM：通过 Cursor Cloud Agents API（CURSOR_API_KEY）流式输出
    def _llm_loop(self, port):
        while True:
            if len(self.llm_buffers[port]) >= self.LLM_BATCH_SIZE:
                batch = self.llm_buffers[port][: self.LLM_BATCH_SIZE]
                del self.llm_buffers[port][: self.LLM_BATCH_SIZE]
                logs_text = "\n".join(batch)
                prompt = (
                    "分析以下设备串口日志是否异常，如果有，请指出异常位置、原因和严重性：\n"
                    f"{logs_text}"
                )
                try:
                    self._cursor_submit_prompt(port, prompt)
                except requests.HTTPError as e:
                    detail = ""
                    if e.response is not None:
                        try:
                            detail = e.response.text[:500]
                        except Exception:
                            detail = str(e.response)
                    print(f"[{port}] Cursor API 调用失败: {e} {detail}")
                except Exception as e:
                    print(f"[{port}] LLM 调用失败: {e}")
            time.sleep(1)

    # 启动多串口 Agent
    def start(self):
        for port in self.ports:
            Thread(target=self._read_logs, args=(port,), daemon=True).start()
            Thread(target=self._lstm_loop, args=(port,), daemon=True).start()
            Thread(target=self._llm_loop, args=(port,), daemon=True).start()
        print("=== 串口/文件日志在线智能 Agent 已启动 ===")

# ------------------------
# 4. 使用示例
# ------------------------
if __name__ == "__main__":
    ports = ["COM3", "COM4"]
    agent = SerialLogAgentOnline(ports)
    agent.start()
    while True:
        time.sleep(10)