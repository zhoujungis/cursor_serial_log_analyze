# -*- coding: utf-8 -*-
"""串口日志规则告警：内置规则 + 可选 JSON 扩展（供桌面端与 SERIAL_ALERT_RULES_JSON 合并使用）。"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

# (priority 越小越优先, category, 显示名, regex 字符串)
RAW_ALERT_RULE_DEFINITIONS: list[tuple[int, str, str, str]] = [
    (
        1,
        "crash",
        "进程/崩溃",
        r"(?i)(\b(SIG(SEGV|KILL|ABRT|BUS|ILL|TSTP)|segfault|segmentation\s+fault|core\s*dumps?)\b)"
        r"|(\b(hardfault|busfault|memmanage|usagefault)\b)"
        r"|(\b(kernel\s*panic|panic|assert(?:ion)?\s*fail|fatal\s+(?:error|exception)?)\b)"
        r"|(\b(system\s+reset|exception\s+reset|software\s+reset)\b)"
        r"|(\b(task\s+(?:timeout|abort)|scheduler\s+abort)\b)"
        r"|(\b(process|task)\s+(crashed|killed)|\bPROGRAM\s+(?:ABORT|TERMINATED)\b)"
        r"|(崩溃|死机|复位|重启|硬件错误|断言失败|异常栈)",
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

CompiledRule = tuple[int, str, str, re.Pattern]


def compile_definitions(
    defs: list[tuple[int, str, str, str]],
) -> list[CompiledRule]:
    # 与历史 backend 一致：扩展规则按忽略大小写编译
    return [(p, c, lbl, re.compile(rx, re.I)) for p, c, lbl, rx in defs]


def _append_from_json_file(
    merged_raw: list[tuple[int, str, str, str]], path: Path
) -> None:
    try:
        with open(path, encoding="utf-8") as f:
            extra = json.load(f)
    except Exception:
        return
    if not isinstance(extra, list):
        return
    for it in extra:
        if not isinstance(it, dict):
            continue
        try:
            merged_raw.append(
                (
                    int(it.get("priority", 3)),
                    str(it["category"]),
                    str(it["label"]),
                    str(it["pattern"]),
                )
            )
        except (KeyError, TypeError, ValueError):
            continue


def build_compiled_rules(
    *,
    env_json_path: str | None = None,
    user_json_path: Path | None = None,
) -> list[CompiledRule]:
    """合并内置、SERIAL_ALERT_RULES_JSON（或显式 env 路径）、以及桌面端用户规则文件。"""
    merged_raw: list[tuple[int, str, str, str]] = list(RAW_ALERT_RULE_DEFINITIONS)
    env = (env_json_path if env_json_path is not None else "").strip()
    if not env:
        env = os.environ.get("SERIAL_ALERT_RULES_JSON", "").strip()
    if env:
        _append_from_json_file(merged_raw, Path(env).expanduser())
    if user_json_path is not None and user_json_path.is_file():
        _append_from_json_file(merged_raw, user_json_path)
    return compile_definitions(merged_raw)


def match_log_alerts_for_rules(text: str, rules: list[CompiledRule]) -> list[dict]:
    """对单行日志做规则匹配；同 category 只保留首次命中。返回按 priority 排序。"""
    if not text or not text.strip():
        return []
    max_chars = int(os.environ.get("SERIAL_ALERT_TEXT_MAXLEN", "8192"))
    if max_chars > 0 and len(text) > max_chars:
        text = text[:max_chars]
    hits: list[dict] = []
    seen_cat: set[str] = set()
    for pri, cat, label, rx in rules:
        if cat in seen_cat:
            continue
        if rx.search(text):
            hits.append({"pri": pri, "cat": cat, "label": label})
            seen_cat.add(cat)
    hits.sort(key=lambda x: x["pri"])
    return hits


def load_user_rules_raw(path: Path) -> list[dict]:
    """读取用户 JSON 为 dict 列表（用于界面展示/编辑）。"""
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    if not isinstance(data, list):
        return []
    out: list[dict] = []
    for it in data:
        if isinstance(it, dict) and "pattern" in it and "category" in it:
            out.append(
                {
                    "priority": int(it.get("priority", 3)),
                    "category": str(it["category"]),
                    "label": str(it.get("label", it["category"])),
                    "pattern": str(it["pattern"]),
                }
            )
    return out


def save_user_rules_raw(path: Path, items: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(items, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
