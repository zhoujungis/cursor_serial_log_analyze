# -*- coding: utf-8 -*-
"""Cursor Skills：规则护栏命中后的专家级 LLM 精准判定。

每个 Skill 绑定一组 rule category / keyword，当规则扫描命中时自动触发，
对命中行及上下文做深度分析，输出结构化判定结果供最终总结引用。
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Callable

_ROOT = Path(__file__).resolve().parent.parent
_USER_SKILLS_PATH = _ROOT / "config/cursor_skills_user.json"

# ── Skill 数据结构 ──────────────────────────────────────────────

@dataclass
class Skill:
    id: str
    name: str
    trigger_categories: list[str]
    trigger_keywords: list[str]
    context_lines: int
    prompt_template: str
    enabled: bool = True
    builtin: bool = True
    priority: int = 5
    category_patterns: list[str] = field(default_factory=list)
    """模糊匹配 rule category 的子串/关键词列表。
    例如 ["oom", "memory"] 会匹配 'oom_memory', 'memory', 'low_memory' 等。
    为空时退化为 trigger_categories 精确匹配。"""


# ── 内置 Skills ─────────────────────────────────────────────────

BUILTIN_SKILLS: list[Skill] = [
    Skill(
        id="oom_analysis",
        name="OOM / 内存分析",
        trigger_categories=["memory"],
        trigger_keywords=["oom-killer", "Out of memory", "oom_score", "invoked oom"],
        context_lines=30,
        priority=1,
        category_patterns=["oom", "memory", "malloc", "alloc"],
        prompt_template=(
            "你是嵌入式 Linux 内存分析专家。以下日志片段包含可能的 OOM / 内存耗尽异常。\n"
            "请分析：\n"
            "1. OOM 是否真实触发？被杀进程是哪个？RSS/VSS 多大？\n"
            "2. 触发前是否有明显的内存泄漏迹象（持续增长）？\n"
            "3. 是单次还是多次 OOM？时间间隔多少？\n"
            "4. 对系统/业务的实际影响（进程重启？通信中断？）\n\n"
            "请严格按以下格式输出：\n"
            "【判定】确认异常 / 疑似误报 / 需更多上下文\n"
            "【置信度】高/中/低\n"
            "【关键发现】一句话概述\n"
            "【建议】一句话排查建议\n\n"
            "--- 日志片段 ---\n"
        ),
    ),
    Skill(
        id="crash_analysis",
        name="崩溃 / Panic 分析",
        trigger_categories=["crash"],
        trigger_keywords=["panic", "segfault", "SIGSEGV", "SIGABRT", "core dump",
                          "hardfault", "assert", "fatal"],
        context_lines=40,
        priority=1,
        category_patterns=["crash", "panic", "fault", "assert", "fatal", "mcu_error"],
        prompt_template=(
            "你是嵌入式系统崩溃分析专家。以下日志片段包含可能的进程崩溃/Kernel Panic/断言失败。\n"
            "请分析：\n"
            "1. 崩溃类型（kernel panic / segfault / 用户态 assert / watchdog reset）？\n"
            "2. 崩溃进程名称和 PID？调用栈（如有）指向哪个模块？\n"
            "3. 崩溃次数和时间分布？\n"
            "4. 是否导致系统重启？\n\n"
            "请严格按以下格式输出：\n"
            "【判定】确认异常 / 疑似误报 / 需更多上下文\n"
            "【置信度】高/中/低\n"
            "【关键发现】一句话概述\n"
            "【建议】一句话排查建议\n\n"
            "--- 日志片段 ---\n"
        ),
    ),
    Skill(
        id="network_analysis",
        name="网络 / WiFi / BLE 分析",
        trigger_categories=["connectivity", "network", "wifi", "ble"],
        trigger_keywords=["disconnect wifi", "wifi disconnect", "ble disconnect",
                          "on disconnect", "link down", "association fail",
                          "deauth", "RSSI"],
        context_lines=25,
        priority=2,
        category_patterns=["wifi", "ble", "network", "heartbeat", "hcc",
                           "host_wifi", "atbm", "disconnect"],
        prompt_template=(
            "你是无线网络连接分析专家。以下日志片段包含可能的 WiFi/BLE 断连异常。\n"
            "请分析：\n"
            "1. 断连是主动还是被动？有无错误码/原因码？\n"
            "2. 断连频率和时间跨度？是否周期性？\n"
            "3. WiFi 和 BLE 断连是否关联（同一时间窗口）？\n"
            "4. 是否与其他异常（OOM/重启）时间重叠？\n\n"
            "请严格按以下格式输出：\n"
            "【判定】确认异常 / 疑似误报 / 需更多上下文\n"
            "【置信度】高/中/低\n"
            "【关键发现】一句话概述\n"
            "【建议】一句话排查建议\n\n"
            "--- 日志片段 ---\n"
        ),
    ),
    Skill(
        id="storage_analysis",
        name="存储 / Flash / 文件系统分析",
        trigger_categories=["storage"],
        trigger_keywords=["bad block", "crc error", "head error", "i/o error",
                          "read_meta_sector", "remount-ro", "no space left",
                          "write error", "erase fail"],
        context_lines=20,
        priority=3,
        category_patterns=["storage", "flash", "mmc", "emmc", "nand", "spi_comm",
                           "kernel_env", "cloud_storage"],
        prompt_template=(
            "你是嵌入式存储系统分析专家。以下日志片段包含可能的 Flash/eMMC/文件系统异常。\n"
            "请分析：\n"
            "1. 错误类型（CRC 校验/坏块/IO 错误/只读重挂载/空间不足）？\n"
            "2. 涉及的分区或设备节点？\n"
            "3. 错误频率——偶发还是持续？\n"
            "4. 是否可能导致配置/数据丢失？\n\n"
            "请严格按以下格式输出：\n"
            "【判定】确认异常 / 疑似误报 / 需更多上下文\n"
            "【置信度】高/中/低\n"
            "【关键发现】一句话概述\n"
            "【建议】一句话排查建议\n\n"
            "--- 日志片段 ---\n"
        ),
    ),
    Skill(
        id="boot_analysis",
        name="启动异常 / 重启循环分析",
        trigger_categories=["boot", "init", "startup"],
        trigger_keywords=["reboot", "boot banner", "Linux version",
                          "Starting kernel", "rockchip_amp", "init:",
                          "system reset", "watchdog"],
        context_lines=30,
        priority=2,
        category_patterns=["boot", "reboot", "startup", "reset", "init",
                           "wake_fail"],
        prompt_template=(
            "你是嵌入式设备启动流程分析专家。以下日志片段包含疑似启动异常或重启循环。\n"
            "请分析：\n"
            "1. 是否存在多次启动（多段 boot banner / 内核时间戳归零）？\n"
            "2. 重启原因（watchdog / panic / 掉电 / 用户主动）？\n"
            "3. 重启间隔和次数？\n"
            "4. 启动过程中有哪些初始化失败？\n\n"
            "请严格按以下格式输出：\n"
            "【判定】确认异常 / 疑似误报 / 需更多上下文\n"
            "【置信度】高/中/低\n"
            "【关键发现】一句话概述\n"
            "【建议】一句话排查建议\n\n"
            "--- 日志片段 ---\n"
        ),
    ),
    Skill(
        id="power_thermal_analysis",
        name="电源 / 温度异常分析",
        trigger_categories=["power_thermal"],
        trigger_keywords=["overheat", "thermal", "throttl", "brown",
                          "undervoltage", "power good fail", "过温", "欠压"],
        context_lines=20,
        priority=3,
        category_patterns=["power", "thermal", "charging", "battery",
                           "voltage"],
        prompt_template=(
            "你是电源与热管理分析专家。以下日志片段包含可能的电源/温度异常。\n"
            "请分析：\n"
            "1. 异常类型（过温降频/thermal shutdown/欠压/电源故障）？\n"
            "2. 温度或电压的具体数值（如日志中有）？\n"
            "3. 是否导致性能降级或关机？\n"
            "4. 环境因素还是硬件问题？\n\n"
            "请严格按以下格式输出：\n"
            "【判定】确认异常 / 疑似误报 / 需更多上下文\n"
            "【置信度】高/中/低\n"
            "【关键发现】一句话概述\n"
            "【建议】一句话排查建议\n\n"
            "--- 日志片段 ---\n"
        ),
    ),
]


# ── 用户自定义 Skills 加载/保存 ────────────────────────────────

def _load_user_skills() -> list[Skill]:
    if not _USER_SKILLS_PATH.is_file():
        return []
    try:
        data = json.loads(_USER_SKILLS_PATH.read_text(encoding="utf-8"))
    except Exception:
        return []
    if not isinstance(data, list):
        return []
    out: list[Skill] = []
    for it in data:
        if not isinstance(it, dict) or "id" not in it:
            continue
        out.append(Skill(
            id=it["id"],
            name=it.get("name", it["id"]),
            trigger_categories=it.get("trigger_categories", []),
            trigger_keywords=it.get("trigger_keywords", []),
            context_lines=int(it.get("context_lines", 25)),
            prompt_template=it.get("prompt_template", ""),
            enabled=it.get("enabled", True),
            builtin=False,
            priority=int(it.get("priority", 5)),
            category_patterns=it.get("category_patterns", []),
        ))
    return out


def save_user_skills(skills: list[Skill]) -> None:
    items = [
        {k: v for k, v in asdict(s).items() if k != "builtin"}
        for s in skills if not s.builtin
    ]
    _USER_SKILLS_PATH.parent.mkdir(parents=True, exist_ok=True)
    _USER_SKILLS_PATH.write_text(
        json.dumps(items, ensure_ascii=False, indent=2), encoding="utf-8",
    )


def get_all_skills() -> list[Skill]:
    """返回内置 + 用户自定义 Skills，按 priority 排序。"""
    all_skills = list(BUILTIN_SKILLS) + _load_user_skills()
    all_skills.sort(key=lambda s: s.priority)
    return all_skills


def get_skill_by_id(skill_id: str) -> Skill | None:
    for s in get_all_skills():
        if s.id == skill_id:
            return s
    return None


def add_user_skill(skill_dict: dict) -> Skill:
    """从 dict 创建并保存一个用户自定义 Skill。"""
    s = Skill(
        id=skill_dict["id"],
        name=skill_dict.get("name", skill_dict["id"]),
        trigger_categories=skill_dict.get("trigger_categories", []),
        trigger_keywords=skill_dict.get("trigger_keywords", []),
        context_lines=int(skill_dict.get("context_lines", 25)),
        prompt_template=skill_dict.get("prompt_template", ""),
        enabled=skill_dict.get("enabled", True),
        builtin=False,
        priority=int(skill_dict.get("priority", 5)),
        category_patterns=skill_dict.get("category_patterns", []),
    )
    existing = _load_user_skills()
    existing = [x for x in existing if x.id != s.id]
    existing.append(s)
    save_user_skills(existing)
    return s


def delete_user_skill(skill_id: str) -> bool:
    existing = _load_user_skills()
    before = len(existing)
    existing = [x for x in existing if x.id != skill_id]
    if len(existing) == before:
        return False
    save_user_skills(existing)
    return True


def toggle_skill(skill_id: str, enabled: bool) -> bool:
    """切换内置/自定义 Skill 的启用状态（内置 Skill 的禁用状态也存入用户文件）。"""
    user_skills = _load_user_skills()
    for s in user_skills:
        if s.id == skill_id:
            s.enabled = enabled
            save_user_skills(user_skills)
            return True
    for s in BUILTIN_SKILLS:
        if s.id == skill_id:
            override = Skill(
                id=s.id, name=s.name,
                trigger_categories=s.trigger_categories,
                trigger_keywords=s.trigger_keywords,
                context_lines=s.context_lines,
                prompt_template=s.prompt_template,
                enabled=enabled, builtin=False,
                priority=s.priority,
                category_patterns=s.category_patterns,
            )
            user_skills.append(override)
            save_user_skills(user_skills)
            return True
    return False


# ── 调度：规则命中 → Skills 匹配 ──────────────────────────────

@dataclass
class HitGroup:
    """一组规则命中：category + 对应的日志行号列表。"""
    category: str
    line_indices: list[int] = field(default_factory=list)


def _skill_matches_categories(skill: Skill, hit_categories: set[str]) -> bool:
    """判断 Skill 是否匹配命中的 category 集合。

    三层匹配策略：
    1. trigger_categories 精确匹配
    2. category_patterns 子串模糊匹配（oom → oom_memory, low_memory 等）
    3. trigger_keywords 文本匹配（兜底）
    """
    if set(skill.trigger_categories) & hit_categories:
        return True
    if skill.category_patterns:
        for cat in hit_categories:
            cat_lower = cat.lower()
            if any(p.lower() in cat_lower for p in skill.category_patterns):
                return True
    return False


def dispatch_skills(
    hit_categories: set[str],
    hit_lines_with_text: list[tuple[int, str]],
) -> list[Skill]:
    """根据规则命中的 category 集合，返回应触发的 Skills（已去重、按 priority 排序）。

    匹配优先级：category_patterns 模糊匹配 > trigger_categories 精确 > trigger_keywords 文本。
    """
    user_overrides = {s.id: s for s in _load_user_skills()}
    triggered: dict[str, Skill] = {}

    for skill in BUILTIN_SKILLS:
        effective = user_overrides.get(skill.id, skill)
        if not effective.enabled:
            continue
        if _skill_matches_categories(effective, hit_categories):
            triggered[effective.id] = effective
            continue
        if effective.trigger_keywords:
            for _, text in hit_lines_with_text:
                text_lower = text.lower()
                if any(kw.lower() in text_lower for kw in effective.trigger_keywords):
                    triggered[effective.id] = effective
                    break

    for skill in _load_user_skills():
        if skill.id in triggered or not skill.enabled:
            continue
        if skill.id in [s.id for s in BUILTIN_SKILLS]:
            continue
        if _skill_matches_categories(skill, hit_categories):
            triggered[skill.id] = skill
            continue
        if skill.trigger_keywords:
            for _, text in hit_lines_with_text:
                text_lower = text.lower()
                if any(kw.lower() in text_lower for kw in skill.trigger_keywords):
                    triggered[skill.id] = skill
                    break

    result = list(triggered.values())
    result.sort(key=lambda s: s.priority)
    return result


# ── 上下文提取 ────────────────────────────────────────────────

def extract_context(
    all_lines: list[str],
    hit_line_indices: list[int],
    context_n: int = 30,
    max_chars: int = 3000,
) -> str:
    """提取命中行前后 context_n 行，合并重叠区间，限制总字符数。"""
    total = len(all_lines)
    if not hit_line_indices:
        return ""

    intervals: list[tuple[int, int]] = []
    for idx in sorted(set(hit_line_indices)):
        lo = max(0, idx - context_n)
        hi = min(total, idx + context_n + 1)
        intervals.append((lo, hi))

    merged: list[tuple[int, int]] = []
    for lo, hi in intervals:
        if merged and lo <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append((lo, hi))

    parts: list[str] = []
    chars = 0
    for lo, hi in merged:
        for i in range(lo, hi):
            line = f"行{i+1}: {all_lines[i]}"
            if chars + len(line) > max_chars:
                parts.append("…（已截断）")
                return "\n".join(parts)
            parts.append(line)
            chars += len(line) + 1
        parts.append("---")

    return "\n".join(parts).rstrip("---\n")


# ── Skill 执行 ────────────────────────────────────────────────

@dataclass
class SkillResult:
    skill_id: str
    skill_name: str
    raw_output: str
    verdict: str = ""
    confidence: str = ""
    finding: str = ""
    suggestion: str = ""


def _parse_skill_output(text: str) -> dict:
    """从 Skill LLM 输出中提取结构化字段。"""
    fields = {}
    for cn, key in [
        ("判定", "verdict"),
        ("置信度", "confidence"),
        ("关键发现", "finding"),
        ("建议", "suggestion"),
    ]:
        m = re.search(rf"【{cn}】\s*(.*?)(?=\n【|\Z)", text, re.DOTALL)
        if m:
            fields[key] = m.group(1).strip()
    return fields


def run_skill(
    skill: Skill,
    context_text: str,
    llm_fn: Callable[[str], str],
) -> SkillResult:
    """执行单个 Skill：组装 prompt → 调用 LLM → 解析结果。"""
    prompt = skill.prompt_template + context_text
    try:
        raw = llm_fn(prompt)
    except Exception as e:
        return SkillResult(
            skill_id=skill.id, skill_name=skill.name,
            raw_output=f"（Skill 调用失败：{e}）",
        )
    parsed = _parse_skill_output(raw)
    return SkillResult(
        skill_id=skill.id,
        skill_name=skill.name,
        raw_output=raw.strip(),
        verdict=parsed.get("verdict", ""),
        confidence=parsed.get("confidence", ""),
        finding=parsed.get("finding", ""),
        suggestion=parsed.get("suggestion", ""),
    )


def run_all_skills(
    all_lines: list[str],
    hit_categories: set[str],
    hit_line_map: dict[str, list[int]],
    hit_lines_with_text: list[tuple[int, str]],
    llm_fn: Callable[[str], str],
    max_skills: int = 5,
    progress_fn: Callable[[str], None] | None = None,
) -> list[SkillResult]:
    """批量执行匹配的 Skills，返回结果列表。

    Args:
        all_lines: 全文按行分割
        hit_categories: 命中的 rule category 集合
        hit_line_map: category → [行号] 映射
        hit_lines_with_text: [(行号, 文本)] 用于 keyword 匹配
        llm_fn: LLM 调用函数 (prompt→response)
        max_skills: 最多调用几个 Skill
        progress_fn: 进度回调
    """
    skills = dispatch_skills(hit_categories, hit_lines_with_text)
    skills = skills[:max_skills]

    if not skills:
        return []

    results: list[SkillResult] = []
    for i, skill in enumerate(skills):
        if progress_fn:
            progress_fn(f"Skills 判定 ({i+1}/{len(skills)})：{skill.name}…")

        relevant_indices: list[int] = []
        # 精确 category 匹配
        for cat in skill.trigger_categories:
            relevant_indices.extend(hit_line_map.get(cat, []))
        # 模糊 category_patterns 匹配
        if not relevant_indices and skill.category_patterns:
            for cat, indices in hit_line_map.items():
                cat_lower = cat.lower()
                if any(p.lower() in cat_lower for p in skill.category_patterns):
                    relevant_indices.extend(indices)
        # 关键词文本匹配兜底
        if not relevant_indices and skill.trigger_keywords:
            for idx, text in hit_lines_with_text:
                text_lower = text.lower()
                if any(kw.lower() in text_lower for kw in skill.trigger_keywords):
                    relevant_indices.append(idx)

        if not relevant_indices:
            continue

        context = extract_context(
            all_lines, relevant_indices,
            context_n=skill.context_lines,
            max_chars=3000,
        )
        if not context.strip():
            continue

        result = run_skill(skill, context, llm_fn)
        results.append(result)

    return results


def format_skill_results(results: list[SkillResult]) -> str:
    """将 Skill 结果格式化为可注入 prompt 的文本段。"""
    if not results:
        return ""
    parts = ["## Skills 智能判定\n"]
    parts.append("以下是各专家 Skill 对规则命中片段的深度判定，请在最终总结时参考：\n")
    for r in results:
        verdict_tag = r.verdict or "未知"
        conf = f"（置信度：{r.confidence}）" if r.confidence else ""
        parts.append(f"### {r.skill_name} [{verdict_tag}]{conf}")
        if r.finding:
            parts.append(f"关键发现：{r.finding}")
        if r.suggestion:
            parts.append(f"建议：{r.suggestion}")
        parts.append("")
    return "\n".join(parts)
