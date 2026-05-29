# 串口日志智能分析工具

基于大模型（DeepSeek）的设备串口/嵌入式日志自动分析工具，支持**规则扫描 + Skills 专家判定 + LLM 上下文关联**三层分析，结果自动入库并支持人工复核与持续学习。

---

## 分析流水线

```
读取文件 (5%)
  │
规范化换行 (10%)
  │
Cloud 清洗先行 (15% → 25%)        —— DeepSeek 前置去噪、合并心跳日志
  │
  ├─ 并行线 A ───────────────────────┐
  │  规则扫描 (30%)                   │  LLM 上下文检测 (30%)
  │  Skills 智能判定 (35%)            │  日志概况 · 异常模式
  │  命中摘要 + 专家判定              │  关键事件时间线
  │                                   │  关联分析 · 风险 TOP3
  │                                   │
  ├─ 并行线 B ───────────────────────┘
  │
合并阶段 (50% → 70%)
  解析异常行 · 历史学习 · 用户侧重点
  Cloud 清洗 + 规则命中 + Skills 判定 + LLM 上下文检测
  ↓
AI Agent 最终总结 (80%)             —— DeepSeek 生成结构化 Bug 报告
  ↓
保存 Bug 入库 (95%)                 —— PostgreSQL，支持人工判别
  ↓
完成 (100%)
```

---

## 功能模块

| 模块 | 说明 |
|------|------|
| **规则扫描** | 内置 5 类正则规则（崩溃、内存、存储、电源温度、严重级别）对日志逐行匹配 |
| **Skills 智能判定** | 规则命中后自动触发专家 Skill（如 OOM 分析、崩溃分析），由 DeepSeek 对上下文做深度分析并输出结构化判定 |
| **LLM 上下文分析** | 对异常行做时间线关联、风险排序，生成全局视角 |
| **Cloud 清洗** | 调用 DeepSeek 对原始日志节选做去噪和规范重排 |
| **持续学习** | 人工判别结果回写数据库，历史经验自动注入后续分析 |
| **规则导入** | 支持从 Excel/CSV 压测用例表格中由 DeepSeek 自动提取匹配规则 |
| **Bug 管理** | 所有 Bug 存入 PostgreSQL，支持按 待定/确认/误报/忽略 分类筛选和人工审核 |

---

## 项目结构

```
AutoAnalizeLog/
├── main.py                          # 在线 Agent（串口/LSTM 实时检测 + Cursor API 流式分析）
├── desktop_serial_log_analyzer.py   # 桌面 GUI（PyQt6），文件分析入口
├── web_server.py                    # Web 版（Flask），REST API + SSE 流式输出
├── config/
│   ├── .env                         # 环境变量配置（API Key、数据库等）
│   ├── serial_rules_user.json       # 用户自定义正则规则
│   └── cursor_skills_user.json      # 用户自定义 Skills
├── utils/
│   ├── serial_alert_rules.py        # 规则编译与匹配引擎
│   ├── cursor_skills.py             # Skills 管理与调度
│   └── db_manager.py                # PostgreSQL Bug 记录 CRUD
├── bugs/                            # 分析结果 TXT 存档
├── static/                          # Web 前端静态文件
└── requirements.txt
```

---

## 安装依赖

```bash
pip install -r requirements.txt
```

依赖项：`pyserial`、`requests`、`python-dotenv`、`pypdf`、`openpyxl`、`flask`、`psycopg2-binary`、`pyqt6`。

---

## 配置环境变量

编辑 `config/.env`：

```ini
# ── DeepSeek API（必填）──────────────────────
DEEPSEEK_API_KEY=sk-your-key-here
DEEPSEEK_MODEL=deepseek-chat

# ── 材料体量限制（可选，不填用默认值）────────
SUMMARY_MAX_CHARS=90000       # 送 LLM 总结的最大字符数（4000 ~ 240000）
CLEAN_MAX_CHARS=24000         # Cloud 清洗节选长度（1000 ~ 80000）

# ── PostgreSQL（Bug 记录功能需要）────────────
PG_HOST=localhost
PG_PORT=5432
PG_DATABASE=serial_log_analysis
PG_USER=postgres
PG_PASSWORD=admin
```

> PostgreSQL 为可选依赖。未配置时 Bug 入库功能自动跳过，其他功能不受影响。

---

## 使用方式

### 桌面 GUI 分析（推荐）

```bash
python desktop_serial_log_analyzer.py
```

1. 菜单「文件 → 打开…」选择 `.log` / `.txt` / `.pdf` 日志文件
2. （可选）菜单「设置」配置 DeepSeek API Key、清洗 prompt、分析侧重点、材料体量
3. （可选）菜单「规则」管理正则匹配规则，或「从 Excel/CSV 导入规则」由 DeepSeek 自动提取
4. 点击「开始分析」，进度条实时更新
5. 结果区显示 LLM 生成的 Bug 报告，可保存为 TXT
6. 菜单「数据库 → Bug 记录…」查看已入库 Bug，进行人工判别（确认/误报/忽略）

### Web 版（Flask）

```bash
python web_server.py              # 默认 http://127.0.0.1:5000
python web_server.py --port 8080  # 自定义端口
```

- 浏览器自动打开 Web 界面
- 上传日志文件 → 实时 SSE 进度推送 → 查看/下载结果
- REST API 覆盖：配置管理、规则管理、Skills 管理、Bug 记录 CRUD

### 在线 Agent（串口实时监控）

```bash
python main.py
```

- 读取 COM 串口或日志文件，LSTM 模型在线检测异常
- 异常批次自动提交 Cursor Cloud Agent 做 LLM 分析（需配置 `CURSOR_API_KEY` 和 `CURSOR_GITHUB_REPO`）

---

## 内置规则一览

| 优先级 | 类别 | 说明 |
|--------|------|------|
| 1 | crash | 进程崩溃、kernel panic、segfault、hardfault、断言失败 |
| 1 | memory | OOM、malloc 失败、堆栈溢出、内存泄漏 |
| 2 | storage | Flash 擦写失败、文件系统损坏、磁盘满 |
| 2 | power_thermal | 过温、欠压、掉电、thermal shutdown |
| 3 | severity | 严重级别关键字（FATAL / CRITICAL / panic） |

用户可在「规则」菜单中增删自定义规则，或从 Excel/CSV 表格由 DeepSeek 自动提炼。

---

## 内置 Skills 一览

| Skill ID | 名称 | 触发类别 |
|----------|------|----------|
| oom_analysis | OOM / 内存分析 | memory |
| crash_analysis | 崩溃 / Panic 分析 | crash |
| storage_analysis | 存储异常分析 | storage |
| power_thermal_analysis | 电源/温度分析 | power_thermal |

用户可在「Skills」菜单中增删自定义 Skill、启用/禁用工能。

---

## 免责声明

本次分析结果只对本次导入的串口 log 有效；具体结果需由测试人员复现、验证后再作结论。

---

## 作者

zhoujun@glazero.com
