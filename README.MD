# 说明
## 基于大模型的串口日志分析Agent
## 持续学习已判别的结果提高准确度

  读取文件 (5%)
    │
  规范化换行 (10%)
t   │
  Cloud 清洗先行 (15% → 25%)           ✗
    │
    ├─ 并行线 A ───────────┐
    │  规则扫描 (30%)       │  LLM 上下文检测 (30%)
    │  Skills 智能判定 (35%) │  日志概况 · 异常模式
    │  命中摘要 + 专家判定   │  关键事件时间线
    │                       │  关联分析 · 风险 TOP3
    │                       │
    ├─ 并行线 B ───────────┘
    │
  合并阶段 (50% → 70%)
    解析异常行 · 历史学习 · 用户侧重点
    Cloud 清洗 + 规则命中 + Skills 判定 + LLM 上下文检测
    ↓
  AI Agent 最终总结 (80%)
    ↓
  保存 Bug 入库 (95%)
    ↓
  完成 (100%)

# 安装依赖

```text
pip install -r requirements.txt
```

# 桌面分析

```text
python desktop_serial_log_analyzer.py
```

菜单「文件 → 打开…」选择 `.log` / `.txt`，配置规则与 Cursor 环境变量（见 `.env`：`CURSOR_API_KEY`、`CURSOR_GITHUB_REPO` 等）。

# Web端 Agent（可选）

```text
python web_server.py
localhost:5000
```

