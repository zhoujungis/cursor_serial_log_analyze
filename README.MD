# 说明
## 基于大模型的串口日志分析Agent
## 可持续学习已判别的结果提高准确度

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

