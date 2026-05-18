# AGENTS.md

## Cursor Cloud specific instructions

### Overview

This is a Python application for serial port log analysis using LLM (Cursor Cloud Agents API). It has:
- **Desktop GUI** (`desktop_serial_log_analyzer.py`) — tkinter-based, requires X11/display
- **Flask Web Server** (`web_server.py`) — headless-friendly, runs on port 5000
- **Online Serial Agent** (`main.py`) — requires physical serial hardware

For Cloud Agent development, use the **Flask web server** (`python3 web_server.py --no-browser --port 5000`).

### Running the web server

```
python3 web_server.py --no-browser --port 5000
```

The server listens on `0.0.0.0:5000`. Key endpoints:
- `GET /` — Web UI (static/index.html)
- `GET /api/about` — Version info
- `GET /api/rules` — List alert rules
- `POST /api/rules` — Add custom rule
- `POST /api/analyze` — Upload log file + analyze (requires CURSOR_API_KEY)
- `GET /api/config` — Current environment config

### Linting

```
python3 -m flake8 --max-line-length=120 *.py
```

The existing codebase has minor style issues (E231, E302, E501) that are pre-existing and should not be fixed unless specifically requested.

### Key notes

- **No automated test suite exists** — validation is done via API endpoint testing and manual interaction.
- **PostgreSQL is optional** — the app gracefully handles missing DB. DB features (bug persistence, learning context) fail silently.
- **CURSOR_API_KEY is required** for LLM-powered analysis. Without it, only local rule-scanning works. The `/api/analyze` endpoint will progress through file reading and rule scanning but fail at the Cloud API call step.
- **tkinter** (`python3-tk`) must be installed for the desktop GUI; the web server does NOT need a display but still imports tkinter transitively.
- **torch** is a heavy dependency (~2GB) used only by `main.py` for LSTM anomaly detection. It's included in `requirements.txt` and installs the CPU version by default.
