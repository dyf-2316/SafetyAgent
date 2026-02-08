# SafetyAgent (SafetyAgent)

<div align="center">

**Real-time Monitoring and Analytics System for OpenClaw AI Agents**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.109+-green.svg)](https://fastapi.tiangolo.com/)
[![SQLAlchemy](https://img.shields.io/badge/SQLAlchemy-2.0+-red.svg)](https://www.sqlalchemy.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

</div>

---

## 📖 Overview

SafetyAgent is a comprehensive monitoring and analytics platform designed for OpenClaw AI agents. It automatically tracks agent sessions, parses JSONL entry files, stores structured data in PostgreSQL, and provides a RESTful API for querying agent activities, tool calls, and performance metrics.

### Key Capabilities

- 🔍 **Real-time Session Monitoring** - Automatically watches and parses OpenClaw session JSONL files
- 💬 **Message Tracking** - Records all user, assistant, and toolResult messages with complete metadata
- 🛠️ **Tool Call Analytics** - Tracks tool invocations, arguments, results, and execution times
- 📊 **Token Usage Statistics** - Monitors input/output tokens, cache hits, and costs per model
- 🔗 **Relationship Mapping** - Links messages, tool calls, and session hierarchies
- 🚀 **High Performance** - Async/await architecture with incremental file parsing
- 🗄️ **Flexible Storage** - Supports both PostgreSQL (production) and SQLite (development)
- 📡 **REST API** - FastAPI-powered endpoints with automatic OpenAPI documentation

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    OpenClaw Agent Runtime                    │
│  ~/.openclaw/agents/main/sessions/*.jsonl                   │
└────────────────────┬────────────────────────────────────────┘
                     │ JSONL Entries
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                      SafetyAgent Monitoring System                   │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │ File Watcher│─▶│ JSONL Parser │─▶│ Sync Service     │   │
│  └─────────────┘  └──────────────┘  └────────┬─────────┘   │
│                                                │             │
│                                                ▼             │
│                                      ┌──────────────────┐   │
│                                      │   PostgreSQL     │   │
│                                      │  (Sessions DB)   │   │
│                                      └────────┬─────────┘   │
│                                                │             │
│                                                ▼             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              FastAPI REST API                       │   │
│  │  /sessions  /messages  /tool-calls  /stats         │   │
│  └─────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────┘
                     │ HTTP/JSON
                     ▼
              Frontend / Analytics Tools
```

---

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- PostgreSQL 16+ (or use included Docker Compose)
- [uv](https://github.com/astral-sh/uv) (recommended) or pip

### 1. Clone and Install

```bash
git clone <repository-url>
cd SafetyAgent

# Install dependencies with uv (recommended)
uv sync

# Or with pip
pip install -e .
```

### 2. Start PostgreSQL

```bash
# Using Docker Compose (recommended)
docker-compose up -d postgres

# Check status
docker-compose ps

# View logs
docker-compose logs -f postgres
```

The PostgreSQL instance will be available at `localhost:5434` (avoiding conflicts with default 5432).

### 3. Configure Environment

```bash
cp .env.example .env

# Edit .env to match your setup
nano .env
```

Key configuration options:

```bash
DATABASE_URL=postgresql+asyncpg://sas:safetyagent_password@localhost:5434/sas
OPENCLAW_SESSIONS_DIR=~/.openclaw/agents/main/sessions
API_PORT=6874
ENABLE_FILE_WATCHER=true
LOG_LEVEL=INFO
```

### 4. Initialize Database

```bash
source .venv/bin/activate  # if using venv
python scripts/init_db.py
```

This creates all necessary tables: `sessions`, `messages`, `tool_calls`.

### 5. Import Existing Sessions (Optional)

```bash
python scripts/import_existing.py
```

This performs a full scan of existing JSONL files and imports historical data.

### 6. Start the Application

```bash
# Method 1: Using run.py (recommended)
python run.py

# Method 2: As a module
python -m sas

# Method 3: Direct uvicorn
uvicorn sas.api.main:app --host 0.0.0.0 --port 6874 --reload
```

### 7. Access the API

- **API Documentation**: http://localhost:6874/docs
- **Alternative Docs**: http://localhost:6874/redoc
- **Health Check**: http://localhost:6874/health
- **Root**: http://localhost:6874/

---

## 📂 Project Structure

```
SafetyAgent/
├── src/sas/
│   ├── models/                 # SQLAlchemy ORM models
│   │   ├── base.py            # Base model with timestamps
│   │   ├── session.py         # Session tracking
│   │   ├── message.py         # User/assistant/toolResult messages
│   │   └── tool_call.py       # Tool invocation records
│   ├── parsers/               # JSONL parsing logic
│   │   └── jsonl_parser.py    # Entry parser with NULL byte handling
│   ├── watchers/              # File system monitoring
│   │   └── file_watcher.py    # Watchdog-based file watcher
│   ├── services/              # Business logic layer
│   │   └── message_sync_service.py  # Core sync engine
│   ├── api/                   # FastAPI application
│   │   ├── main.py           # App entry point
│   │   └── routes/           # API endpoints
│   │       ├── sessions.py   # Session management
│   │       ├── messages.py   # Message queries
│   │       ├── tool_calls.py # Tool call analytics
│   │       └── stats.py      # Statistics & aggregations
│   ├── config.py             # Pydantic settings
│   └── database.py           # Database connection & initialization
├── scripts/
│   ├── init_db.py            # Database schema initialization
│   └── import_existing.py    # Batch import utility
├── docker-compose.yml        # PostgreSQL container
├── pyproject.toml           # Dependencies & build config
├── .env.example             # Environment template
├── run.py                   # Application launcher
└── README.md               # This file
```

---

## 📡 API Reference

### Sessions

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/sessions/` | GET | List all sessions with pagination |
| `/api/sessions/{session_id}` | GET | Get session details with stats |
| `/api/sessions/{session_id}` | DELETE | Soft delete a session |

**Query Parameters:**
- `skip`: Pagination offset (default: 0)
- `limit`: Results per page (default: 100, max: 1000)

**Example:**
```bash
curl http://localhost:6874/api/sessions/?limit=10
```

### Messages

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/messages/` | GET | List messages with filters |
| `/api/messages/{message_id}` | GET | Get message details |
| `/api/messages/{message_id}/children` | GET | Get child messages |
| `/api/messages/stats/by-role` | GET | Message statistics by role |

**Query Parameters:**
- `session_id`: Filter by session
- `role`: Filter by role (user/assistant/toolResult)
- `skip`, `limit`: Pagination

**Example:**
```bash
# Get all assistant messages
curl http://localhost:6874/api/messages/?role=assistant

# Get messages for a specific session
curl http://localhost:6874/api/messages/?session_id=abc-123
```

### Tool Calls

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/tool-calls/` | GET | List tool calls with filters |
| `/api/tool-calls/{tool_call_id}` | GET | Get tool call details |
| `/api/tool-calls/stats/by-tool` | GET | Statistics grouped by tool name |

**Query Parameters:**
- `session_id`: Filter by session
- `tool_name`: Filter by tool type (e.g., "read", "exec")
- `status`: Filter by status (running/completed/failed)
- `skip`, `limit`: Pagination

**Example:**
```bash
# Get all exec tool calls
curl http://localhost:6874/api/tool-calls/?tool_name=exec

# Get failed tool calls
curl http://localhost:6874/api/tool-calls/?status=failed
```

### Statistics

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/stats/overview` | GET | Overall system statistics |
| `/api/stats/by-model` | GET | Token usage by model |
| `/api/stats/daily` | GET | Daily activity statistics |

**Example:**
```bash
# Get overall stats
curl http://localhost:6874/api/stats/overview

# Get last 7 days
curl http://localhost:6874/api/stats/daily?days=7
```

---

## 🗄️ Database Schema

### Sessions Table

Tracks OpenClaw agent sessions.

```sql
CREATE TABLE sessions (
    session_id VARCHAR(36) PRIMARY KEY,      -- UUID from JSONL
    session_key VARCHAR(255) UNIQUE,         -- User-friendly key
    agent_id VARCHAR(64) DEFAULT 'main',
    channel VARCHAR(64),                      -- messaging/cli/api
    first_seen_at TIMESTAMP NOT NULL,
    last_activity_at TIMESTAMP,
    current_model_provider VARCHAR(64),       -- e.g., "anthropic"
    current_model_name VARCHAR(128),          -- e.g., "claude-3-5-sonnet"
    jsonl_file_path TEXT,
    last_read_position INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
```

### Messages Table

Stores all messages (user, assistant, toolResult).

```sql
CREATE TABLE messages (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(36) REFERENCES sessions(session_id),
    message_id VARCHAR(36) UNIQUE NOT NULL,   -- Message ID from JSONL
    parent_message_id VARCHAR(36),            -- Parent for threading
    role VARCHAR(32) NOT NULL,                -- user/assistant/toolResult
    timestamp TIMESTAMP NOT NULL,
    content_text TEXT,
    content_json JSONB,                       -- Full content structure
    provider VARCHAR(64),                     -- Model provider
    model_id VARCHAR(128),                    -- Model name
    input_tokens INTEGER,
    output_tokens INTEGER,
    cache_read_tokens INTEGER,
    cache_write_tokens INTEGER,
    total_tokens INTEGER,
    stop_reason VARCHAR(64),
    raw_entry JSONB NOT NULL,                 -- Full JSONL entry
    created_at TIMESTAMP DEFAULT NOW()
);
```

### Tool Calls Table

Tracks tool invocations and results.

```sql
CREATE TABLE tool_calls (
    id VARCHAR(64) PRIMARY KEY,               -- Tool call ID from JSONL
    message_id INTEGER REFERENCES messages(id),
    initiating_message_id VARCHAR(36),        -- Assistant message that called tool
    result_message_id VARCHAR(36),            -- ToolResult message
    tool_name VARCHAR(64) NOT NULL,
    arguments JSON,
    started_at TIMESTAMP NOT NULL,
    completed_at TIMESTAMP,
    duration_seconds FLOAT,
    result_text TEXT,
    result_json JSONB,
    is_error BOOLEAN DEFAULT FALSE,
    error_message TEXT,
    exit_code INTEGER,
    status VARCHAR(32) DEFAULT 'running',
    created_at TIMESTAMP DEFAULT NOW()
);
```

---

## 🔧 Configuration Reference

All configuration is done via environment variables (`.env` file):

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgresql+asyncpg://...` | Database connection string |
| `OPENCLAW_SESSIONS_DIR` | `~/.openclaw/agents/main/sessions` | Path to JSONL files |
| `API_HOST` | `0.0.0.0` | API server bind address |
| `API_PORT` | `6874` | API server port |
| `API_RELOAD` | `true` | Auto-reload on code changes |
| `LOG_LEVEL` | `INFO` | Logging level (DEBUG/INFO/WARNING/ERROR) |
| `ENABLE_FILE_WATCHER` | `true` | Enable real-time file watching |
| `WATCH_INTERVAL_SECONDS` | `1` | File check interval |
| `FULL_SCAN_INTERVAL_HOURS` | `1` | Full directory scan interval |
| `BATCH_SIZE` | `100` | Database batch insert size |
| `CORS_ORIGINS` | `["http://localhost:3000"]` | Allowed CORS origins |

---

## 🛠️ Development

### Running Tests

```bash
# Install dev dependencies
uv sync --dev

# Run all tests
pytest

# Run with coverage
pytest --cov=sas --cov-report=html

# Run specific test file
pytest tests/test_jsonl_parser.py -v
```

### Code Quality

```bash
# Format code
black src/

# Lint
ruff check src/

# Type checking
mypy src/
```

### Database Management

```bash
# Connect to PostgreSQL
docker exec -it safetyagent-postgres psql -U sas -d sas

# Common SQL commands
\dt                              # List tables
\d+ sessions                     # Describe table
SELECT COUNT(*) FROM messages;   # Count records
\q                              # Quit

# Backup database
docker exec safetyagent-postgres pg_dump -U sas sas > backup.sql

# Restore database
cat backup.sql | docker exec -i safetyagent-postgres psql -U sas -d sas
```

### Adding New Migrations

```bash
# Generate migration (if using Alembic in future)
alembic revision --autogenerate -m "Add new field"

# Apply migrations
alembic upgrade head
```

---

## 🐛 Troubleshooting

### Database Connection Issues

```bash
# Check if PostgreSQL is running
docker-compose ps

# View PostgreSQL logs
docker-compose logs postgres

# Test connection
psql "postgresql://sas:safetyagent_password@localhost:5434/sas" -c "SELECT 1"
```

### File Watcher Not Working

- Check `OPENCLAW_SESSIONS_DIR` path exists
- Verify file permissions
- Set `LOG_LEVEL=DEBUG` for detailed logs

### NULL Byte Errors

SafetyAgent automatically cleans `\x00` characters from JSONL files (common with binary data in tool results). If you still see errors:

```bash
# Check for NULL bytes in files
grep -Pa '\x00' ~/.openclaw/agents/main/sessions/*.jsonl
```

### Import Script Hanging

- Check database connection
- Verify JSONL files are valid JSON
- Monitor logs: `LOG_LEVEL=DEBUG python scripts/import_existing.py`

---

## 🔒 Security Considerations

- **Database Access**: Change default PostgreSQL credentials in production
- **API Authentication**: Currently no auth - add JWT/OAuth before exposing publicly
- **CORS**: Restrict `CORS_ORIGINS` to trusted domains only
- **Data Sanitization**: NULL bytes and malicious content are automatically cleaned
- **File Permissions**: Ensure JSONL directory has appropriate read permissions

---

## 🚀 Performance Tips

- **PostgreSQL**: For large datasets (>1M messages), add custom indexes:
  ```sql
  CREATE INDEX idx_messages_timestamp ON messages(timestamp DESC);
  CREATE INDEX idx_tool_calls_tool_name ON tool_calls(tool_name, started_at DESC);
  ```

- **Batch Size**: Adjust `BATCH_SIZE` based on your system (100-1000)

- **Watch Interval**: Increase `WATCH_INTERVAL_SECONDS` to reduce CPU usage

- **Connection Pool**: SQLAlchemy defaults are usually sufficient, but can be tuned in `database.py`

---

## 🗺️ Roadmap

- [ ] WebSocket support for real-time updates
- [ ] Advanced analytics dashboard (React frontend)
- [ ] Token cost estimation per session
- [ ] Export sessions to various formats (CSV, JSON, Markdown)
- [ ] Plugin system for custom parsers
- [ ] Alembic migrations for schema versioning
- [ ] Multi-agent comparison tools
- [ ] Integration with OpenClaw plugin system

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- [OpenClaw](https://github.com/openclaw/openclaw) - The AI agent framework this monitors
- [FastAPI](https://fastapi.tiangolo.com/) - Modern web framework
- [SQLAlchemy](https://www.sqlalchemy.org/) - Powerful ORM
- [Watchdog](https://github.com/gorakhargosh/watchdog) - File system monitoring

---

<div align="center">

**Made with ❤️ for the OpenClaw community**

[Report Bug](https://github.com/yourusername/SafetyAgent/issues) · [Request Feature](https://github.com/yourusername/SafetyAgent/issues)

</div>
