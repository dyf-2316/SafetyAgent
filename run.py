#!/usr/bin/env python3
"""Convenience script to run the SafetyAgent application."""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

import uvicorn

from safetyagent.config import settings

if __name__ == "__main__":
    print("🚀 Starting SafetyAgent Application...")
    print(f"📍 Database: {settings.database_url}")
    print(f"📂 Watching: {settings.openclaw_sessions_dir}")
    print(f"🌐 API: http://{settings.api_host}:{settings.api_port}")
    print()
    
    uvicorn.run(
        "safetyagent.api.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.api_reload,
        log_level=settings.log_level.lower(),
    )
