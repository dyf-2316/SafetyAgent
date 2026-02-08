#!/usr/bin/env python
"""Script to import existing OpenClaw session files into the database."""

import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from safetyagent.config import settings
from safetyagent.database import init_db
from safetyagent.services.message_sync_service import MessageSyncService


async def main():
    """Import all existing session files."""
    print("📥 Importing existing session files...")
    
    # Initialize database
    await init_db()
    
    # Create sync service
    sync_service = MessageSyncService()
    
    # Manually trigger initial scan
    sessions_dir = settings.OPENCLAW_SESSIONS_DIR
    print(f"📂 Scanning: {sessions_dir}")
    
    await sync_service._initial_scan()
    
    print("✅ Import completed successfully!")


if __name__ == "__main__":
    asyncio.run(main())
