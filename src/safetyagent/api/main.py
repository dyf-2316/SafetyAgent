"""Main FastAPI application."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from ..config import settings
from ..database import close_db, init_db
from ..services.message_sync_service import MessageSyncService
from .routes import messages, sessions, stats, tool_calls


# Global sync service instance
message_sync_service: MessageSyncService | None = None


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """
    Application lifespan manager.
    
    Handles startup and shutdown events.
    """
    global message_sync_service
    
    # Startup
    print("🚀 Starting SafetyAgent Application...")
    
    # Initialize database
    await init_db()
    print("✅ Database initialized")
    
    # Start Message-based sync service
    if settings.enable_file_watcher:
        message_sync_service = MessageSyncService()
        await message_sync_service.start()
    else:
        print("⚠️  File watcher disabled")
    
    print(f"✅ API server ready at http://{settings.api_host}:{settings.api_port}")
    
    yield
    
    # Shutdown
    print("🛑 Shutting down SafetyAgent Application...")
    
    if message_sync_service:
        await message_sync_service.stop()
    
    await close_db()
    print("✅ Shutdown complete")


# Create FastAPI app
app = FastAPI(
    title="SafetyAgent API",
    description="Real-time monitoring and analytics system for OpenClaw AI agents",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(sessions.router, prefix="/api/sessions", tags=["Sessions"])
app.include_router(messages.router, prefix="/api/messages", tags=["Messages"])
app.include_router(tool_calls.router, prefix="/api/tool-calls", tags=["Tool Calls"])
app.include_router(stats.router, prefix="/api/stats", tags=["Statistics"])


@app.get("/", tags=["Root"])
async def root():
    """Root endpoint."""
    return {
        "name": "SAS - SafetyAgent Scaffold",
        "version": "0.2.0",  # Bumped for Message-based schema
        "status": "running",
        "message_sync_service_running": message_sync_service.is_running() if message_sync_service else False,
        "schema": "message-based",  # New schema indicator
    }


@app.get("/health", tags=["Health"])
async def health():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "database": "connected",
        "message_sync_service": "running" if (message_sync_service and message_sync_service.is_running()) else "stopped",
    }


def get_message_sync_service() -> MessageSyncService | None:
    """Get the global message sync service instance."""
    return message_sync_service
