"""Session API endpoints."""

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ...database import get_db
from ...models import Message, Session

router = APIRouter()


class SessionResponse(BaseModel):
    """Session response model."""

    session_id: str
    first_seen_at: datetime
    last_activity_at: datetime | None
    cwd: str | None
    current_model_provider: str | None
    current_model_name: str | None
    total_runs: int
    total_tokens: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class SessionListResponse(BaseModel):
    """Session list response."""

    sessions: list[SessionResponse]
    total: int
    page: int
    page_size: int


@router.get("/", response_model=SessionListResponse)
async def list_sessions(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    db: AsyncSession = Depends(get_db),
):
    """List all sessions with pagination."""
    
    # Count total
    count_stmt = select(func.count()).select_from(Session)
    total_result = await db.execute(count_stmt)
    total = total_result.scalar_one()
    
    # Get sessions
    offset = (page - 1) * page_size
    stmt = (
        select(Session)
        .order_by(Session.last_activity_at.desc())
        .offset(offset)
        .limit(page_size)
    )
    result = await db.execute(stmt)
    sessions = result.scalars().all()
    
    # Get run counts and token counts for each session
    session_responses = []
    for session in sessions:
        # Count messages
        message_count_stmt = select(func.count(Message.id)).where(Message.session_id == session.session_id)
        message_count_result = await db.execute(message_count_stmt)
        message_count = message_count_result.scalar_one() or 0
        
        # Sum tokens (from assistant messages)
        token_sum_stmt = select(func.sum(Message.total_tokens)).where(
            Message.session_id == session.session_id,
            Message.role == "assistant"
        )
        token_sum_result = await db.execute(token_sum_stmt)
        token_sum = token_sum_result.scalar_one() or 0
        
        session_responses.append(
            SessionResponse(
                session_id=session.session_id,
                first_seen_at=session.first_seen_at,
                last_activity_at=session.last_activity_at,
                cwd=session.cwd,
                current_model_provider=session.current_model_provider,
                current_model_name=session.current_model_name,
                total_runs=message_count,
                total_tokens=token_sum,
                created_at=session.created_at,
                updated_at=session.updated_at,
            )
        )
    
    return SessionListResponse(
        sessions=session_responses,
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{session_id}", response_model=SessionResponse)
async def get_session(
    session_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get a specific session by ID."""
    
    stmt = select(Session).where(Session.session_id == session_id)
    result = await db.execute(stmt)
    session = result.scalar_one_or_none()
    
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    # Get message count and token sum
    message_count_stmt = select(func.count(Message.id)).where(Message.session_id == session_id)
    message_count_result = await db.execute(message_count_stmt)
    message_count = message_count_result.scalar_one() or 0
    
    token_sum_stmt = select(func.sum(Message.total_tokens)).where(
        Message.session_id == session_id,
        Message.role == "assistant"
    )
    token_sum_result = await db.execute(token_sum_stmt)
    token_sum = token_sum_result.scalar_one() or 0
    
    return SessionResponse(
        session_id=session.session_id,
        first_seen_at=session.first_seen_at,
        last_activity_at=session.last_activity_at,
        cwd=session.cwd,
        current_model_provider=session.current_model_provider,
        current_model_name=session.current_model_name,
        total_runs=run_count,
        total_tokens=token_sum,
        created_at=session.created_at,
        updated_at=session.updated_at,
    )


@router.delete("/{session_id}")
async def delete_session(
    session_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Delete a session and all associated data."""
    
    stmt = select(Session).where(Session.session_id == session_id)
    result = await db.execute(stmt)
    session = result.scalar_one_or_none()
    
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    # Delete associated runs (cascade should handle tool_calls)
    await db.delete(session)
    await db.commit()
    
    return {"message": f"Session {session_id} deleted successfully"}
