"""API routes for Red Team automation."""

import asyncio
import json
import uuid
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from ...gateway_client import GatewayClient

router = APIRouter()

# --------------- Data file path ---------------
_DATA_FILE = Path(__file__).resolve().parents[4] / "external" / "RedWork" / "data" / "generate" / "decomposed_epoch1.jsonl"

# --------------- Cache ---------------
_records: list[dict] | None = None

# --------------- Gateway sessions ---------------
# { session_id: GatewayClient }
_gateway_sessions: dict[str, GatewayClient] = {}


def _load_records() -> list[dict]:
    """Load and cache all records from the JSONL file."""
    global _records
    if _records is not None:
        return _records

    if not _DATA_FILE.exists():
        raise HTTPException(status_code=500, detail=f"Data file not found: {_DATA_FILE}")

    records = []
    for line in _DATA_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
            records.append(rec)
        except json.JSONDecodeError:
            continue

    _records = records
    return _records


# --------------- Pydantic Schemas ---------------

class InstructionItem(BaseModel):
    record_id: str
    instruction: str


class TurnItem(BaseModel):
    thought: str
    output: str


class DecomposedResult(BaseModel):
    record_id: str
    instruction: str
    name: str
    description: str
    risk_type: str
    turns: list[TurnItem]


class GenerateRequest(BaseModel):
    record_id: str = Field(..., description="The record_id to generate attack from")


class StartSessionResponse(BaseModel):
    session_key: str
    status: str = "connected"


class SendMessageRequest(BaseModel):
    session_key: str = Field(..., description="Gateway session key")
    message: str = Field(..., description="Message to send to the agent")


class SendMessageResponse(BaseModel):
    run_id: str
    state: str
    response_text: str
    usage: dict | None = None
    stop_reason: str | None = None


class ExecuteTurnRequest(BaseModel):
    session_key: str = Field(..., description="Gateway session key for this red team run")
    message: str = Field(..., description="The turn output to send")


class ExecuteTurnResponse(BaseModel):
    turn_index: int | None = None
    output: str
    status: str = "sent"
    agent_reply: str = ""
    run_id: str = ""
    state: str = ""


# --------------- Endpoints ---------------

@router.get("/instructions", response_model=list[InstructionItem])
async def list_instructions():
    """List all available red team instructions for selection."""
    records = _load_records()
    return [
        InstructionItem(record_id=r["record_id"], instruction=r["instruction"])
        for r in records
    ]


@router.post("/generate", response_model=DecomposedResult)
async def generate_attack(request: GenerateRequest):
    """
    Generate decomposed multi-turn attack from an instruction.

    Currently reads from the JSONL file and simulates 2-4s generation delay.
    """
    records = _load_records()
    rec = next((r for r in records if r["record_id"] == request.record_id), None)
    if rec is None:
        raise HTTPException(status_code=404, detail=f"Record {request.record_id} not found")

    # Simulate generation delay
    await asyncio.sleep(3)

    # Parse the decomposed query
    decomposed_raw = rec.get("deomposed_query", "")
    try:
        decomposed = json.loads(decomposed_raw) if isinstance(decomposed_raw, str) else decomposed_raw
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="Failed to parse decomposed_query")

    turns = [
        TurnItem(thought=t.get("thought", ""), output=t.get("output", ""))
        for t in decomposed.get("turns", [])
    ]

    return DecomposedResult(
        record_id=rec["record_id"],
        instruction=rec["instruction"],
        name=decomposed.get("name", ""),
        description=decomposed.get("description", ""),
        risk_type=decomposed.get("risk_type", ""),
        turns=turns,
    )


@router.post("/start-session", response_model=StartSessionResponse)
async def start_session():
    """
    Create a new OpenClaw gateway session for red team testing.
    
    Returns a session_key that can be used for subsequent send-message calls.
    """
    session_key = f"redteam-{uuid.uuid4().hex[:12]}"

    client = GatewayClient()
    try:
        await client.connect()
    except Exception as e:
        raise HTTPException(
            status_code=503,
            detail=f"Failed to connect to OpenClaw gateway: {str(e)}. Make sure the gateway is running.",
        )

    _gateway_sessions[session_key] = client

    return StartSessionResponse(session_key=session_key, status="connected")


@router.post("/send-message", response_model=SendMessageResponse)
async def send_message(request: SendMessageRequest):
    """
    Send a message to the agent via the OpenClaw gateway and wait for the response.
    """
    client = _gateway_sessions.get(request.session_key)
    if not client:
        # Try to create a new connection for this session
        client = GatewayClient()
        try:
            await client.connect()
        except Exception as e:
            raise HTTPException(
                status_code=503,
                detail=f"Failed to connect to OpenClaw gateway: {str(e)}",
            )
        _gateway_sessions[request.session_key] = client

    try:
        result = await client.send_chat(
            session_key=request.session_key,
            message=request.message,
            timeout_ms=120_000,
        )
        return SendMessageResponse(
            run_id=result.get("run_id", ""),
            state=result.get("state", "unknown"),
            response_text=result.get("response_text", ""),
            usage=result.get("usage"),
            stop_reason=result.get("stop_reason"),
        )
    except asyncio.TimeoutError:
        return SendMessageResponse(
            run_id="",
            state="timeout",
            response_text="[Timeout] Agent did not respond within 120 seconds.",
        )
    except Exception as e:
        return SendMessageResponse(
            run_id="",
            state="error",
            response_text=f"[Error] {str(e)}",
        )


@router.post("/close-session")
async def close_session(session_key: str = Query(..., description="Session key to close")):
    """Close an OpenClaw gateway session."""
    client = _gateway_sessions.pop(session_key, None)
    if client:
        try:
            await client.disconnect()
        except Exception:
            pass
    return {"status": "closed", "session_key": session_key}
