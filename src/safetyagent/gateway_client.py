"""
OpenClaw Gateway WebSocket client for Python.

Connects to the local OpenClaw gateway, sends chat messages,
and collects the agent's response (streamed deltas → final).
"""

import asyncio
import json
import uuid
from pathlib import Path
from typing import Any


async def _load_gateway_config() -> dict:
    """Load gateway config from ~/.openclaw/openclaw.json."""
    config_path = Path.home() / ".openclaw" / "openclaw.json"
    if not config_path.exists():
        return {}
    text = config_path.read_text(encoding="utf-8")
    return json.loads(text).get("gateway", {})


class GatewayClient:
    """Lightweight async WebSocket client for the OpenClaw gateway."""

    def __init__(self, url: str | None = None, token: str | None = None):
        self._url = url
        self._token = token
        self._ws: Any = None
        self._pending: dict[str, asyncio.Future] = {}
        self._event_handlers: list = []
        self._connected = asyncio.Event()
        self._reader_task: asyncio.Task | None = None

    async def connect(self) -> None:
        """Connect to the gateway and complete the handshake."""
        import websockets

        # Resolve connection params
        if not self._url or not self._token:
            cfg = await _load_gateway_config()
            if not self._url:
                port = cfg.get("port", 18789)
                self._url = f"ws://127.0.0.1:{port}"
            if not self._token:
                auth = cfg.get("auth", {})
                self._token = auth.get("token")

        self._ws = await websockets.connect(
            self._url,
            max_size=25 * 1024 * 1024,
            close_timeout=5,
        )
        self._reader_task = asyncio.create_task(self._read_loop())

        # Wait for connect.challenge or timeout → send connect
        try:
            await asyncio.wait_for(self._connected.wait(), timeout=2.0)
        except asyncio.TimeoutError:
            # No challenge received, send connect directly
            await self._send_connect(nonce=None)
            await asyncio.wait_for(self._connected.wait(), timeout=5.0)

    async def disconnect(self) -> None:
        """Close the WebSocket connection."""
        if self._reader_task:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except (asyncio.CancelledError, Exception):
                pass
        if self._ws:
            await self._ws.close()
            self._ws = None

    async def _send_connect(self, nonce: str | None = None) -> None:
        """Send the connect handshake frame."""
        params: dict[str, Any] = {
            "minProtocol": 3,
            "maxProtocol": 3,
            "client": {
                "id": "gateway-client",
                "displayName": "SafetyAgent RedTeam",
                "version": "1.0.0",
                "platform": "linux",
                "mode": "ui",
                "instanceId": str(uuid.uuid4()),
            },
            "caps": [],
            "role": "operator",
            "scopes": ["operator.admin"],
        }
        if self._token:
            params["auth"] = {"token": self._token}

        await self._request("connect", params, is_connect=True)

    async def _request(self, method: str, params: Any = None, is_connect: bool = False) -> Any:
        """Send a JSON-RPC request and wait for the response."""
        req_id = str(uuid.uuid4())
        frame = {"type": "req", "id": req_id, "method": method, "params": params or {}}

        future: asyncio.Future = asyncio.get_event_loop().create_future()
        self._pending[req_id] = future

        await self._ws.send(json.dumps(frame))
        result = await asyncio.wait_for(future, timeout=30.0)

        if is_connect:
            self._connected.set()

        return result

    async def _read_loop(self) -> None:
        """Background task that reads messages from the WebSocket."""
        try:
            async for raw in self._ws:
                try:
                    msg = json.loads(raw)
                except json.JSONDecodeError:
                    continue

                msg_type = msg.get("type")

                # Event frame (gateway uses "event" not "evt")
                if msg_type == "event":
                    event_name = msg.get("event", "")

                    # Handle connect challenge
                    if event_name == "connect.challenge":
                        payload = msg.get("payload", {})
                        nonce = payload.get("nonce")
                        asyncio.create_task(self._send_connect(nonce=nonce))
                        continue

                    # Dispatch to event handlers
                    for handler in list(self._event_handlers):
                        try:
                            handler(msg)
                        except Exception:
                            pass
                    continue

                # Response frame
                if msg_type == "res":
                    req_id = msg.get("id")
                    future = self._pending.get(req_id)
                    if future and not future.done():
                        # For accepted responses (like chat.send ack), resolve immediately
                        if msg.get("ok"):
                            self._pending.pop(req_id, None)
                            future.set_result(msg.get("payload"))
                        else:
                            self._pending.pop(req_id, None)
                            err_msg = msg.get("error", {}).get("message", "unknown error")
                            future.set_exception(Exception(err_msg))
                    continue

        except asyncio.CancelledError:
            raise
        except Exception:
            pass

    async def send_chat(
        self,
        session_key: str,
        message: str,
        thinking: str | None = None,
        timeout_ms: int | None = None,
    ) -> dict:
        """
        Send a chat message and wait for the complete response.

        1. Register event listener for 'chat' events matching our runId
        2. Send 'chat.send' request (returns {status: "accepted"})
        3. Wait for 'chat' event with state='final'|'aborted'|'error'
        4. Return the collected response
        """
        run_id = str(uuid.uuid4())

        # Accumulate response
        deltas: list[str] = []
        final_event: dict | None = None
        done = asyncio.Event()

        def on_event(evt: dict) -> None:
            nonlocal final_event
            if evt.get("event") != "chat":
                return
            payload = evt.get("payload", {})

            # Match by runId (== our idempotencyKey)
            if payload.get("runId") != run_id:
                return

            state = payload.get("state")
            if state == "delta":
                # Accumulate text deltas
                msg_data = payload.get("message")
                if isinstance(msg_data, dict):
                    content = msg_data.get("content")
                    if isinstance(content, str):
                        deltas.append(content)
                    elif isinstance(content, list):
                        for block in content:
                            if isinstance(block, dict) and block.get("type") == "text":
                                deltas.append(block.get("text", ""))
            elif state in ("final", "aborted", "error"):
                final_event = payload
                done.set()

        self._event_handlers.append(on_event)

        try:
            # Send the chat.send request
            params: dict[str, Any] = {
                "sessionKey": session_key,
                "message": message,
                "idempotencyKey": run_id,
            }
            if thinking:
                params["thinking"] = thinking
            if timeout_ms:
                params["timeoutMs"] = timeout_ms

            # This returns {status: "accepted"} immediately
            await self._request("chat.send", params)

            # Now wait for the final chat event (up to 120s)
            await asyncio.wait_for(done.wait(), timeout=120.0)

            # Extract final message text
            response_text = ""
            if final_event:
                msg_data = final_event.get("message")
                if isinstance(msg_data, dict):
                    content = msg_data.get("content")
                    if isinstance(content, str):
                        response_text = content
                    elif isinstance(content, list):
                        for block in content:
                            if isinstance(block, dict) and block.get("type") == "text":
                                response_text += block.get("text", "")

            # If final didn't have full text, use accumulated deltas
            if not response_text and deltas:
                response_text = "".join(deltas)

            return {
                "run_id": run_id,
                "state": final_event.get("state", "unknown") if final_event else "timeout",
                "response_text": response_text,
                "usage": final_event.get("usage") if final_event else None,
                "stop_reason": final_event.get("stopReason") if final_event else None,
            }

        except asyncio.TimeoutError:
            return {
                "run_id": run_id,
                "state": "timeout",
                "response_text": "".join(deltas) if deltas else "[Timeout] Agent did not respond within 120 seconds.",
                "usage": None,
                "stop_reason": None,
            }

        finally:
            if on_event in self._event_handlers:
                self._event_handlers.remove(on_event)

    async def load_history(self, session_key: str, limit: int = 50) -> list:
        """Load chat history for a session."""
        result = await self._request("chat.history", {
            "sessionKey": session_key,
            "limit": limit,
        })
        if isinstance(result, dict):
            return result.get("messages", [])
        return []
