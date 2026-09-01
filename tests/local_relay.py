import asyncio
import json
import socket
from collections.abc import Awaitable
from typing import Any

import websockets


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class LocalNostrRelay:
    """Small in-process relay for transport and implementation tests."""

    def __init__(self, port: int | None = None) -> None:
        self.port = port or free_port()
        self.url = f"ws://127.0.0.1:{self.port}"
        self.events: list[dict[str, Any]] = []
        self._subscriptions: dict[Any, dict[str, list[dict[str, Any]]]] = {}
        self._server: Any = None

    async def __aenter__(self) -> "LocalNostrRelay":
        return await self.start()

    async def __aexit__(self, *_args: object) -> None:
        await self.stop()

    async def start(self) -> "LocalNostrRelay":
        if self._server is not None:
            return self
        self._server = await websockets.serve(self._handle, "127.0.0.1", self.port)
        return self

    async def stop(self) -> None:
        if self._server is None:
            return
        self._server.close()
        await self._server.wait_closed()
        self._server = None

    def has_subscription(self, subscription_id: str, recipient: str) -> bool:
        for subscriptions in self._subscriptions.values():
            for current_id, filters in subscriptions.items():
                if current_id != subscription_id:
                    continue
                if any(recipient in item.get("#p", []) for item in filters):
                    return True
        return False

    def has_recipient_subscription(self, recipient: str) -> bool:
        return any(
            recipient in item.get("#p", [])
            for subscriptions in self._subscriptions.values()
            for filters in subscriptions.values()
            for item in filters
        )

    async def _handle(self, websocket: Any) -> None:
        self._subscriptions[websocket] = {}
        try:
            async for raw in websocket:
                message = json.loads(raw)
                if not isinstance(message, list) or not message:
                    continue
                if message[0] == "REQ" and len(message) >= 3:
                    subscription_id = str(message[1])
                    filters = [item for item in message[2:] if isinstance(item, dict)]
                    self._subscriptions[websocket][subscription_id] = filters
                    await websocket.send(json.dumps(["EOSE", subscription_id]))
                elif message[0] == "CLOSE" and len(message) == 2:
                    self._subscriptions[websocket].pop(str(message[1]), None)
                elif message[0] == "EVENT" and len(message) == 2:
                    event = message[1]
                    if not isinstance(event, dict):
                        continue
                    self.events.append(event)
                    await websocket.send(json.dumps(["OK", event.get("id", ""), True, ""]))
                    await self._broadcast(event)
        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            self._subscriptions.pop(websocket, None)

    async def _broadcast(self, event: dict[str, Any]) -> None:
        deliveries: list[Awaitable[None]] = []
        for websocket, subscriptions in list(self._subscriptions.items()):
            for subscription_id, filters in list(subscriptions.items()):
                if any(self._matches(event, item) for item in filters):
                    deliveries.append(websocket.send(json.dumps(["EVENT", subscription_id, event])))
        if deliveries:
            await asyncio.gather(*deliveries, return_exceptions=True)

    @staticmethod
    def _matches(event: dict[str, Any], item: dict[str, Any]) -> bool:
        kinds = item.get("kinds")
        if kinds is not None and event.get("kind") not in kinds:
            return False
        recipients = item.get("#p")
        if recipients is not None:
            event_recipients = {
                tag[1]
                for tag in event.get("tags", [])
                if isinstance(tag, list) and len(tag) >= 2 and tag[0] == "p"
            }
            if not event_recipients.intersection(recipients):
                return False
        return True
