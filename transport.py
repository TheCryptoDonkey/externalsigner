import asyncio
import ipaddress
import json
import queue
import socket
import threading
from datetime import timedelta
from typing import Any, Protocol, cast
from urllib.parse import urlsplit

from lnbits.settings import settings
from nostr_sdk import (
    Client,
    ClientMessage,
    Filter,
    HandleNotification,
    RelayMessage,
    RelayUrl,
    SubscribeOptions,
    uniffi_set_event_loop,
)


class Nip46Transport(Protocol):
    def reconcile(self, routes: dict[str, list[str]], subscription_id: str) -> None: ...

    def publish(self, event: dict[str, Any], relays: list[str]) -> None: ...

    def take_events(self, subscription_id: str) -> list[dict[str, Any]]: ...

    def close(self) -> None: ...


class _NotificationHandler(HandleNotification):
    def __init__(self, transport: "NostrSdkTransport") -> None:
        self._transport = transport

    async def handle(self, _relay_url: RelayUrl, subscription_id: str, event: Any) -> None:
        try:
            raw = event.as_json() if hasattr(event, "as_json") else str(event)
            decoded = json.loads(raw)
            if isinstance(decoded, dict):
                self._transport.enqueue(subscription_id, decoded)
        except Exception:
            # Invalid relay input is deliberately dropped at this boundary. The
            # protocol layer performs the authoritative signature and recipient
            # checks for every event that reaches it.
            return

    async def handle_msg(self, _relay_url: RelayUrl, _message: RelayMessage) -> None:
        return


class NostrSdkTransport:
    """An isolated, target-aware NIP-46 relay session.

    LNbits already ships ``nostr-sdk``. Using its public per-relay subscription
    and ``send_msg_to`` APIs keeps traffic on only the relays selected for a
    connection and avoids depending on private methods from another extension.
    """

    MAX_QUEUED_EVENTS = 4096

    def __init__(self) -> None:
        self._routes: dict[str, list[str]] = {}
        self._incoming: queue.Queue[tuple[str, dict[str, Any]]] = queue.Queue(
            maxsize=self.MAX_QUEUED_EVENTS
        )
        self._loop_ready = threading.Event()
        self._closed = False
        self._thread = threading.Thread(
            target=self._run_event_loop,
            name="externalsigner-nostr-sdk",
            daemon=True,
        )
        self._thread.start()
        if not self._loop_ready.wait(timeout=10):
            raise RuntimeError("NIP-46 relay runtime did not start.")

    def reconcile(self, routes: dict[str, list[str]], subscription_id: str) -> None:
        self._ensure_open()
        normalized = {relay: sorted(set(pubkeys)) for relay, pubkeys in routes.items() if pubkeys}

        new_relays = set(normalized) - set(self._routes)
        for relay in sorted(normalized):
            validate_relay_network_target(relay)
            self._run(
                self._subscribe_relay(
                    relay,
                    normalized[relay],
                    subscription_id,
                    add=relay in new_relays,
                )
            )

        for relay in sorted(set(self._routes) - set(normalized)):
            self._run(self._client.force_remove_relay(RelayUrl.parse(relay)))

        self._routes = normalized

    def publish(self, event: dict[str, Any], relays: list[str]) -> None:
        self._ensure_open()
        targets = [relay for relay in dict.fromkeys(relays) if relay in self._routes]
        if not targets:
            raise RuntimeError("No active relay route exists for this signer connection.")
        message = ClientMessage.from_json(json.dumps(["EVENT", event], separators=(",", ":")))
        self._send_to(targets, message)

    def take_events(self, subscription_id: str) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        while True:
            try:
                item_subscription, event = self._incoming.get_nowait()
            except queue.Empty:
                break
            if item_subscription == subscription_id:
                events.append(event)
        return events

    def enqueue(self, subscription_id: str, event: dict[str, Any]) -> None:
        try:
            self._incoming.put_nowait((subscription_id, event))
        except queue.Full:
            try:
                self._incoming.get_nowait()
            except queue.Empty:
                pass
            try:
                self._incoming.put_nowait((subscription_id, event))
            except queue.Full:
                pass

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._loop_ready.is_set():
            try:
                self._run(self._client.disconnect(), allow_closed=True)
            finally:
                self._loop.call_soon_threadsafe(self._notification_task.cancel)
                self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=5)

    def _run_event_loop(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        uniffi_set_event_loop(cast(asyncio.BaseEventLoop, self._loop))
        self._client = Client()
        self._notification_task = self._loop.create_task(
            self._client.handle_notifications(_NotificationHandler(self))
        )
        self._loop_ready.set()
        self._loop.run_forever()
        pending = asyncio.all_tasks(self._loop)
        for task in pending:
            task.cancel()
        if pending:
            self._loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        self._loop.close()

    async def _subscribe_relay(
        self,
        relay: str,
        pubkeys: list[str],
        subscription_id: str,
        *,
        add: bool,
    ) -> None:
        relay_url = RelayUrl.parse(relay)
        if add:
            await self._client.add_relay(relay_url)
        relay_connection = await self._client.relay(relay_url)
        if not relay_connection.is_connected():
            # Do not wait for an SDK backoff after the endpoint is healthy again.
            # Moving the relay to TERMINATED lets try_connect make one bounded,
            # synchronous attempt before the subscription is installed.
            if not add:
                relay_connection.disconnect()
            await relay_connection.try_connect(timedelta(seconds=5))
        relay_filter = Filter.from_json(json.dumps({"kinds": [24133], "#p": pubkeys, "limit": 0}))
        await relay_connection.subscribe_with_id(
            subscription_id,
            relay_filter,
            SubscribeOptions(),
        )

    def _send_to(self, relays: list[str], message: ClientMessage) -> None:
        relay_urls = [RelayUrl.parse(relay) for relay in relays]
        self._run(self._client.send_msg_to(relay_urls, message))

    def _run(self, coroutine: Any, *, allow_closed: bool = False) -> Any:
        if self._closed and not allow_closed:
            raise RuntimeError("NIP-46 relay runtime is closed.")
        if not self._loop_ready.is_set():
            raise RuntimeError("NIP-46 relay runtime is unavailable.")
        future = asyncio.run_coroutine_threadsafe(coroutine, self._loop)
        return future.result(timeout=15)

    def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeError("NIP-46 relay runtime is closed.")


def validate_relay_network_target(relay: str) -> None:
    """Reject server-side connections to local or special-use networks.

    Local loopback relays remain available in LNbits debug mode for the live
    interoperability harness. Production relay targets must resolve entirely
    to globally routable addresses.
    """

    parsed = urlsplit(relay)
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Relay URL has no host.")
    if settings.debug:
        return
    lowered = hostname.rstrip(".").lower()
    if lowered == "localhost" or lowered.endswith((".localhost", ".local", ".internal")):
        raise ValueError("Production relay URLs must not target a local network.")
    try:
        addresses = {
            item[4][0]
            for item in socket.getaddrinfo(
                hostname,
                parsed.port or 443,
                type=socket.SOCK_STREAM,
            )
        }
    except OSError as exc:
        raise ValueError("Relay host could not be resolved.") from exc
    if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
        raise ValueError("Production relay URLs must resolve only to public addresses.")


# Backwards-compatible import name for integrations written against 0.1.0-pre.
NostrClientTransport = NostrSdkTransport
