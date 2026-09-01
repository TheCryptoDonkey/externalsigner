import asyncio
import json

import pytest
import websockets
from lnbits.settings import settings
from nostr_sdk import Keys

from externalsigner.protocol import derive_pubkey
from externalsigner.transport import NostrSdkTransport

from .fakes import make_response_event
from .local_relay import LocalNostrRelay


async def _wait_for(predicate, timeout: float = 5) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        if predicate():
            return
        await asyncio.sleep(0.05)
    raise TimeoutError("Timed out waiting for local relay transport evidence.")


@pytest.mark.asyncio
async def test_sdk_transport_targets_relay_and_receives_valid_subscription_event(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "debug", True)
    client_pubkey = derive_pubkey(Keys.generate().secret_key().to_hex())
    other_pubkey = derive_pubkey(Keys.generate().secret_key().to_hex())
    remote_secret = Keys.generate().secret_key().to_hex()
    event = make_response_event(
        remote_secret,
        client_pubkey,
        {"id": "transport-test", "result": "pong"},
    )

    async with LocalNostrRelay() as selected, LocalNostrRelay() as excluded:
        transport = await asyncio.to_thread(NostrSdkTransport)
        try:
            await asyncio.to_thread(
                transport.reconcile,
                {
                    selected.url: [client_pubkey],
                    excluded.url: [other_pubkey],
                },
                "transport-test",
            )
            await _wait_for(lambda: selected.has_subscription("transport-test", client_pubkey))
            async with websockets.connect(selected.url) as publisher:
                await publisher.send(json.dumps(["EVENT", event]))
                acknowledgement = await asyncio.wait_for(publisher.recv(), timeout=5)
                assert '"OK"' in acknowledgement

            received: list[dict] = []

            def take_received() -> bool:
                received.extend(transport.take_events("transport-test"))
                return bool(received)

            await _wait_for(take_received)
            assert received == [event]

            await asyncio.to_thread(transport.publish, event, [selected.url])
            await _wait_for(lambda: any(item["id"] == event["id"] for item in selected.events))
            assert excluded.events == []
        finally:
            await asyncio.to_thread(transport.close)


@pytest.mark.asyncio
async def test_sdk_transport_restores_unchanged_subscription_after_relay_restart(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "debug", True)
    client_pubkey = derive_pubkey(Keys.generate().secret_key().to_hex())
    relay = LocalNostrRelay()
    transport = await asyncio.to_thread(NostrSdkTransport)
    try:
        await relay.start()
        await asyncio.to_thread(
            transport.reconcile,
            {relay.url: [client_pubkey]},
            "relay-recovery-test",
        )
        await _wait_for(lambda: relay.has_subscription("relay-recovery-test", client_pubkey))

        await relay.stop()
        # Give the SDK's relay task time to observe the closed WebSocket before
        # the same endpoint becomes available again.
        await asyncio.sleep(0.5)
        await relay.start()
        deadline = asyncio.get_running_loop().time() + 10
        while not relay.has_subscription("relay-recovery-test", client_pubkey):
            if asyncio.get_running_loop().time() >= deadline:
                raise TimeoutError("Transport did not restore the relay subscription.")
            await asyncio.to_thread(
                transport.reconcile,
                {relay.url: [client_pubkey]},
                "relay-recovery-test",
            )
            await asyncio.sleep(0.1)
    finally:
        await asyncio.to_thread(transport.close)
        await relay.stop()
