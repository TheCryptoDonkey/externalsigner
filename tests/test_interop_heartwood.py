import asyncio
import json
import os
from collections.abc import Awaitable, Callable
from pathlib import Path

import httpx
import pytest
from lnbits.settings import settings

from externalsigner.crud import get_connection
from externalsigner.models import CreateBunkerConnection
from externalsigner.services import (
    close_transport,
    create_bunker_connection,
    process_transport_events,
    refresh_runtime_state,
    sign_event,
)

from .local_relay import LocalNostrRelay, free_port


async def _wait_until(predicate: Callable[[], Awaitable[bool]], timeout: float = 25) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        await refresh_runtime_state(force=True)
        await process_transport_events()
        if await predicate():
            return
        await asyncio.sleep(0.1)
    raise TimeoutError("Timed out waiting for NIP-46 state transition.")


@pytest.mark.asyncio
@pytest.mark.interop
async def test_live_heartwood_soft_signer_bootstrap_and_sign(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Exercise the extension against the real Heartwood daemon and soft backend."""

    configured_binary = os.getenv("HEARTWOODD_PATH")
    if not configured_binary:
        pytest.skip("set HEARTWOODD_PATH to run the Heartwood implementation test")
    binary = Path(configured_binary).resolve()
    if not binary.is_file():
        pytest.fail(f"HEARTWOODD_PATH is not a file: {binary}")

    monkeypatch.setattr(settings, "debug", True)

    api_port = free_port()
    api_token = "externalsigner-heartwood-test-token"
    daemon: asyncio.subprocess.Process | None = None

    async with LocalNostrRelay() as relay:
        daemon = await asyncio.create_subprocess_exec(
            str(binary),
            "--mode",
            "soft",
            "--data-dir",
            str(tmp_path / "heartwood"),
            "--relays",
            relay.url,
            "--api-port",
            str(api_port),
            "--api-token",
            api_token,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={**os.environ, "RUST_LOG": "info"},
        )
        headers = {"Authorization": f"Bearer {api_token}"}
        base_url = f"http://127.0.0.1:{api_port}"
        try:
            async with httpx.AsyncClient(
                base_url=base_url,
                headers=headers,
                timeout=30,
            ) as client:
                for _ in range(150):
                    try:
                        response = await client.get("/api/info")
                        if response.status_code == 200:
                            break
                    except httpx.TransportError:
                        pass
                    await asyncio.sleep(0.1)
                else:
                    pytest.fail("Heartwood management API did not start")

                response = await client.post(
                    "/api/unlock", json={"passphrase": "temporary-test-passphrase"}
                )
                response.raise_for_status()
                response = await client.post("/api/masters", json={"label": "LNbits test"})
                response.raise_for_status()
                master = response.json()
                master_slot = int(master["index"])

                response = await client.post(
                    f"/api/slots/{master_slot}", json={"label": "External Signer test"}
                )
                response.raise_for_status()
                slot = response.json()
                slot_index = int(slot["slot_index"])
                response = await client.put(
                    f"/api/slots/{master_slot}/{slot_index}",
                    json={
                        "allowed_methods": ["get_public_key", "sign_event"],
                        "allowed_kinds": [0, 27235],
                        "auto_approve": True,
                    },
                )
                response.raise_for_status()
                response = await client.get(f"/api/slots/{master_slot}/{slot_index}/uri")
                response.raise_for_status()
                bunker_uri = response.json()["bunker_uri"]

            # Heartwood refreshes identities created after startup every five seconds.
            await asyncio.sleep(6)
            user_id = "heartwood-interop-user"
            connection, _operation = await create_bunker_connection(
                user_id,
                CreateBunkerConnection(
                    name="Heartwood soft signer",
                    bunker_uri=bunker_uri,
                    permissions=["sign_event:0"],
                ),
            )

            async def connected() -> bool:
                current = await get_connection(connection.id)
                return current is not None and current.status == "connected"

            await _wait_until(connected)
            unsigned = {
                "kind": 0,
                "content": json.dumps({"name": "Heartwood interop"}),
                "tags": [],
                "created_at": 1_800_000_000,
            }
            signing = asyncio.create_task(sign_event(user_id, connection.id, unsigned, timeout=25))

            async def signed() -> bool:
                return signing.done()

            await _wait_until(signed)
            event = await signing
            assert event["pubkey"] == master["pubkey"]
            assert event["kind"] == 0
            assert event["content"] == unsigned["content"]
        finally:
            close_transport()
            if daemon.returncode is None:
                daemon.terminate()
                try:
                    await asyncio.wait_for(daemon.wait(), timeout=5)
                except TimeoutError:
                    daemon.kill()
                    await daemon.wait()
