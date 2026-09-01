import asyncio
import json
import os
import shutil
import tempfile
from collections.abc import Awaitable, Callable
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit
from uuid import uuid4

import pytest
from nostr_sdk import Keys

from externalsigner.crud import get_connection, get_operation
from externalsigner.helpers import decrypt_json
from externalsigner.models import CreateBunkerConnection, CreateNostrConnectConnection
from externalsigner.protocol import derive_pubkey, verify_signed_event
from externalsigner.services import (
    close_transport,
    connection_view,
    create_bunker_connection,
    create_nostrconnect_connection,
    process_transport_events,
    refresh_runtime_state,
    request_signer,
    revoke_connection,
    set_transport,
)
from externalsigner.transport import NostrSdkTransport

from .local_relay import LocalNostrRelay

NAK_PATH = os.getenv("NAK_PATH")
if not NAK_PATH:
    pytest.skip(
        "Set NAK_PATH to run interop against the released nak signer.",
        allow_module_level=True,
    )

NAK_RELEASE = "v0.20.6"


def key_hex() -> str:
    return Keys.generate().secret_key().to_hex()


@pytest.fixture
def nak_config_path() -> Path:
    # Unix-domain sockets have a short platform path limit. Pytest's normal
    # macOS temporary path is already long enough to exceed it.
    path = Path(tempfile.mkdtemp(prefix="extnak-", dir="/tmp"))
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


async def wait_for(
    predicate: Callable[[], bool | Awaitable[bool]],
    *,
    process: asyncio.subprocess.Process | None = None,
    timeout: float = 30,
) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        if process and process.returncode is not None:
            output = await process.stdout.read() if process.stdout else b""
            pytest.fail(
                f"nak {NAK_RELEASE} exited with {process.returncode}: "
                f"{output.decode(errors='replace')[-2000:]}"
            )
        result = predicate()
        if isinstance(result, Awaitable):
            result = await result
        if result:
            return
        await asyncio.sleep(0.1)
    raise TimeoutError(f"Timed out waiting for nak {NAK_RELEASE} interoperability evidence.")


async def start_nak(
    nak_path: str,
    relay: LocalNostrRelay,
    signer_secret: str,
    config_path: Path,
    profile: str,
    authorized_secret: str,
) -> asyncio.subprocess.Process:
    process = await asyncio.create_subprocess_exec(
        nak_path,
        "--config-path",
        str(config_path),
        "--sec",
        signer_secret,
        "--quiet",
        "bunker",
        "--profile",
        profile,
        "--authorized-secrets",
        authorized_secret,
        relay.url,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    signer_pubkey = derive_pubkey(signer_secret)
    await wait_for(
        lambda: relay.has_recipient_subscription(signer_pubkey),
        process=process,
    )
    await wait_for(
        lambda: (config_path / "bunkerconn" / profile).exists(),
        process=process,
    )
    return process


async def stop_nak(process: asyncio.subprocess.Process) -> None:
    if process.returncode is not None:
        return
    process.terminate()
    try:
        await asyncio.wait_for(process.wait(), timeout=5)
    except TimeoutError:
        process.kill()
        await process.wait()


async def pump_until(predicate: Callable[[], Awaitable[bool]], timeout: float = 30) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        await process_transport_events()
        if await predicate():
            return
        await asyncio.sleep(0.1)
    raise TimeoutError("Timed out waiting for the external signer state transition.")


async def wait_for_connection(connection_id: str, status: str) -> None:
    async def ready() -> bool:
        connection = await get_connection(connection_id)
        return bool(connection and connection.status == status)

    await pump_until(ready)


async def wait_for_operation(operation_id: str, status: str) -> None:
    async def ready() -> bool:
        operation = await get_operation(operation_id)
        return bool(operation and operation.status == status)

    await pump_until(ready)


async def sign_and_verify(connection_id: str, signer_pubkey: str) -> None:
    connection = await get_connection(connection_id)
    assert connection and connection.status == "connected"
    unsigned = {
        "kind": 0,
        "content": json.dumps({"name": f"nak-{NAK_RELEASE}-interop"}),
        "tags": [],
        "created_at": 1_700_000_000,
    }
    operation = await request_signer(
        connection,
        "sign_event",
        [json.dumps(unsigned, separators=(",", ":"))],
    )
    await wait_for_operation(operation.id, "complete")
    complete = await get_operation(operation.id)
    assert complete
    result = decrypt_json(complete.encrypted_result)
    assert isinstance(result, str)
    signed = verify_signed_event(result, signer_pubkey, unsigned)
    assert signed["pubkey"] == signer_pubkey


@pytest.mark.asyncio
@pytest.mark.interop
async def test_released_nak_bunker_invite_sign_restart_relay_recovery_and_revoke(
    nak_config_path: Path,
):
    signer_secret = key_hex()
    signer_pubkey = derive_pubkey(signer_secret)
    invite_secret = "released-nak-one-use"
    relay = await LocalNostrRelay().start()
    nak = await start_nak(
        NAK_PATH,
        relay,
        signer_secret,
        nak_config_path,
        "invite",
        invite_secret,
    )
    transport = await asyncio.to_thread(NostrSdkTransport)
    set_transport(transport)
    try:
        query = urlencode({"relay": relay.url, "secret": invite_secret})
        connection, _operation = await create_bunker_connection(
            uuid4().hex,
            CreateBunkerConnection(
                name=f"nak {NAK_RELEASE} invite",
                bunker_uri=f"bunker://{signer_pubkey}?{query}",
                permissions=["sign_event:0"],
            ),
        )
        await wait_for_connection(connection.id, "connected")
        await sign_and_verify(connection.id, signer_pubkey)

        await stop_nak(nak)
        nak = await start_nak(
            NAK_PATH,
            relay,
            signer_secret,
            nak_config_path,
            "invite",
            invite_secret,
        )
        await relay.stop()
        await relay.start()
        await wait_for(
            lambda: relay.has_recipient_subscription(signer_pubkey),
            process=nak,
        )
        await refresh_runtime_state(force=True)
        await wait_for(
            lambda: relay.has_recipient_subscription(connection.client_pubkey),
            process=nak,
        )
        await sign_and_verify(connection.id, signer_pubkey)

        revoked = await revoke_connection(connection.user_id, connection.id)
        assert revoked.status == "revoked"
        assert revoked.encrypted_client_secret == ""
    finally:
        close_transport()
        await stop_nak(nak)
        await relay.stop()


@pytest.mark.asyncio
@pytest.mark.interop
async def test_released_nak_accepts_client_initiated_nostrconnect_pairing(
    nak_config_path: Path,
):
    signer_secret = key_hex()
    signer_pubkey = derive_pubkey(signer_secret)
    relay = await LocalNostrRelay().start()
    nak = await start_nak(
        NAK_PATH,
        relay,
        signer_secret,
        nak_config_path,
        "qr",
        "unused-invite-secret",
    )
    transport = await asyncio.to_thread(NostrSdkTransport)
    set_transport(transport)
    try:
        connection = await create_nostrconnect_connection(
            uuid4().hex,
            CreateNostrConnectConnection(
                name=f"nak {NAK_RELEASE} QR",
                relays=[relay.url],
                permissions=["sign_event:0"],
            ),
        )
        public = await connection_view(connection)
        assert public.pairing_uri
        pairing_secret = parse_qs(urlsplit(public.pairing_uri).query)["secret"][0]
        assert pairing_secret not in signer_secret

        connect = await asyncio.create_subprocess_exec(
            NAK_PATH,
            "--config-path",
            str(nak_config_path),
            "--quiet",
            "bunker",
            "connect",
            "--profile",
            "qr",
            public.pairing_uri,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        output, _ = await asyncio.wait_for(connect.communicate(), timeout=10)
        assert connect.returncode == 0, output.decode(errors="replace")

        await wait_for_connection(connection.id, "connected")
        await sign_and_verify(connection.id, signer_pubkey)
    finally:
        close_transport()
        await stop_nak(nak)
        await relay.stop()
