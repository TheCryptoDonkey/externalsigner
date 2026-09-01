import json
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

import pytest
from loguru import logger
from nostr_sdk import Keys

from externalsigner.crud import (
    create_operation,
    db,
    get_connection,
    get_operation,
    get_operation_by_request_id,
    update_connection,
)
from externalsigner.helpers import decrypt_json, decrypt_secret, encrypt_json
from externalsigner.models import CreateBunkerConnection, CreateNostrConnectConnection
from externalsigner.protocol import derive_pubkey
from externalsigner.services import (
    _log_exception,
    connection_view,
    create_bunker_connection,
    create_nostrconnect_connection,
    handle_response_event,
    refresh_runtime_state,
    request_signer,
    request_signer_for_user,
    retry_connection,
    revoke_connection,
    run_maintenance,
    set_transport,
)

from .fakes import (
    FakeTransport,
    decrypt_request_event,
    make_response_event,
    sign_unsigned_event,
)


def key_hex() -> str:
    return Keys.generate().secret_key().to_hex()


def test_runtime_exception_logging_omits_exception_data():
    messages: list[str] = []
    sink = logger.add(messages.append, format="{message}")
    try:
        _log_exception("NIP-46 runtime error", RuntimeError("secret-account-sentinel"))
    finally:
        logger.remove(sink)
    assert messages == ["[externalsigner] NIP-46 runtime error (RuntimeError)\n"]
    assert "secret-account-sentinel" not in "".join(messages)


async def bootstrap_bunker() -> tuple:
    transport = FakeTransport()
    set_transport(transport)
    remote_secret = key_hex()
    user_secret = key_hex()
    remote_pubkey = derive_pubkey(remote_secret)
    user_id = uuid4().hex
    connection, connect_operation = await create_bunker_connection(
        user_id,
        CreateBunkerConnection(
            name="Hardware merchant",
            bunker_uri=(
                f"bunker://{remote_pubkey}?relay=wss%3A%2F%2Frelay.example&secret=pair-once"
            ),
            permissions=[
                "sign_event:0",
                "sign_event:4",
                "sign_event:5",
                "sign_event:30017",
                "sign_event:30018",
                "nip04_encrypt",
                "nip04_decrypt",
            ],
        ),
    )
    assert connect_operation.status == "sent", decrypt_secret(connect_operation.encrypted_error)
    connect_request = decrypt_request_event(transport.published[-1], remote_secret)
    assert connect_request["method"] == "connect"
    assert connect_request["params"][1] == "pair-once"
    assert "sign_event:30017" in connect_request["params"][2]

    await handle_response_event(
        make_response_event(
            remote_secret,
            connection.client_pubkey,
            {"id": connect_request["id"], "result": "pair-once"},
        )
    )
    get_public_key_request = decrypt_request_event(transport.published[-1], remote_secret)
    assert get_public_key_request["method"] == "get_public_key"

    await handle_response_event(
        make_response_event(
            remote_secret,
            connection.client_pubkey,
            {
                "id": get_public_key_request["id"],
                "result": derive_pubkey(user_secret),
            },
        )
    )
    proof_request = decrypt_request_event(transport.published[-1], remote_secret)
    assert proof_request["method"] == "sign_event"
    unsigned_proof = json.loads(proof_request["params"][0])
    signed_proof = sign_unsigned_event(unsigned_proof, user_secret)

    await handle_response_event(
        make_response_event(
            remote_secret,
            connection.client_pubkey,
            {
                "id": proof_request["id"],
                "result": json.dumps(signed_proof, separators=(",", ":")),
            },
        )
    )
    switch_request = decrypt_request_event(transport.published[-1], remote_secret)
    assert switch_request["method"] == "switch_relays"
    await handle_response_event(
        make_response_event(
            remote_secret,
            connection.client_pubkey,
            {
                "id": switch_request["id"],
                "result": json.dumps(["wss://signer-relay.example"]),
            },
        )
    )
    connection = await get_connection(connection.id)
    assert connection
    assert connection.status == "connected"
    assert connection.user_pubkey == derive_pubkey(user_secret)
    assert connection.proof_verified_at is not None
    assert connection.encrypted_connect_secret is None
    assert connection.relays == ["wss://signer-relay.example"]
    return transport, connection, remote_secret, user_secret, user_id


@pytest.mark.asyncio
async def test_bunker_pairing_proves_separate_user_key_and_encrypts_stored_capabilities():
    transport, connection, _remote_secret, _user_secret, _user_id = await bootstrap_bunker()
    assert len(transport.published) == 4
    client_secret = decrypt_secret(connection.encrypted_client_secret)
    assert client_secret
    assert derive_pubkey(client_secret) == connection.client_pubkey
    assert client_secret != connection.encrypted_client_secret

    raw_connection = await db.fetchone(
        "SELECT * FROM externalsigner.connections WHERE id = :id",
        {"id": connection.id},
    )
    assert raw_connection["encrypted_client_secret"] != client_secret
    assert "pair-once" not in repr(raw_connection)

    rows = await db.fetchall(
        "SELECT * FROM externalsigner.operations WHERE connection_id = :connection_id",
        {"connection_id": connection.id},
    )
    assert rows
    assert all("pair-once" not in repr(row) for row in rows)


@pytest.mark.asyncio
async def test_permission_escalation_is_refused_before_publication():
    transport, connection, *_ = await bootstrap_bunker()
    published_before = len(transport.published)
    with pytest.raises(PermissionError, match="sign_event:1"):
        await request_signer(
            connection,
            "sign_event",
            [json.dumps({"kind": 1, "content": "nope", "tags": [], "created_at": 1_700_000_000})],
        )
    assert len(transport.published) == published_before

    with pytest.raises(ValueError, match="must not include"):
        await request_signer(
            connection,
            "sign_event",
            [
                json.dumps(
                    {
                        "id": "caller-chosen",
                        "kind": 0,
                        "content": "{}",
                        "tags": [],
                        "created_at": 1_700_000_000,
                    }
                )
            ],
        )
    assert len(transport.published) == published_before


@pytest.mark.asyncio
async def test_auth_url_is_nonterminal_and_later_response_completes_same_request():
    transport, connection, remote_secret, *_ = await bootstrap_bunker()
    operation = await request_signer(connection, "ping", [])
    request = decrypt_request_event(transport.published[-1], remote_secret)
    auth_event = make_response_event(
        remote_secret,
        connection.client_pubkey,
        {
            "id": request["id"],
            "result": "auth_url",
            "error": "https://signer.example/approve?token=secret",
        },
    )
    await handle_response_event(auth_event)
    stored = await get_operation(operation.id)
    assert stored
    assert stored.status == "auth_required"
    assert decrypt_secret(stored.encrypted_auth_url) == (
        "https://signer.example/approve?token=secret"
    )
    assert "token=secret" not in stored.encrypted_auth_url

    await handle_response_event(
        make_response_event(
            remote_secret,
            connection.client_pubkey,
            {"id": request["id"], "result": "pong"},
        )
    )
    stored = await get_operation(operation.id)
    assert stored
    assert stored.status == "complete"
    assert decrypt_json(stored.encrypted_result) == "pong"
    assert stored.encrypted_auth_url is None


@pytest.mark.asyncio
async def test_invalid_response_shape_is_rejected_before_claiming_operation():
    transport, connection, remote_secret, *_ = await bootstrap_bunker()
    operation = await request_signer(connection, "ping", [])
    request = decrypt_request_event(transport.published[-1], remote_secret)

    with pytest.raises(ValueError, match="result must be a string"):
        await handle_response_event(
            make_response_event(
                remote_secret,
                connection.client_pubkey,
                {"id": request["id"], "result": {"not": "a protocol string"}},
            )
        )

    stored = await get_operation(operation.id)
    assert stored and stored.status == "sent"
    assert stored.response_event_id is None


@pytest.mark.asyncio
async def test_forged_author_wrong_recipient_and_replay_do_not_change_authority():
    transport, connection, remote_secret, *_ = await bootstrap_bunker()
    operation = await request_signer(connection, "ping", [])
    request = decrypt_request_event(transport.published[-1], remote_secret)
    attacker_secret = key_hex()

    with pytest.raises(ValueError, match="different remote signer"):
        await handle_response_event(
            make_response_event(
                attacker_secret,
                connection.client_pubkey,
                {"id": request["id"], "result": "forged"},
            )
        )
    stored = await get_operation(operation.id)
    assert stored and stored.status == "sent"

    with pytest.raises(ValueError, match="active client"):
        await handle_response_event(
            make_response_event(
                remote_secret,
                connection.client_pubkey,
                {"id": request["id"], "result": "wrong recipient"},
                recipient=derive_pubkey(attacker_secret),
            )
        )
    stored = await get_operation(operation.id)
    assert stored and stored.status == "sent"

    valid = make_response_event(
        remote_secret,
        connection.client_pubkey,
        {"id": request["id"], "result": "pong"},
    )
    await handle_response_event(valid)
    first = await get_operation(operation.id)
    await handle_response_event(valid)
    replayed = await get_operation(operation.id)
    assert first and replayed
    assert first.status == replayed.status == "complete"
    assert first.response_event_id == replayed.response_event_id == valid["id"]


@pytest.mark.asyncio
async def test_client_initiated_pairing_requires_returned_secret_before_trusting_author():
    transport = FakeTransport()
    set_transport(transport)
    user_id = uuid4().hex
    connection = await create_nostrconnect_connection(
        user_id,
        CreateNostrConnectConnection(
            name="Scan me",
            relays=["wss://relay.example"],
            permissions=["sign_event:0"],
        ),
    )
    public = await connection_view(connection)
    assert public.pairing_uri
    assert public.pairing_expires_at is not None
    secret = parse_qs(urlsplit(public.pairing_uri).query)["secret"][0]
    remote_secret = key_hex()

    with pytest.raises(ValueError, match="pairing secret"):
        await handle_response_event(
            make_response_event(
                remote_secret,
                connection.client_pubkey,
                {"id": "connect", "result": "wrong"},
            )
        )
    unchanged = await get_connection(connection.id)
    assert unchanged and unchanged.remote_signer_pubkey is None

    await handle_response_event(
        make_response_event(
            remote_secret,
            connection.client_pubkey,
            {"id": "connect", "result": secret},
        )
    )
    updated = await get_connection(connection.id)
    assert updated
    assert updated.remote_signer_pubkey == derive_pubkey(remote_secret)
    assert updated.encrypted_connect_secret is None
    assert updated.pairing_expires_at is None
    assert updated.status == "verifying"
    assert decrypt_request_event(transport.published[-1], remote_secret)["method"] == (
        "get_public_key"
    )


@pytest.mark.asyncio
async def test_unreachable_pairing_relay_returns_a_safe_retryable_connection():
    class FailingTransport(FakeTransport):
        def reconcile(self, routes: dict[str, list[str]], subscription_id: str) -> None:
            raise RuntimeError("relay handshake failed")

    set_transport(FailingTransport())
    user_id = uuid4().hex
    connection = await create_nostrconnect_connection(
        user_id,
        CreateNostrConnectConnection(
            name="Offline relay",
            relays=["wss://relay.example"],
            permissions=[],
        ),
    )

    failed = await get_connection(connection.id)
    assert failed
    assert failed.status == "error"
    assert failed.encrypted_connect_secret is None
    assert failed.pairing_expires_at is None
    assert (await connection_view(failed)).pairing_uri is None

    with pytest.raises(ValueError, match="could not be reached"):
        await retry_connection(user_id, connection.id)

    retried = await get_connection(connection.id)
    assert retried
    assert retried.status == "error"
    assert retried.encrypted_connect_secret is None


@pytest.mark.asyncio
async def test_ping_requires_the_standard_pong_result():
    transport, connection, remote_secret, *_ = await bootstrap_bunker()
    operation = await request_signer(connection, "ping", [])
    request = decrypt_request_event(transport.published[-1], remote_secret)

    with pytest.raises(ValueError, match="must be pong"):
        await handle_response_event(
            make_response_event(
                remote_secret,
                connection.client_pubkey,
                {"id": request["id"], "result": "anything"},
            )
        )

    unchanged = await get_operation(operation.id)
    assert unchanged and unchanged.status == "sent"


@pytest.mark.asyncio
async def test_revocation_erases_client_capability_and_wrong_owner_cannot_request():
    transport, connection, remote_secret, _user_secret, user_id = await bootstrap_bunker()
    with pytest.raises(ValueError, match="not found"):
        await request_signer_for_user(uuid4().hex, connection.id, "ping", [])

    revoked = await revoke_connection(user_id, connection.id)
    assert revoked.status == "revoked"
    assert revoked.encrypted_client_secret == ""
    assert revoked.encrypted_connect_secret is None
    logout = decrypt_request_event(transport.published[-1], remote_secret)
    assert logout["method"] == "logout"

    persisted = await get_connection(connection.id)
    assert persisted and persisted.encrypted_client_secret == ""
    logout_operation = await get_operation_by_request_id(logout["id"])
    assert logout_operation is None


@pytest.mark.asyncio
async def test_expired_nostrconnect_secret_is_rejected_and_retry_mints_a_new_pairing():
    transport = FakeTransport()
    set_transport(transport)
    user_id = uuid4().hex
    connection = await create_nostrconnect_connection(
        user_id,
        CreateNostrConnectConnection(
            name="Expiring pairing",
            relays=["wss://relay.example"],
            permissions=["sign_event:0"],
        ),
    )
    original = await connection_view(connection)
    assert original.pairing_uri
    original_secret = parse_qs(urlsplit(original.pairing_uri).query)["secret"][0]
    connection.pairing_expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    await update_connection(connection)

    with pytest.raises(ValueError, match="expired"):
        await handle_response_event(
            make_response_event(
                key_hex(),
                connection.client_pubkey,
                {"id": "connect", "result": original_secret},
            )
        )

    await run_maintenance(force=True)
    expired = await get_connection(connection.id)
    assert expired
    assert expired.status == "error"
    assert expired.encrypted_connect_secret is None
    assert (await connection_view(expired)).pairing_uri is None
    await retry_connection(user_id, connection.id)
    refreshed = await get_connection(connection.id)
    assert refreshed
    public = await connection_view(refreshed)
    assert public.pairing_uri
    assert public.pairing_expires_at and public.pairing_expires_at > datetime.now(timezone.utc)
    new_secret = parse_qs(urlsplit(public.pairing_uri).query)["secret"][0]
    assert new_secret != original_secret


@pytest.mark.asyncio
async def test_maintenance_expires_abandoned_operations_and_scrubs_params():
    _transport, connection, _remote_secret, _user_secret, _user_id = await bootstrap_bunker()
    operation = await request_signer(connection, "ping", [])
    stale = datetime.now(timezone.utc) - timedelta(hours=1)
    await db.execute(
        f"""
        UPDATE externalsigner.operations
        SET updated_at = {db.timestamp_placeholder("updated_at")}
        WHERE id = :id
        """,
        {"updated_at": stale, "id": operation.id},
    )

    await run_maintenance(force=True)

    expired = await get_operation(operation.id)
    assert expired
    assert expired.status == "failed"
    assert decrypt_json(expired.encrypted_params) == []
    still_connected = await get_connection(connection.id)
    assert still_connected and still_connected.status == "connected"


@pytest.mark.asyncio
async def test_restart_recovers_sent_approval_required_and_completed_operations():
    transport, connection, remote_secret, _user_secret, _user_id = await bootstrap_bunker()

    sent = await request_signer(connection, "ping", [])
    sent_request = decrypt_request_event(transport.published[-1], remote_secret)

    approval = await request_signer(connection, "ping", [])
    approval_request = decrypt_request_event(transport.published[-1], remote_secret)
    await handle_response_event(
        make_response_event(
            remote_secret,
            connection.client_pubkey,
            {
                "id": approval_request["id"],
                "result": "auth_url",
                "error": "https://signer.example/approve",
            },
        )
    )

    complete = await request_signer(connection, "ping", [])
    complete_request = decrypt_request_event(transport.published[-1], remote_secret)
    complete_response = make_response_event(
        remote_secret,
        connection.client_pubkey,
        {"id": complete_request["id"], "result": "pong"},
    )
    await handle_response_event(complete_response)

    set_transport(None)
    restarted_transport = FakeTransport()
    set_transport(restarted_transport)
    await refresh_runtime_state(force=True)

    assert restarted_transport.relays == ["wss://signer-relay.example"]
    assert connection.client_pubkey in next(iter(restarted_transport.subscriptions.values()))

    await handle_response_event(
        make_response_event(
            remote_secret,
            connection.client_pubkey,
            {"id": sent_request["id"], "result": "pong"},
        )
    )
    await handle_response_event(
        make_response_event(
            remote_secret,
            connection.client_pubkey,
            {"id": approval_request["id"], "result": "pong"},
        )
    )
    await handle_response_event(complete_response)

    recovered_sent = await get_operation(sent.id)
    recovered_approval = await get_operation(approval.id)
    unchanged_complete = await get_operation(complete.id)
    assert recovered_sent and recovered_sent.status == "complete"
    assert recovered_approval and recovered_approval.status == "complete"
    assert unchanged_complete and unchanged_complete.status == "complete"
    assert unchanged_complete.response_event_id == complete_response["id"]


@pytest.mark.asyncio
async def test_clock_controlled_expiry_and_retention_boundaries():
    _transport, connection, _remote_secret, _user_secret, _user_id = await bootstrap_bunker()
    clock = datetime.now(timezone.utc).replace(microsecond=0)

    stale = await create_operation(
        connection.id,
        uuid4().hex,
        "ping",
        "user",
        encrypt_json(["must be scrubbed"]),
    )
    terminal = await create_operation(
        connection.id,
        uuid4().hex,
        "ping",
        "user",
        encrypt_json([]),
    )
    await db.execute(
        f"""
        UPDATE externalsigner.operations
        SET status = 'sent', updated_at = {db.timestamp_placeholder("updated_at")}
        WHERE id = :id
        """,
        {"updated_at": clock, "id": stale.id},
    )
    await db.execute(
        f"""
        UPDATE externalsigner.operations
        SET status = 'complete', updated_at = {db.timestamp_placeholder("updated_at")}
        WHERE id = :id
        """,
        {"updated_at": clock, "id": terminal.id},
    )

    await run_maintenance(force=True, now=clock + timedelta(minutes=29))
    assert (await get_operation(stale.id)).status == "sent"  # type: ignore[union-attr]
    assert await get_operation(terminal.id)

    await run_maintenance(force=True, now=clock + timedelta(minutes=31))

    expired = await get_operation(stale.id)
    assert expired and expired.status == "failed"
    assert decrypt_json(expired.encrypted_params) == []

    await run_maintenance(force=True, now=clock + timedelta(days=7) - timedelta(seconds=1))
    assert await get_operation(terminal.id)

    await run_maintenance(force=True, now=clock + timedelta(days=7, seconds=1))
    assert await get_operation(terminal.id) is None
