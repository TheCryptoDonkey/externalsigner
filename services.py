import asyncio
import json
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlsplit

from lnbits.settings import settings
from loguru import logger
from nostr_sdk import Keys

from .crud import (
    claim_nostrconnect_handshake,
    claim_operation_response,
    count_active_connections_for_user,
    count_open_operations_for_connection,
    count_recent_operations_for_connection,
    create_operation,
    delete_connection_operations,
    delete_terminal_operations_before,
    get_connection,
    get_connection_by_client_pubkey,
    get_connection_for_user,
    get_connections_for_user,
    get_expired_pairings,
    get_operation,
    get_operation_by_request_id,
    get_runtime_connections,
    get_stale_operations,
    new_connection,
    update_connection,
    update_operation,
)
from .helpers import (
    PERMISSION_PRESETS,
    build_nostrconnect_uri,
    decrypt_json,
    decrypt_secret,
    encrypt_json,
    encrypt_secret,
    normalize_hex_pubkey,
    normalize_permissions,
    normalize_relay_urls,
    parse_bunker_uri,
)
from .models import (
    ConnectionView,
    CreateBunkerConnection,
    CreateNostrConnectConnection,
    ExternalSignerConnection,
    OperationView,
    PermissionPreset,
    SignerOperation,
)
from .protocol import (
    build_identity_proof_event,
    build_request_event,
    decrypt_response_payload,
    derive_pubkey,
    verify_identity_proof,
    verify_signed_event,
)
from .transport import Nip46Transport, NostrSdkTransport, validate_relay_network_target

SUBSCRIPTION_ID = "externalsigner_nip46"
REFRESH_INTERVAL_SECONDS = 20
MAX_REQUEST_BYTES = 256 * 1024
MAX_RESPONSE_BYTES = 512 * 1024
PAIRING_TTL_SECONDS = 10 * 60
MAX_ACTIVE_CONNECTIONS_PER_ACCOUNT = 10
MAX_OPEN_OPERATIONS_PER_CONNECTION = 12
MAX_USER_REQUESTS_PER_MINUTE = 60
OPERATION_TIMEOUT_SECONDS = 30 * 60
OPERATION_RETENTION_DAYS = 7
MAINTENANCE_INTERVAL_SECONDS = 5 * 60
TERMINAL_OPERATION_STATUSES = {"complete", "failed"}


class SignerCapacityError(ValueError):
    pass


class SignerRateLimitError(ValueError):
    pass


@dataclass
class RuntimeState:
    subscribed_pubkeys: set[str] = field(default_factory=set)
    relays: set[str] = field(default_factory=set)
    next_refresh_at: float = 0
    next_maintenance_at: float = 0
    seen_event_ids: set[str] = field(default_factory=set)


runtime_state = RuntimeState()
_transport: Nip46Transport | None = None
_transport_factory: Callable[[], Nip46Transport] = NostrSdkTransport


def set_transport(transport: Nip46Transport | None) -> None:
    global _transport
    _transport = transport
    mark_runtime_state_dirty()


def close_transport() -> None:
    global _transport
    if _transport is not None:
        _transport.close()
        _transport = None
    mark_runtime_state_dirty()


def set_transport_factory(factory: Callable[[], Nip46Transport]) -> None:
    global _transport_factory
    _transport_factory = factory
    set_transport(None)


def get_transport() -> Nip46Transport:
    global _transport
    if _transport is None:
        _transport = _transport_factory()
    return _transport


def mark_runtime_state_dirty() -> None:
    runtime_state.next_refresh_at = 0


def permission_presets() -> list[PermissionPreset]:
    return [
        PermissionPreset(id=preset_id, **preset) for preset_id, preset in PERMISSION_PRESETS.items()
    ]


async def create_bunker_connection(
    user_id: str, data: CreateBunkerConnection
) -> tuple[ExternalSignerConnection, SignerOperation]:
    await _enforce_connection_limit(user_id)
    parsed = parse_bunker_uri(data.bunker_uri)
    for relay in parsed.relays:
        await _validate_relay_target(relay)
    permissions = normalize_permissions(data.permissions)
    client_secret = Keys.generate().secret_key().to_hex()
    connection = await new_connection(
        user_id=user_id,
        name=data.name.strip(),
        mode="bunker",
        remote_signer_pubkey=parsed.remote_signer_pubkey,
        client_pubkey=derive_pubkey(client_secret),
        encrypted_client_secret=_encrypt_required(client_secret),
        encrypted_connect_secret=encrypt_secret(parsed.secret),
        relays=parsed.relays,
        permissions=permissions,
        status="connecting",
    )
    mark_runtime_state_dirty()
    operation = await _start_bunker_connect(connection)
    return connection, operation


async def create_nostrconnect_connection(
    user_id: str, data: CreateNostrConnectConnection
) -> ExternalSignerConnection:
    await _enforce_connection_limit(user_id)
    permissions = normalize_permissions(data.permissions)
    relays = normalize_relay_urls(data.relays)
    for relay in relays:
        await _validate_relay_target(relay)
    client_secret = Keys.generate().secret_key().to_hex()
    connect_secret = secrets.token_urlsafe(32)
    connection = await new_connection(
        user_id=user_id,
        name=data.name.strip(),
        mode="nostrconnect",
        client_pubkey=derive_pubkey(client_secret),
        encrypted_client_secret=_encrypt_required(client_secret),
        encrypted_connect_secret=_encrypt_required(connect_secret),
        relays=relays,
        permissions=permissions,
        status="awaiting_signer",
        pairing_expires_at=datetime.now(timezone.utc) + timedelta(seconds=PAIRING_TTL_SECONDS),
    )
    mark_runtime_state_dirty()
    try:
        await _ensure_connection_relays(connection)
    except Exception as exc:
        connection.encrypted_connect_secret = None
        connection.pairing_expires_at = None
        await _fail_connection(connection, f"Pairing relay connection failed: {exc}")
    return connection


async def connection_view(connection: ExternalSignerConnection) -> ConnectionView:
    pairing_uri = None
    if (
        connection.mode == "nostrconnect"
        and connection.status == "awaiting_signer"
        and not _pairing_expired(connection)
    ):
        connect_secret = decrypt_secret(connection.encrypted_connect_secret)
        if connect_secret:
            pairing_uri = build_nostrconnect_uri(
                connection.client_pubkey,
                connection.relays,
                connect_secret,
                connection.permissions,
                connection.name,
            )
    return ConnectionView(
        id=connection.id,
        name=connection.name,
        mode=connection.mode,
        remote_signer_pubkey=connection.remote_signer_pubkey,
        user_pubkey=connection.user_pubkey,
        client_pubkey=connection.client_pubkey,
        relays=connection.relays,
        permissions=connection.permissions,
        status=connection.status,
        last_error=decrypt_secret(connection.encrypted_last_error),
        pairing_expires_at=connection.pairing_expires_at,
        proof_verified_at=connection.proof_verified_at,
        last_used_at=connection.last_used_at,
        created_at=connection.created_at,
        updated_at=connection.updated_at,
        pairing_uri=pairing_uri,
    )


async def operation_view(operation: SignerOperation) -> OperationView:
    result = None
    if operation.encrypted_result:
        result = decrypt_json(operation.encrypted_result)
    return OperationView(
        id=operation.id,
        connection_id=operation.connection_id,
        request_id=operation.request_id,
        method=operation.method,
        purpose=operation.purpose,
        status=operation.status,
        result=result,
        error=decrypt_secret(operation.encrypted_error),
        auth_url=decrypt_secret(operation.encrypted_auth_url),
        response_event_id=operation.response_event_id,
        created_at=operation.created_at,
        updated_at=operation.updated_at,
    )


async def list_connection_views(user_id: str) -> list[ConnectionView]:
    await run_maintenance()
    return [await connection_view(item) for item in await get_connections_for_user(user_id)]


async def get_connection_view(user_id: str, connection_id: str) -> ConnectionView | None:
    await run_maintenance()
    connection = await get_connection_for_user(user_id, connection_id)
    return await connection_view(connection) if connection else None


async def get_operation_view(user_id: str, operation_id: str) -> OperationView | None:
    operation = await get_operation(operation_id)
    if not operation:
        return None
    connection = await get_connection_for_user(user_id, operation.connection_id)
    return await operation_view(operation) if connection else None


async def request_signer(
    connection: ExternalSignerConnection,
    method: str,
    params: list[Any],
    *,
    purpose: str = "user",
    allow_unconnected: bool = False,
) -> SignerOperation:
    if connection.status == "revoked" or not connection.encrypted_client_secret:
        raise ValueError("This external signer connection has been revoked.")
    if not allow_unconnected and connection.status != "connected":
        raise ValueError("External signer connection is not ready.")
    if not connection.remote_signer_pubkey:
        raise ValueError("External signer public key is not known yet.")
    _validate_request_policy(connection, method, params, purpose)
    await _enforce_operation_limits(connection.id, purpose)
    request_id = secrets.token_hex(16)
    operation = await create_operation(
        connection.id,
        request_id,
        method,
        purpose,
        encrypt_json(params),
    )
    return await _publish_operation(connection, operation)


async def request_signer_for_user(
    user_id: str,
    connection_id: str,
    method: str,
    params: list[Any],
) -> SignerOperation:
    connection = await get_connection_for_user(user_id, connection_id)
    if not connection:
        raise ValueError("External signer connection not found.")
    return await request_signer(connection, method, params)


async def sign_event(
    user_id: str,
    connection_id: str,
    unsigned_event: dict[str, Any],
    timeout: float = 120,
) -> dict[str, Any]:
    connection = await get_connection_for_user(user_id, connection_id)
    if not connection or not connection.user_pubkey:
        raise ValueError("Connected external signer identity is unavailable.")
    operation = await request_signer(
        connection,
        "sign_event",
        [json.dumps(unsigned_event, separators=(",", ":"), ensure_ascii=False)],
    )
    result = await await_operation(operation.id, timeout)
    if not isinstance(result, str):
        raise ValueError("External signer returned an invalid signed event.")
    return verify_signed_event(result, connection.user_pubkey, unsigned_event)


async def nip44_encrypt(
    user_id: str,
    connection_id: str,
    recipient_pubkey: str,
    plaintext: str,
    timeout: float = 120,
) -> str:
    return await _string_request(
        user_id,
        connection_id,
        "nip44_encrypt",
        [normalize_hex_pubkey(recipient_pubkey), plaintext],
        timeout,
    )


async def nip44_decrypt(
    user_id: str,
    connection_id: str,
    sender_pubkey: str,
    ciphertext: str,
    timeout: float = 120,
) -> str:
    return await _string_request(
        user_id,
        connection_id,
        "nip44_decrypt",
        [normalize_hex_pubkey(sender_pubkey), ciphertext],
        timeout,
    )


async def nip04_encrypt(
    user_id: str,
    connection_id: str,
    recipient_pubkey: str,
    plaintext: str,
    timeout: float = 120,
) -> str:
    return await _string_request(
        user_id,
        connection_id,
        "nip04_encrypt",
        [normalize_hex_pubkey(recipient_pubkey), plaintext],
        timeout,
    )


async def nip04_decrypt(
    user_id: str,
    connection_id: str,
    sender_pubkey: str,
    ciphertext: str,
    timeout: float = 120,
) -> str:
    return await _string_request(
        user_id,
        connection_id,
        "nip04_decrypt",
        [normalize_hex_pubkey(sender_pubkey), ciphertext],
        timeout,
    )


async def _string_request(
    user_id: str,
    connection_id: str,
    method: str,
    params: list[Any],
    timeout: float,
) -> str:
    operation = await request_signer_for_user(user_id, connection_id, method, params)
    result = await await_operation(operation.id, timeout)
    if not isinstance(result, str):
        raise ValueError(f"External signer returned an invalid {method} result.")
    return result


async def await_operation(operation_id: str, timeout: float = 120) -> Any:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        operation = await get_operation(operation_id)
        if not operation:
            raise ValueError("External signer operation no longer exists.")
        if operation.status == "complete":
            return decrypt_json(operation.encrypted_result) if operation.encrypted_result else None
        if operation.status == "failed":
            raise ValueError(
                decrypt_secret(operation.encrypted_error) or "External signer request failed."
            )
        await asyncio.sleep(0.1)
    operation = await get_operation(operation_id)
    if operation and operation.status not in TERMINAL_OPERATION_STATUSES:
        await _fail_operation(operation, "Signer request timed out while waiting for approval.")
    raise TimeoutError(f"External signer operation {operation_id} timed out waiting for approval.")


async def revoke_connection(user_id: str, connection_id: str) -> ExternalSignerConnection:
    connection = await get_connection_for_user(user_id, connection_id)
    if not connection:
        raise ValueError("External signer connection not found.")
    if connection.status != "revoked" and connection.remote_signer_pubkey:
        try:
            await request_signer(
                connection,
                "logout",
                [],
                purpose="logout",
                allow_unconnected=True,
            )
        except Exception as exc:
            logger.info(f"[externalsigner] Logout courtesy request was not delivered: {exc}")
    connection.status = "revoked"
    connection.encrypted_client_secret = ""
    connection.encrypted_connect_secret = None
    connection.encrypted_last_error = None
    connection.pairing_expires_at = None
    await update_connection(connection)
    await delete_connection_operations(connection.id)
    mark_runtime_state_dirty()
    return connection


async def retry_connection(user_id: str, connection_id: str) -> SignerOperation | None:
    connection = await get_connection_for_user(user_id, connection_id)
    if not connection:
        raise ValueError("External signer connection not found.")
    if connection.status == "revoked":
        raise ValueError("Revoked connections cannot be retried; pair a new client.")
    connection.encrypted_last_error = None
    if connection.mode == "nostrconnect" and not connection.remote_signer_pubkey:
        connection.encrypted_connect_secret = _encrypt_required(secrets.token_urlsafe(32))
        connection.pairing_expires_at = datetime.now(timezone.utc) + timedelta(
            seconds=PAIRING_TTL_SECONDS
        )
        connection.status = "awaiting_signer"
        await update_connection(connection)
        mark_runtime_state_dirty()
        try:
            await _ensure_connection_relays(connection)
        except Exception as exc:
            connection.encrypted_connect_secret = None
            connection.pairing_expires_at = None
            await _fail_connection(connection, f"Pairing relay connection failed: {exc}")
            raise ValueError(
                "The pairing relay could not be reached. Check the relay and retry."
            ) from exc
        return None
    connection.status = "connecting"
    await update_connection(connection)
    mark_runtime_state_dirty()
    return await _start_bunker_connect(connection)


async def run_maintenance(*, force: bool = False) -> None:
    monotonic_now = time.monotonic()
    if not force and monotonic_now < runtime_state.next_maintenance_at:
        return
    now = datetime.now(timezone.utc)
    stale_before = now - timedelta(seconds=OPERATION_TIMEOUT_SECONDS)
    for operation in await get_stale_operations(stale_before):
        await _fail_operation(operation, "Signer request expired before a final response arrived.")
        if operation.purpose in {"connect", "get_public_key", "identity_proof"}:
            connection = await get_connection(operation.connection_id)
            if connection and connection.status not in {"connected", "revoked"}:
                await _fail_connection(
                    connection, "Signer pairing timed out. Retry the connection."
                )
    for connection in await get_expired_pairings(now):
        connection.encrypted_connect_secret = None
        connection.pairing_expires_at = None
        await _fail_connection(connection, "Pairing QR expired. Retry to create a new one.")
    await delete_terminal_operations_before(now - timedelta(days=OPERATION_RETENTION_DAYS))
    runtime_state.next_maintenance_at = monotonic_now + MAINTENANCE_INTERVAL_SECONDS


async def _enforce_connection_limit(user_id: str) -> None:
    active = await count_active_connections_for_user(user_id)
    if active >= MAX_ACTIVE_CONNECTIONS_PER_ACCOUNT:
        raise SignerCapacityError(
            f"An account can have at most {MAX_ACTIVE_CONNECTIONS_PER_ACCOUNT} active signer "
            "connections. Revoke one before adding another."
        )


async def _validate_relay_target(relay: str) -> None:
    if settings.debug:
        return
    await asyncio.to_thread(validate_relay_network_target, relay)


async def _enforce_operation_limits(connection_id: str, purpose: str) -> None:
    if purpose != "user":
        return
    await run_maintenance()
    open_operations = await count_open_operations_for_connection(connection_id)
    if open_operations >= MAX_OPEN_OPERATIONS_PER_CONNECTION:
        raise SignerCapacityError(
            "This signer already has too many requests waiting for a response. "
            "Approve, reject or allow them to expire before sending more."
        )
    recent = await count_recent_operations_for_connection(
        connection_id,
        datetime.now(timezone.utc) - timedelta(minutes=1),
    )
    if recent >= MAX_USER_REQUESTS_PER_MINUTE:
        raise SignerRateLimitError(
            f"This signer accepts at most {MAX_USER_REQUESTS_PER_MINUTE} requests per minute."
        )


async def run_nip46_runtime() -> None:
    while True:
        try:
            await refresh_runtime_state()
            await process_transport_events()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning(f"[externalsigner] NIP-46 runtime error: {exc}")
            await asyncio.sleep(1)
        await asyncio.sleep(0.2)


async def refresh_runtime_state(*, force: bool = False) -> None:
    await run_maintenance()
    now = time.monotonic()
    if not force and now < runtime_state.next_refresh_at:
        return
    connections = await get_runtime_connections()
    if not connections and _transport is None:
        runtime_state.relays.clear()
        runtime_state.subscribed_pubkeys.clear()
        runtime_state.next_refresh_at = now + REFRESH_INTERVAL_SECONDS
        return
    transport = await asyncio.to_thread(get_transport)
    routes: dict[str, list[str]] = {}
    for connection in connections:
        for relay in connection.relays:
            routes.setdefault(relay, []).append(connection.client_pubkey)
    await asyncio.to_thread(transport.reconcile, routes, SUBSCRIPTION_ID)
    relays = set(routes)
    pubkeys = {connection.client_pubkey for connection in connections}
    runtime_state.relays = relays
    runtime_state.subscribed_pubkeys = pubkeys
    runtime_state.next_refresh_at = now + REFRESH_INTERVAL_SECONDS


async def process_transport_events() -> None:
    transport = _transport
    if transport is None:
        return
    for event in transport.take_events(SUBSCRIPTION_ID):
        event_id = str(event.get("id", ""))
        if not event_id or event_id in runtime_state.seen_event_ids:
            continue
        try:
            await handle_response_event(event)
        except Exception as exc:
            logger.warning(f"[externalsigner] Ignoring invalid NIP-46 response: {exc}")
        finally:
            runtime_state.seen_event_ids.add(event_id)
            if len(runtime_state.seen_event_ids) > 4096:
                runtime_state.seen_event_ids.clear()


async def handle_response_event(event: dict[str, Any]) -> None:
    if len(json.dumps(event, ensure_ascii=False).encode()) > MAX_RESPONSE_BYTES:
        raise ValueError("NIP-46 response exceeds the 512 KiB limit.")
    client_pubkey = _extract_recipient(event)
    connection = await get_connection_by_client_pubkey(client_pubkey)
    if not connection or connection.status == "revoked":
        raise ValueError("Response does not match an active client.")
    client_secret = _connection_client_secret(connection)
    if connection.mode == "nostrconnect" and not connection.remote_signer_pubkey:
        await _handle_nostrconnect_handshake(connection, client_secret, event)
        return
    if not connection.remote_signer_pubkey:
        raise ValueError("Connection has no remote signer public key.")
    payload = decrypt_response_payload(
        event,
        client_secret,
        connection.remote_signer_pubkey,
    )
    request_id = payload.get("id")
    if not isinstance(request_id, str):
        raise ValueError("Response has no request id.")
    operation = await get_operation_by_request_id(request_id)
    if not operation or operation.connection_id != connection.id:
        raise ValueError("Response does not match a pending operation.")
    if operation.status in TERMINAL_OPERATION_STATUSES:
        return
    if operation.status == "processing":
        return
    _validate_response_payload(operation, payload)
    response_event_id = str(event["id"])
    if not await claim_operation_response(request_id, response_event_id):
        return
    operation.status = "processing"
    operation.response_event_id = response_event_id
    if payload.get("result") == "auth_url" and payload.get("error"):
        auth_url = _validate_auth_url(str(payload["error"]))
        operation.status = "auth_required"
        operation.encrypted_auth_url = _encrypt_required(auth_url)
        await update_operation(operation)
        return
    if payload.get("error") not in {None, ""}:
        message = str(payload["error"])
        await _fail_operation(operation, message)
        if operation.purpose in {"connect", "get_public_key", "identity_proof"}:
            await _fail_connection(connection, message)
        return
    if "result" not in payload:
        raise ValueError("Response has neither a result nor an error.")
    result = payload.get("result")
    operation.status = "complete"
    operation.encrypted_result = encrypt_json(result)
    operation.encrypted_error = None
    operation.encrypted_auth_url = None
    await update_operation(operation)
    connection.last_used_at = datetime.now(timezone.utc)
    await update_connection(connection)
    try:
        await _advance_bootstrap(connection, operation, result)
    except Exception as exc:
        if operation.purpose in {"connect", "get_public_key", "identity_proof"}:
            await _fail_connection(connection, f"Signer verification failed: {exc}")
        raise
    finally:
        operation.encrypted_params = encrypt_json([])
        await update_operation(operation)


async def _handle_nostrconnect_handshake(
    connection: ExternalSignerConnection,
    client_secret: str,
    event: dict[str, Any],
) -> None:
    if _pairing_expired(connection):
        raise ValueError("NostrConnect pairing request has expired; retry to create a new one.")
    payload = decrypt_response_payload(event, client_secret)
    expected_secret = decrypt_secret(connection.encrypted_connect_secret)
    if not expected_secret or payload.get("result") != expected_secret:
        raise ValueError("NostrConnect response did not return the pairing secret.")
    if payload.get("error") not in {None, ""}:
        raise ValueError(str(payload["error"]))
    remote_signer_pubkey = normalize_hex_pubkey(str(event.get("pubkey", "")))
    if not await claim_nostrconnect_handshake(connection.id, remote_signer_pubkey):
        return
    connection.remote_signer_pubkey = remote_signer_pubkey
    connection.encrypted_connect_secret = None
    connection.pairing_expires_at = None
    connection.status = "verifying"
    connection.encrypted_last_error = None
    await update_connection(connection)
    mark_runtime_state_dirty()
    try:
        await request_signer(
            connection,
            "get_public_key",
            [],
            purpose="get_public_key",
            allow_unconnected=True,
        )
    except Exception as exc:
        await _fail_connection(connection, f"Identity request failed: {exc}")
        raise


async def _advance_bootstrap(
    connection: ExternalSignerConnection,
    operation: SignerOperation,
    result: Any,
) -> None:
    if operation.purpose == "connect":
        connect_secret = decrypt_secret(connection.encrypted_connect_secret)
        if result not in {"ack", connect_secret}:
            await _fail_connection(
                connection, "Remote signer returned an invalid connect acknowledgement."
            )
            return
        connection.encrypted_connect_secret = None
        connection.status = "verifying"
        connection.encrypted_last_error = None
        await update_connection(connection)
        await request_signer(
            connection,
            "get_public_key",
            [],
            purpose="get_public_key",
            allow_unconnected=True,
        )
        return
    if operation.purpose == "get_public_key":
        connection.user_pubkey = normalize_hex_pubkey(str(result))
        connection.status = "verifying"
        await update_connection(connection)
        proof_event = build_identity_proof_event(connection.id, secrets.token_hex(32))
        await request_signer(
            connection,
            "sign_event",
            [json.dumps(proof_event, separators=(",", ":"))],
            purpose="identity_proof",
            allow_unconnected=True,
        )
        return
    if operation.purpose == "identity_proof":
        if not connection.user_pubkey or not isinstance(result, str):
            await _fail_connection(connection, "Remote signer returned an invalid identity proof.")
            return
        params = decrypt_json(operation.encrypted_params)
        unsigned_event = _parse_unsigned_event(params)
        verify_identity_proof(result, connection.user_pubkey, unsigned_event)
        connection.status = "connected"
        connection.proof_verified_at = datetime.now(timezone.utc)
        connection.encrypted_last_error = None
        await update_connection(connection)
        await request_signer(
            connection,
            "switch_relays",
            [],
            purpose="switch_relays",
        )
        return
    if operation.purpose == "switch_relays" and result is not None:
        try:
            relays = json.loads(result) if isinstance(result, str) else result
            if not isinstance(relays, list):
                raise ValueError("switch_relays result is not a list.")
            connection.relays = normalize_relay_urls([str(relay) for relay in relays])
            await update_connection(connection)
            mark_runtime_state_dirty()
        except Exception as exc:
            connection.encrypted_last_error = _encrypt_required(
                f"Signer relay update was ignored: {exc}"
            )
            await update_connection(connection)


async def _start_bunker_connect(connection: ExternalSignerConnection) -> SignerOperation:
    if not connection.remote_signer_pubkey:
        raise ValueError("Bunker connection has no remote signer public key.")
    secret = decrypt_secret(connection.encrypted_connect_secret) or ""
    metadata = json.dumps(
        {
            "name": "LNbits External Signer",
            "url": "https://github.com/TheCryptoDonkey/externalsigner",
        },
        separators=(",", ":"),
    )
    return await request_signer(
        connection,
        "connect",
        [
            connection.remote_signer_pubkey,
            secret,
            ",".join(connection.permissions),
            metadata,
        ],
        purpose="connect",
        allow_unconnected=True,
    )


async def _publish_operation(
    connection: ExternalSignerConnection, operation: SignerOperation
) -> SignerOperation:
    try:
        await _ensure_connection_relays(connection)
        params = decrypt_json(operation.encrypted_params)
        if not isinstance(params, list):
            raise ValueError("Stored NIP-46 request parameters are invalid.")
        event = build_request_event(
            _connection_client_secret(connection),
            connection.remote_signer_pubkey or "",
            operation.request_id,
            operation.method,
            params,
        )
        transport = await asyncio.to_thread(get_transport)
        await asyncio.to_thread(transport.publish, event, connection.relays)
        operation.status = "sent"
        return await update_operation(operation)
    except Exception as exc:
        await _fail_operation(operation, f"Request publication failed: {exc}")
        if operation.purpose in {"connect", "get_public_key", "identity_proof"}:
            await _fail_connection(connection, f"Request publication failed: {exc}")
        return operation


async def _ensure_connection_relays(connection: ExternalSignerConnection) -> None:
    await refresh_runtime_state(force=True)
    if not all(relay in runtime_state.relays for relay in connection.relays):
        raise RuntimeError("External signer relay routes could not be established.")


def _validate_request_policy(
    connection: ExternalSignerConnection,
    method: str,
    params: list[Any],
    purpose: str,
) -> None:
    internal_methods = {"connect", "logout", "ping", "switch_relays"}
    if method not in internal_methods and method not in connection.permissions:
        if method != "sign_event":
            raise PermissionError(f"Connection does not grant {method}.")
    if method == "sign_event":
        event = _parse_unsigned_event(params)
        kind = event.get("kind")
        if not isinstance(kind, int) or isinstance(kind, bool) or not 0 <= kind <= 65535:
            raise ValueError("Unsigned event has an invalid kind.")
        if f"sign_event:{kind}" not in connection.permissions:
            raise PermissionError(f"Connection does not grant sign_event:{kind}.")
        if any(field in event for field in ("id", "pubkey", "sig")):
            raise ValueError("Unsigned event must not include id, pubkey or sig.")
        if not isinstance(event.get("content"), str):
            raise ValueError("Unsigned event content must be a string.")
        if not isinstance(event.get("tags"), list):
            raise ValueError("Unsigned event tags must be an array.")
        created_at = event.get("created_at")
        if not isinstance(created_at, int) or isinstance(created_at, bool) or created_at < 0:
            raise ValueError("Unsigned event created_at must be Unix seconds.")
    elif method in {"get_public_key", "ping", "switch_relays", "logout"}:
        if params:
            raise ValueError(f"{method} does not accept parameters.")
    elif method == "connect":
        if purpose != "connect" or len(params) < 2:
            raise ValueError("Invalid internal connect request.")
    elif method.startswith("nip04_") or method.startswith("nip44_"):
        if len(params) != 2 or not all(isinstance(value, str) for value in params):
            raise ValueError(f"{method} requires a public key and a string payload.")
        normalize_hex_pubkey(params[0])
    if len(json.dumps(params, ensure_ascii=False).encode()) > MAX_REQUEST_BYTES:
        raise ValueError("NIP-46 request exceeds the 256 KiB limit.")


def _parse_unsigned_event(params: object) -> dict[str, Any]:
    if not isinstance(params, list) or not params:
        raise ValueError("sign_event requires an unsigned event.")
    raw = params[0]
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except Exception as exc:
            raise ValueError("Unsigned event is not valid JSON.") from exc
    if not isinstance(raw, dict):
        raise ValueError("Unsigned event must be an object.")
    return raw


def _extract_recipient(event: dict[str, Any]) -> str:
    recipients = [
        tag[1]
        for tag in event.get("tags", [])
        if isinstance(tag, list) and len(tag) >= 2 and tag[0] == "p"
    ]
    if len(recipients) != 1:
        raise ValueError("NIP-46 response must have exactly one recipient.")
    return normalize_hex_pubkey(str(recipients[0]))


def _validate_auth_url(value: str) -> str:
    if value != value.strip() or any(ord(character) < 32 for character in value):
        raise ValueError("Signer authentication URL contains unsafe whitespace.")
    if len(value) > 4096:
        raise ValueError("Signer authentication URL is too long.")
    if "\\" in value:
        raise ValueError("Signer authentication URL contains an unsafe backslash.")
    parsed = urlsplit(value)
    if parsed.scheme != "https" and not (
        settings.debug
        and parsed.scheme == "http"
        and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    ):
        raise ValueError("Signer authentication URL must use HTTPS.")
    if not parsed.hostname:
        raise ValueError("Signer authentication URL is invalid.")
    if parsed.username or parsed.password:
        raise ValueError("Signer authentication URL must not contain credentials.")
    return value


def _validate_response_payload(operation: SignerOperation, payload: dict[str, Any]) -> None:
    error = payload.get("error")
    if error is not None and not isinstance(error, str):
        raise ValueError("NIP-46 response error must be a string.")
    if isinstance(error, str) and len(error.encode()) > 8192:
        raise ValueError("NIP-46 response error is too long.")
    if payload.get("result") == "auth_url" and isinstance(error, str) and error:
        _validate_auth_url(error)
        return
    if "result" not in payload and error in {None, ""}:
        raise ValueError("Response has neither a result nor an error.")
    if "result" not in payload:
        return
    result = payload.get("result")
    if result is None and operation.method == "switch_relays":
        return
    if not isinstance(result, str):
        raise ValueError("NIP-46 response result must be a string.")
    if operation.method == "ping" and result != "pong":
        raise ValueError("NIP-46 ping response must be pong.")
    if len(result.encode()) > MAX_RESPONSE_BYTES:
        raise ValueError("NIP-46 response result exceeds the 512 KiB limit.")


def _connection_client_secret(connection: ExternalSignerConnection) -> str:
    secret = decrypt_secret(connection.encrypted_client_secret)
    if not secret:
        raise ValueError("External signer client capability is unavailable.")
    return secret


def _pairing_expired(connection: ExternalSignerConnection) -> bool:
    expires_at = connection.pairing_expires_at
    if expires_at is None:
        return False
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return expires_at <= datetime.now(timezone.utc)


def _encrypt_required(value: str) -> str:
    encrypted = encrypt_secret(value)
    if not encrypted:
        raise ValueError("Failed to encrypt external signer secret.")
    return encrypted


async def _fail_operation(operation: SignerOperation, message: str) -> SignerOperation:
    operation.status = "failed"
    operation.encrypted_params = encrypt_json([])
    operation.encrypted_error = _encrypt_required(_safe_message(message))
    operation.encrypted_auth_url = None
    return await update_operation(operation)


async def _fail_connection(
    connection: ExternalSignerConnection, message: str
) -> ExternalSignerConnection:
    connection.status = "error"
    connection.encrypted_last_error = _encrypt_required(_safe_message(message))
    return await update_connection(connection)


def _safe_message(message: str) -> str:
    cleaned = " ".join(str(message).split())
    return cleaned[:8192] or "External signer request failed."
