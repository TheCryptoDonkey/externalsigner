from datetime import datetime, timezone
from typing import Any

from lnbits.db import Database
from lnbits.helpers import urlsafe_short_hash

from .models import ExternalSignerConnection, SignerOperation

db = Database("ext_externalsigner")


async def create_connection(data: ExternalSignerConnection) -> ExternalSignerConnection:
    await db.insert("externalsigner.connections", data)
    return data


async def new_connection(**kwargs) -> ExternalSignerConnection:
    connection = ExternalSignerConnection(id=urlsafe_short_hash(), **kwargs)
    return await create_connection(connection)


async def get_connection(connection_id: str) -> ExternalSignerConnection | None:
    return await db.fetchone(
        "SELECT * FROM externalsigner.connections WHERE id = :id",
        {"id": connection_id},
        ExternalSignerConnection,
    )


async def get_connection_for_user(
    user_id: str, connection_id: str
) -> ExternalSignerConnection | None:
    return await db.fetchone(
        """
        SELECT * FROM externalsigner.connections
        WHERE id = :id AND user_id = :user_id
        """,
        {"id": connection_id, "user_id": user_id},
        ExternalSignerConnection,
    )


async def get_connections_for_user(user_id: str) -> list[ExternalSignerConnection]:
    return await db.fetchall(
        """
        SELECT * FROM externalsigner.connections
        WHERE user_id = :user_id
        ORDER BY created_at DESC
        """,
        {"user_id": user_id},
        ExternalSignerConnection,
    )


async def count_active_connections_for_user(user_id: str) -> int:
    row: Any = await db.fetchone(
        """
        SELECT COUNT(*) AS count FROM externalsigner.connections
        WHERE user_id = :user_id AND status != 'revoked'
        """,
        {"user_id": user_id},
    )
    return int(row["count"] if row else 0)


async def get_runtime_connections() -> list[ExternalSignerConnection]:
    return await db.fetchall(
        """
        SELECT * FROM externalsigner.connections
        WHERE status NOT IN ('revoked')
          AND encrypted_client_secret != ''
        """,
        model=ExternalSignerConnection,
    )


async def get_connection_by_client_pubkey(
    client_pubkey: str,
) -> ExternalSignerConnection | None:
    return await db.fetchone(
        "SELECT * FROM externalsigner.connections WHERE client_pubkey = :client_pubkey",
        {"client_pubkey": client_pubkey},
        ExternalSignerConnection,
    )


async def update_connection(
    connection: ExternalSignerConnection,
) -> ExternalSignerConnection:
    connection.updated_at = datetime.now(timezone.utc)
    await db.update("externalsigner.connections", connection)
    return connection


async def claim_nostrconnect_handshake(connection_id: str, remote_signer_pubkey: str) -> bool:
    now = datetime.now(timezone.utc)
    result = await db.execute(
        """
        UPDATE externalsigner.connections
        SET remote_signer_pubkey = :remote_signer_pubkey,
            encrypted_connect_secret = NULL,
            pairing_expires_at = NULL,
            status = 'verifying',
            encrypted_last_error = NULL,
            updated_at = :updated_at
        WHERE id = :id
          AND mode = 'nostrconnect'
          AND status = 'awaiting_signer'
          AND remote_signer_pubkey IS NULL
        """,
        {
            "id": connection_id,
            "remote_signer_pubkey": remote_signer_pubkey,
            "updated_at": now,
        },
    )
    return result.rowcount == 1


async def delete_connection_operations(connection_id: str) -> None:
    await db.execute(
        "DELETE FROM externalsigner.operations WHERE connection_id = :connection_id",
        {"connection_id": connection_id},
    )


async def create_operation(
    connection_id: str,
    request_id: str,
    method: str,
    purpose: str,
    encrypted_params: str,
) -> SignerOperation:
    operation = SignerOperation(
        id=urlsafe_short_hash(),
        connection_id=connection_id,
        request_id=request_id,
        method=method,
        purpose=purpose,
        encrypted_params=encrypted_params,
    )
    await db.insert("externalsigner.operations", operation)
    return operation


async def get_operation(operation_id: str) -> SignerOperation | None:
    return await db.fetchone(
        "SELECT * FROM externalsigner.operations WHERE id = :id",
        {"id": operation_id},
        SignerOperation,
    )


async def get_operation_by_request_id(request_id: str) -> SignerOperation | None:
    return await db.fetchone(
        "SELECT * FROM externalsigner.operations WHERE request_id = :request_id",
        {"request_id": request_id},
        SignerOperation,
    )


async def claim_operation_response(request_id: str, response_event_id: str) -> bool:
    result = await db.execute(
        """
        UPDATE externalsigner.operations
        SET status = 'processing',
            response_event_id = :response_event_id,
            updated_at = :updated_at
        WHERE request_id = :request_id
          AND status IN ('pending', 'sent', 'auth_required')
        """,
        {
            "request_id": request_id,
            "response_event_id": response_event_id,
            "updated_at": datetime.now(timezone.utc),
        },
    )
    return result.rowcount == 1


async def get_operations_for_connection(connection_id: str) -> list[SignerOperation]:
    return await db.fetchall(
        """
        SELECT * FROM externalsigner.operations
        WHERE connection_id = :connection_id
        ORDER BY created_at DESC
        """,
        {"connection_id": connection_id},
        SignerOperation,
    )


async def count_open_operations_for_connection(connection_id: str) -> int:
    row: Any = await db.fetchone(
        """
        SELECT COUNT(*) AS count FROM externalsigner.operations
        WHERE connection_id = :connection_id
          AND status IN ('pending', 'sent', 'auth_required', 'processing')
        """,
        {"connection_id": connection_id},
    )
    return int(row["count"] if row else 0)


async def count_recent_operations_for_connection(connection_id: str, since: datetime) -> int:
    row: Any = await db.fetchone(
        """
        SELECT COUNT(*) AS count FROM externalsigner.operations
        WHERE connection_id = :connection_id AND created_at >= :since
        """,
        {"connection_id": connection_id, "since": since},
    )
    return int(row["count"] if row else 0)


async def get_stale_operations(before: datetime) -> list[SignerOperation]:
    return await db.fetchall(
        """
        SELECT * FROM externalsigner.operations
        WHERE status IN ('pending', 'sent', 'auth_required', 'processing')
          AND updated_at < :before
        """,
        {"before": before},
        SignerOperation,
    )


async def delete_terminal_operations_before(before: datetime) -> None:
    await db.execute(
        """
        DELETE FROM externalsigner.operations
        WHERE status IN ('complete', 'failed') AND updated_at < :before
        """,
        {"before": before},
    )


async def get_expired_pairings(before: datetime) -> list[ExternalSignerConnection]:
    return await db.fetchall(
        """
        SELECT * FROM externalsigner.connections
        WHERE mode = 'nostrconnect'
          AND status = 'awaiting_signer'
          AND pairing_expires_at IS NOT NULL
          AND pairing_expires_at <= :before
        """,
        {"before": before},
        ExternalSignerConnection,
    )


async def update_operation(operation: SignerOperation) -> SignerOperation:
    operation.updated_at = datetime.now(timezone.utc)
    await db.update("externalsigner.operations", operation)
    return operation
