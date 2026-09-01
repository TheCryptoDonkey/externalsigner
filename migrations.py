async def m001_initial(db):
    await db.execute(f"""
        CREATE TABLE externalsigner.connections (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            mode TEXT NOT NULL,
            remote_signer_pubkey TEXT,
            user_pubkey TEXT,
            client_pubkey TEXT NOT NULL UNIQUE,
            encrypted_client_secret TEXT NOT NULL,
            encrypted_connect_secret TEXT,
            relays TEXT NOT NULL DEFAULT '[]',
            permissions TEXT NOT NULL DEFAULT '[]',
            status TEXT NOT NULL DEFAULT 'pending',
            encrypted_last_error TEXT,
            pairing_expires_at TIMESTAMP,
            proof_verified_at TIMESTAMP,
            last_used_at TIMESTAMP,
            created_at TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
            updated_at TIMESTAMP NOT NULL DEFAULT {db.timestamp_now}
        );
        """)
    await db.execute(f"""
        CREATE TABLE externalsigner.operations (
            id TEXT PRIMARY KEY,
            connection_id TEXT NOT NULL,
            request_id TEXT NOT NULL UNIQUE,
            method TEXT NOT NULL,
            purpose TEXT NOT NULL DEFAULT 'user',
            encrypted_params TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            encrypted_result TEXT,
            encrypted_error TEXT,
            encrypted_auth_url TEXT,
            response_event_id TEXT,
            created_at TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
            updated_at TIMESTAMP NOT NULL DEFAULT {db.timestamp_now}
        );
        """)
    if db.type != "SQLITE":
        await db.execute(
            "CREATE INDEX externalsigner_user_id_idx " "ON externalsigner.connections (user_id);"
        )
        await db.execute(
            "CREATE INDEX externalsigner_operation_connection_idx "
            "ON externalsigner.operations (connection_id);"
        )


async def m002_query_indexes(db):
    if db.type == "SQLITE":
        await db.execute(
            "CREATE INDEX IF NOT EXISTS externalsigner.externalsigner_user_status_idx "
            "ON connections (user_id, status);"
        )
        await db.execute(
            "CREATE INDEX IF NOT EXISTS externalsigner.externalsigner_operation_connection_idx "
            "ON operations (connection_id);"
        )
        await db.execute(
            "CREATE INDEX IF NOT EXISTS externalsigner.externalsigner_operation_status_updated_idx "
            "ON operations (status, updated_at);"
        )
        await db.execute(
            "CREATE INDEX IF NOT EXISTS externalsigner.externalsigner_operation_rate_idx "
            "ON operations (connection_id, created_at);"
        )
        await db.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS externalsigner.externalsigner_response_event_idx "
            "ON operations (response_event_id);"
        )
        return
    await db.execute(
        "CREATE INDEX IF NOT EXISTS externalsigner_user_status_idx "
        "ON externalsigner.connections (user_id, status);"
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS externalsigner_operation_connection_idx "
        "ON externalsigner.operations (connection_id);"
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS externalsigner_operation_status_updated_idx "
        "ON externalsigner.operations (status, updated_at);"
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS externalsigner_operation_rate_idx "
        "ON externalsigner.operations (connection_id, created_at);"
    )
    await db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS externalsigner_response_event_idx "
        "ON externalsigner.operations (response_event_id);"
    )
