import json
import os
import sys
from pathlib import Path
from uuid import uuid4

import pytest
from lnbits.core.helpers import run_migration
from nostr_sdk import Keys

from externalsigner.crud import get_connection, get_operation
from externalsigner.helpers import PROOF_EVENT_KIND, decrypt_json
from externalsigner.models import CreateBunkerConnection
from externalsigner.protocol import derive_pubkey, verify_signed_event
from externalsigner.services import (
    create_bunker_connection,
    handle_response_event,
    request_signer,
    set_transport,
)

from .fakes import FakeTransport

NOSTR_BUNKER_PATH = os.getenv("NOSTR_BUNKER_PATH")
if not NOSTR_BUNKER_PATH:
    pytest.skip(
        "Set NOSTR_BUNKER_PATH to run interop against the upstream LNbits signer.",
        allow_module_level=True,
    )

sys.path.insert(0, str(Path(NOSTR_BUNKER_PATH).resolve().parent))

import nostr_bunker.migrations as bunker_migrations  # noqa: E402
import nostr_bunker.services as bunker_services  # noqa: E402
from nostr_bunker.crud import (  # noqa: E402
    create_bunkers_data,
    create_url_data,
)
from nostr_bunker.crud import (  # noqa: E402
    db as bunker_db,
)
from nostr_bunker.models import CreateBunkersData, CreateUrlData  # noqa: E402


def key_hex() -> str:
    return Keys.generate().secret_key().to_hex()


@pytest.mark.asyncio
@pytest.mark.interop
async def test_full_bootstrap_and_sign_event_against_upstream_lnbits_bunker(
    monkeypatch,
):
    if os.path.isfile(bunker_db.path):
        os.remove(bunker_db.path)
    async with bunker_db.connect() as connection:
        await run_migration(connection, bunker_migrations, "nostr_bunker")

    signer_secret = key_hex()
    signer_pubkey = derive_pubkey(signer_secret)
    bunker = await create_bunkers_data(
        uuid4().hex,
        CreateBunkersData(name="Upstream interop signer", nsec=signer_secret),
    )
    await create_url_data(
        bunker.id,
        CreateUrlData(
            name="External Signer interop",
            relays=["wss://relay.example"],
            permissions=[
                "get_public_key",
                f"sign_event:{PROOF_EVENT_KIND}",
                "sign_event:0",
            ],
            auto_sign=True,
            confirm_sign=False,
            can_write=True,
            secret="one-use-interop",
        ),
    )

    signer_responses: list[str] = []
    monkeypatch.setattr(
        bunker_services.nostr_client.relay_manager,
        "publish_message",
        signer_responses.append,
    )
    monkeypatch.setattr(
        bunker_services.nostr_client.relay_manager,
        "add_relay",
        lambda *_args, **_kwargs: None,
    )

    transport = FakeTransport()
    set_transport(transport)
    connection, _operation = await create_bunker_connection(
        uuid4().hex,
        CreateBunkerConnection(
            name="Upstream LNbits bunker",
            bunker_uri=(
                f"bunker://{signer_pubkey}"
                "?relay=wss%3A%2F%2Frelay.example&secret=one-use-interop"
            ),
            permissions=["sign_event:0"],
        ),
    )

    published_index = 0
    for _ in range(4):
        request_event = transport.published[published_index]
        published_index += 1
        await bunker_services._handle_request_event(request_event)
        response_message = json.loads(signer_responses.pop(0))
        assert response_message[0] == "EVENT"
        await handle_response_event(response_message[1])

    connected = await get_connection(connection.id)
    assert connected
    assert connected.status == "connected"
    assert connected.remote_signer_pubkey == signer_pubkey
    assert connected.user_pubkey == signer_pubkey
    assert connected.proof_verified_at is not None

    unsigned = {
        "kind": 0,
        "content": '{"name":"interop"}',
        "tags": [],
        "created_at": 1_700_000_000,
    }
    operation = await request_signer(
        connected,
        "sign_event",
        [json.dumps(unsigned, separators=(",", ":"))],
    )
    request_event = transport.published[published_index]
    await bunker_services._handle_request_event(request_event)
    response_message = json.loads(signer_responses.pop(0))
    await handle_response_event(response_message[1])

    complete = await get_operation(operation.id)
    assert complete and complete.status == "complete"
    result = decrypt_json(complete.encrypted_result)
    assert isinstance(result, str)
    signed = verify_signed_event(result, signer_pubkey, unsigned)
    assert signed["pubkey"] == signer_pubkey
