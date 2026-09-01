from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI
from lnbits.core.models.users import AccountId
from lnbits.decorators import check_account_id_exists
from nostr_sdk import Keys

from externalsigner import externalsigner_ext, services
from externalsigner.protocol import derive_pubkey
from externalsigner.services import set_transport

from .fakes import FakeTransport


def key_hex() -> str:
    return Keys.generate().secret_key().to_hex()


@pytest.mark.asyncio
async def test_account_api_creates_lists_and_isolates_bunker_connections():
    transport = FakeTransport()
    set_transport(transport)
    current_account = {"id": uuid4().hex}
    app = FastAPI()
    app.include_router(externalsigner_ext)

    async def account_override() -> AccountId:
        return AccountId(id=current_account["id"])

    app.dependency_overrides[check_account_id_exists] = account_override
    remote_pubkey = derive_pubkey(key_hex())
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/externalsigner/api/v1/connections/bunker",
            json={
                "name": "Counter signer",
                "bunker_uri": (
                    f"bunker://{remote_pubkey}" "?relay=wss%3A%2F%2Frelay.example&secret=one-use"
                ),
                "permissions": ["sign_event:0"],
            },
        )
        assert response.status_code == 201, response.text
        payload = response.json()
        connection_id = payload["connection"]["id"]
        assert payload["connection"]["status"] == "connecting"
        assert payload["connection"]["pairing_expires_at"] is None
        assert payload["operation"]["status"] == "sent"
        assert "secret" not in payload["connection"]
        assert "encrypted" not in response.text
        assert "one-use" not in response.text

        listed = await client.get("/externalsigner/api/v1/connections")
        assert listed.status_code == 200
        assert listed.headers["cache-control"] == "no-store"
        assert [item["id"] for item in listed.json()] == [connection_id]

        current_account["id"] = uuid4().hex
        hidden = await client.get(f"/externalsigner/api/v1/connections/{connection_id}")
        assert hidden.status_code == 404


@pytest.mark.asyncio
async def test_api_rejects_broad_signing_permission_before_publication():
    transport = FakeTransport()
    set_transport(transport)
    app = FastAPI()

    async def account_override() -> AccountId:
        return AccountId(id=uuid4().hex)

    app.dependency_overrides[check_account_id_exists] = account_override
    app.include_router(externalsigner_ext)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/externalsigner/api/v1/connections/nostrconnect",
            json={
                "name": "Too broad",
                "relays": ["wss://relay.example"],
                "permissions": ["sign_event"],
            },
        )

    assert response.status_code == 422
    assert transport.published == []


@pytest.mark.asyncio
async def test_api_rejects_blank_names_extra_fields_and_non_string_params():
    set_transport(FakeTransport())
    app = FastAPI()

    async def account_override() -> AccountId:
        return AccountId(id=uuid4().hex)

    app.dependency_overrides[check_account_id_exists] = account_override
    app.include_router(externalsigner_ext)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        blank = await client.post(
            "/externalsigner/api/v1/connections/nostrconnect",
            json={"name": "   ", "relays": ["wss://relay.example"], "permissions": []},
        )
        extra = await client.post(
            "/externalsigner/api/v1/connections/nostrconnect",
            json={
                "name": "Signer",
                "relays": ["wss://relay.example"],
                "permissions": [],
                "nsec": "must-never-be-accepted",
            },
        )
        non_string = await client.post(
            "/externalsigner/api/v1/connections/anything/requests",
            json={"method": "sign_event", "params": [123]},
        )

    assert blank.status_code == 422
    assert extra.status_code == 422
    assert non_string.status_code == 422


@pytest.mark.asyncio
async def test_api_enforces_active_connection_limit(monkeypatch):
    transport = FakeTransport()
    set_transport(transport)
    app = FastAPI()
    account_id = uuid4().hex

    async def account_override() -> AccountId:
        return AccountId(id=account_id)

    monkeypatch.setattr(services, "MAX_ACTIVE_CONNECTIONS_PER_ACCOUNT", 1)
    app.dependency_overrides[check_account_id_exists] = account_override
    app.include_router(externalsigner_ext)
    remote_pubkey = derive_pubkey(key_hex())
    payload = {
        "name": "Signer",
        "bunker_uri": f"bunker://{remote_pubkey}?relay=wss%3A%2F%2Frelay.example",
        "permissions": ["sign_event:0"],
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        first = await client.post("/externalsigner/api/v1/connections/bunker", json=payload)
        second = await client.post("/externalsigner/api/v1/connections/bunker", json=payload)

    assert first.status_code == 201
    assert second.status_code == 409
