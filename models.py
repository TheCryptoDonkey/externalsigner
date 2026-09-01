from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field, StrictStr, validator

from .helpers import normalize_permissions, normalize_relay_urls


class StrictApiModel(BaseModel):
    class Config:
        extra = "forbid"


def _clean_connection_name(value: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError("Connection name must not be blank.")
    return cleaned


class CreateBunkerConnection(StrictApiModel):
    name: str = Field(min_length=1, max_length=120)
    bunker_uri: str = Field(min_length=1, max_length=4096)
    permissions: list[str] = Field(default_factory=list)

    _name = validator("name", allow_reuse=True)(_clean_connection_name)
    _permissions = validator("permissions", allow_reuse=True)(normalize_permissions)


class CreateNostrConnectConnection(StrictApiModel):
    name: str = Field(min_length=1, max_length=120)
    relays: list[str] = Field(min_items=1, max_items=8)
    permissions: list[str] = Field(default_factory=list)

    _name = validator("name", allow_reuse=True)(_clean_connection_name)
    _relays = validator("relays", allow_reuse=True)(normalize_relay_urls)
    _permissions = validator("permissions", allow_reuse=True)(normalize_permissions)


class CreateSignerRequest(StrictApiModel):
    method: str = Field(min_length=1, max_length=64)
    params: list[StrictStr] = Field(default_factory=list, max_items=2)

    @validator("method")
    def validate_method(cls, value: str) -> str:
        method = value.strip()
        allowed = {
            "get_public_key",
            "nip04_decrypt",
            "nip04_encrypt",
            "nip44_decrypt",
            "nip44_encrypt",
            "ping",
            "sign_event",
            "switch_relays",
        }
        if method not in allowed:
            raise ValueError("Unsupported NIP-46 method.")
        return method


class ExternalSignerConnection(BaseModel):
    id: str
    user_id: str
    name: str
    mode: str
    remote_signer_pubkey: str | None = None
    user_pubkey: str | None = None
    client_pubkey: str
    encrypted_client_secret: str
    encrypted_connect_secret: str | None = None
    relays: list[str] = Field(default_factory=list)
    permissions: list[str] = Field(default_factory=list)
    status: str = "pending"
    encrypted_last_error: str | None = None
    pairing_expires_at: datetime | None = None
    proof_verified_at: datetime | None = None
    last_used_at: datetime | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @validator("mode")
    def validate_mode(cls, value: str) -> str:
        if value not in {"bunker", "nostrconnect"}:
            raise ValueError("Unknown external signer connection mode.")
        return value


class ConnectionView(BaseModel):
    id: str
    name: str
    mode: str
    remote_signer_pubkey: str | None = None
    user_pubkey: str | None = None
    client_pubkey: str
    relays: list[str] = Field(default_factory=list)
    permissions: list[str] = Field(default_factory=list)
    status: str
    last_error: str | None = None
    pairing_expires_at: datetime | None = None
    proof_verified_at: datetime | None = None
    last_used_at: datetime | None = None
    created_at: datetime
    updated_at: datetime
    pairing_uri: str | None = None


class SignerOperation(BaseModel):
    id: str
    connection_id: str
    request_id: str
    method: str
    purpose: str = "user"
    encrypted_params: str
    status: str = "pending"
    encrypted_result: str | None = None
    encrypted_error: str | None = None
    encrypted_auth_url: str | None = None
    response_event_id: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class OperationView(BaseModel):
    id: str
    connection_id: str
    request_id: str
    method: str
    purpose: str
    status: str
    result: Any | None = None
    error: str | None = None
    auth_url: str | None = None
    response_event_id: str | None = None
    created_at: datetime
    updated_at: datetime


class ConnectionWithOperation(BaseModel):
    connection: ConnectionView
    operation: OperationView | None = None


class PermissionPreset(BaseModel):
    id: str
    name: str
    description: str
    permissions: list[str]
