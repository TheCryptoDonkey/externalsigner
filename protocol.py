import json
import time
from typing import Any

from coincurve import PrivateKey
from lnbits.utils.nostr import json_dumps, sign_event
from nostr_sdk import Event, Nip44Version, PublicKey, SecretKey, nip44_decrypt, nip44_encrypt

from .helpers import PROOF_EVENT_KIND, normalize_hex_pubkey

NIP46_KIND = 24133


def derive_pubkey(secret_hex: str) -> str:
    private_key = PrivateKey(bytes.fromhex(secret_hex))
    return private_key.public_key.format(compressed=True)[1:].hex()


def build_request_event(
    client_secret_hex: str,
    remote_signer_pubkey: str,
    request_id: str,
    method: str,
    params: list[Any],
    created_at: int | None = None,
) -> dict[str, Any]:
    remote_pubkey = normalize_hex_pubkey(remote_signer_pubkey)
    client_pubkey = derive_pubkey(client_secret_hex)
    payload = json_dumps({"id": request_id, "method": method, "params": params})
    encrypted = nip44_encrypt(
        SecretKey.parse(client_secret_hex),
        PublicKey.parse(remote_pubkey),
        payload,
        Nip44Version.V2,
    )
    unsigned = {
        "kind": NIP46_KIND,
        "content": encrypted,
        "tags": [["p", remote_pubkey]],
        "created_at": created_at or int(time.time()),
    }
    return sign_event(unsigned, client_pubkey, PrivateKey(bytes.fromhex(client_secret_hex)))


def validate_response_event(
    event: dict[str, Any],
    client_pubkey: str,
    remote_signer_pubkey: str | None = None,
) -> str:
    if event.get("kind") != NIP46_KIND:
        raise ValueError("Unexpected Nostr event kind.")
    try:
        valid = Event.from_json(json.dumps(event, separators=(",", ":"))).verify()
    except Exception as exc:
        raise ValueError("Malformed NIP-46 response event.") from exc
    if not valid:
        raise ValueError("NIP-46 response has an invalid signature.")
    author = normalize_hex_pubkey(str(event.get("pubkey", "")))
    if remote_signer_pubkey and author != normalize_hex_pubkey(remote_signer_pubkey):
        raise ValueError("NIP-46 response came from a different remote signer.")
    recipient = normalize_hex_pubkey(client_pubkey)
    if not any(
        isinstance(tag, list) and len(tag) >= 2 and tag[0] == "p" and tag[1] == recipient
        for tag in event.get("tags", [])
    ):
        raise ValueError("NIP-46 response is not addressed to this client.")
    return author


def decrypt_response_payload(
    event: dict[str, Any],
    client_secret_hex: str,
    remote_signer_pubkey: str | None = None,
) -> dict[str, Any]:
    client_pubkey = derive_pubkey(client_secret_hex)
    author = validate_response_event(event, client_pubkey, remote_signer_pubkey)
    try:
        plaintext = nip44_decrypt(
            SecretKey.parse(client_secret_hex),
            PublicKey.parse(author),
            str(event["content"]),
        )
        payload = json.loads(plaintext)
    except Exception as exc:
        raise ValueError("NIP-46 response could not be decrypted.") from exc
    if not isinstance(payload, dict):
        raise ValueError("NIP-46 response payload is not an object.")
    if "id" in payload and not isinstance(payload["id"], str):
        raise ValueError("NIP-46 response id is invalid.")
    return payload


def build_identity_proof_event(connection_id: str, challenge: str) -> dict[str, Any]:
    return {
        "kind": PROOF_EVENT_KIND,
        "content": "",
        "tags": [
            ["u", f"https://externalsigner.invalid/proof/{connection_id}"],
            ["method", "GET"],
            ["challenge", challenge],
        ],
        "created_at": int(time.time()),
    }


def verify_identity_proof(
    signed_event_json: str,
    expected_pubkey: str,
    unsigned_event: dict[str, Any],
) -> dict[str, Any]:
    return verify_signed_event(signed_event_json, expected_pubkey, unsigned_event)


def verify_signed_event(
    signed_event_json: str,
    expected_pubkey: str,
    unsigned_event: dict[str, Any],
) -> dict[str, Any]:
    try:
        signed_event = json.loads(signed_event_json)
    except Exception as exc:
        raise ValueError("Signer returned an invalid signed event.") from exc
    if not isinstance(signed_event, dict):
        raise ValueError("Signer returned an invalid signed event.")
    if normalize_hex_pubkey(str(signed_event.get("pubkey", ""))) != normalize_hex_pubkey(
        expected_pubkey
    ):
        raise ValueError("Signed event uses a different user public key.")
    for field in ("kind", "content", "tags", "created_at"):
        if signed_event.get(field) != unsigned_event.get(field):
            raise ValueError(f"Signed event changed the requested {field}.")
    try:
        valid = Event.from_json(json.dumps(signed_event, separators=(",", ":"))).verify()
    except Exception as exc:
        raise ValueError("Signed event is malformed.") from exc
    if not valid:
        raise ValueError("Signed event has an invalid signature.")
    return signed_event
