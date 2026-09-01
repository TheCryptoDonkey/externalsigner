import json

import pytest
from nostr_sdk import Keys

from externalsigner.protocol import (
    build_identity_proof_event,
    build_request_event,
    decrypt_response_payload,
    derive_pubkey,
    verify_identity_proof,
)

from .fakes import make_response_event, sign_unsigned_event


def key_hex() -> str:
    return Keys.generate().secret_key().to_hex()


def test_request_response_round_trip_uses_authenticated_nip44():
    client_secret = key_hex()
    remote_secret = key_hex()
    remote_pubkey = derive_pubkey(remote_secret)
    request = build_request_event(
        client_secret,
        remote_pubkey,
        "request-1",
        "ping",
        [],
        created_at=1_700_000_000,
    )
    assert request["pubkey"] == derive_pubkey(client_secret)
    assert request["tags"] == [["p", remote_pubkey]]

    response = make_response_event(
        remote_secret,
        derive_pubkey(client_secret),
        {"id": "request-1", "result": "pong", "error": None},
    )
    assert decrypt_response_payload(response, client_secret, remote_pubkey) == {
        "id": "request-1",
        "result": "pong",
    }


def test_response_rejects_forged_author_wrong_recipient_and_tampering():
    client_secret = key_hex()
    remote_secret = key_hex()
    attacker_secret = key_hex()
    client_pubkey = derive_pubkey(client_secret)
    remote_pubkey = derive_pubkey(remote_secret)
    forged = make_response_event(
        attacker_secret,
        client_pubkey,
        {"id": "x", "result": "forged"},
    )
    with pytest.raises(ValueError, match="different remote signer"):
        decrypt_response_payload(forged, client_secret, remote_pubkey)

    wrong_recipient = make_response_event(
        remote_secret,
        client_pubkey,
        {"id": "x", "result": "wrong"},
        recipient=derive_pubkey(attacker_secret),
    )
    with pytest.raises(ValueError, match="not addressed"):
        decrypt_response_payload(wrong_recipient, client_secret, remote_pubkey)

    tampered = make_response_event(
        remote_secret,
        client_pubkey,
        {"id": "x", "result": "valid"},
    )
    tampered["content"] += "x"
    with pytest.raises(ValueError, match="invalid signature"):
        decrypt_response_payload(tampered, client_secret, remote_pubkey)


def test_identity_proof_requires_expected_user_signature_and_exact_event():
    user_secret = key_hex()
    other_secret = key_hex()
    unsigned = build_identity_proof_event("connection-1", "challenge")
    signed = sign_unsigned_event(unsigned, user_secret)
    verified = verify_identity_proof(json.dumps(signed), derive_pubkey(user_secret), unsigned)
    assert verified["pubkey"] == derive_pubkey(user_secret)

    with pytest.raises(ValueError, match="different user"):
        verify_identity_proof(json.dumps(signed), derive_pubkey(other_secret), unsigned)

    changed = dict(signed)
    changed["content"] = "changed"
    with pytest.raises(ValueError, match="changed the requested content"):
        verify_identity_proof(json.dumps(changed), derive_pubkey(user_secret), unsigned)
