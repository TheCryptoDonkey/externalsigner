import pytest
from lnbits.settings import settings

from externalsigner.helpers import (
    PROOF_EVENT_KIND,
    build_nostrconnect_uri,
    decrypt_secret,
    encrypt_secret,
    normalize_permissions,
    normalize_relay_url,
    parse_bunker_uri,
)


def test_parse_bunker_uri_normalizes_pubkey_relays_and_secret():
    parsed = parse_bunker_uri(
        "bunker://"
        + "AB" * 32
        + "?relay=wss%3A%2F%2FRelay.Example&relay=wss%3A%2F%2Frelay.example&secret=once"
    )
    assert parsed.remote_signer_pubkey == "ab" * 32
    assert parsed.relays == ["wss://relay.example"]
    assert parsed.secret == "once"


@pytest.mark.parametrize(
    "uri",
    [
        "https://example.com",
        "bunker://not-a-key?relay=wss://relay.example",
        "bunker://" + "11" * 32,
        "bunker://" + "11" * 32 + "?relay=ws://public.example",
        "bunker://" + "11" * 32 + "?relay=wss://user:pass@relay.example",
        "bunker://" + "11" * 32 + "/unexpected?relay=wss://relay.example",
    ],
)
def test_parse_bunker_uri_rejects_malformed_or_unsafe_input(uri):
    with pytest.raises(ValueError):
        parse_bunker_uri(uri)


def test_localhost_plain_websocket_is_allowed_for_development_only(monkeypatch):
    assert normalize_relay_url("ws://localhost:7777/") == "ws://localhost:7777/"
    with pytest.raises(ValueError, match="must use wss"):
        normalize_relay_url("ws://relay.example")
    monkeypatch.setattr(settings, "debug", False)
    with pytest.raises(ValueError, match="debug mode"):
        normalize_relay_url("ws://localhost:7777/")


def test_production_rejects_private_or_local_wss_relay_targets(monkeypatch):
    monkeypatch.setattr(settings, "debug", False)
    for relay in ("wss://127.0.0.1", "wss://[::1]", "wss://signer.internal"):
        with pytest.raises(ValueError, match=r"public|local network"):
            normalize_relay_url(relay)


def test_permissions_are_kind_scoped_deduplicated_and_include_identity_proof():
    permissions = normalize_permissions(["sign_event:1", "sign_event:1", "nip44_encrypt"])
    assert permissions.count("sign_event:1") == 1
    assert "get_public_key" in permissions
    assert f"sign_event:{PROOF_EVENT_KIND}" in permissions
    with pytest.raises(ValueError, match="Broad sign_event"):
        normalize_permissions(["sign_event"])
    with pytest.raises(ValueError, match="Invalid kind"):
        normalize_permissions(["sign_event:-1"])


def test_nostrconnect_uri_contains_repeated_relays_secret_and_exact_permissions():
    uri = build_nostrconnect_uri(
        "11" * 32,
        ["wss://one.example", "wss://two.example"],
        "pair-secret",
        ["get_public_key", "sign_event:1"],
        "LNbits shop",
    )
    assert uri.startswith("nostrconnect://" + "11" * 32 + "?")
    assert uri.count("relay=") == 2
    assert "secret=pair-secret" in uri
    assert "sign_event%3A1" in uri


def test_secret_envelope_is_authenticated_and_handles_block_aligned_keys():
    secret = "11" * 32
    encrypted = encrypt_secret(secret)
    assert encrypted and encrypted != secret
    assert decrypt_secret(encrypted) == secret
    replacement = "A" if encrypted[-1] != "A" else "B"
    with pytest.raises(ValueError):
        decrypt_secret(encrypted[:-1] + replacement)
