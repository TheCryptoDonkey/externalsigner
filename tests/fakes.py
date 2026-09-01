import json
import time
from typing import Any

from coincurve import PrivateKey
from lnbits.utils.nostr import json_dumps, sign_event
from nostr_sdk import Event, Nip44Version, PublicKey, SecretKey, nip44_decrypt, nip44_encrypt

from externalsigner.protocol import NIP46_KIND, derive_pubkey


class FakeTransport:
    def __init__(self) -> None:
        self.relays: list[str] = []
        self.subscriptions: dict[str, list[str]] = {}
        self.published: list[dict[str, Any]] = []
        self.published_routes: list[list[str]] = []
        self.incoming: list[dict[str, Any]] = []
        self.closed = False

    def reconcile(self, routes: dict[str, list[str]], subscription_id: str) -> None:
        self.relays = sorted(routes)
        self.subscriptions = {
            f"{subscription_id}:{relay}": sorted(pubkeys) for relay, pubkeys in routes.items()
        }

    def publish(self, event: dict[str, Any], relays: list[str]) -> None:
        self.published.append(event)
        self.published_routes.append(list(relays))

    def take_events(self, _subscription_id: str) -> list[dict[str, Any]]:
        events = list(self.incoming)
        self.incoming.clear()
        return events

    def close(self) -> None:
        self.closed = True


def make_response_event(
    remote_secret: str,
    client_pubkey: str,
    payload: dict[str, Any],
    *,
    recipient: str | None = None,
    created_at: int | None = None,
) -> dict[str, Any]:
    remote_pubkey = derive_pubkey(remote_secret)
    encrypted = nip44_encrypt(
        SecretKey.parse(remote_secret),
        PublicKey.parse(client_pubkey),
        json_dumps(payload),
        Nip44Version.V2,
    )
    unsigned = {
        "kind": NIP46_KIND,
        "content": encrypted,
        "tags": [["p", recipient or client_pubkey]],
        "created_at": created_at or int(time.time()),
    }
    return sign_event(unsigned, remote_pubkey, PrivateKey(bytes.fromhex(remote_secret)))


def decrypt_request_event(event: dict[str, Any], remote_secret: str) -> dict[str, Any]:
    assert Event.from_json(json.dumps(event, separators=(",", ":"))).verify()
    plaintext = nip44_decrypt(
        SecretKey.parse(remote_secret),
        PublicKey.parse(event["pubkey"]),
        event["content"],
    )
    payload = json.loads(plaintext)
    assert isinstance(payload, dict)
    return payload


def sign_unsigned_event(unsigned_event: dict[str, Any], user_secret: str) -> dict[str, Any]:
    user_pubkey = derive_pubkey(user_secret)
    return sign_event(
        dict(unsigned_event),
        user_pubkey,
        PrivateKey(bytes.fromhex(user_secret)),
    )
