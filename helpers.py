import ipaddress
import json
import re
from base64 import urlsafe_b64decode, urlsafe_b64encode
from dataclasses import dataclass
from hashlib import sha256
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from lnbits.settings import settings

HEX_32_RE = re.compile(r"^[0-9a-fA-F]{64}$")
PROOF_EVENT_KIND = 27235
SUPPORTED_METHODS = {
    "get_public_key",
    "logout",
    "nip04_decrypt",
    "nip04_encrypt",
    "nip44_decrypt",
    "nip44_encrypt",
    "ping",
    "sign_event",
    "switch_relays",
}
REQUIRED_PERMISSIONS = ("get_public_key", f"sign_event:{PROOF_EVENT_KIND}")
SECRET_ENVELOPE_PREFIX = "v1."
SECRET_ENVELOPE_AAD = b"lnbits-externalsigner:v1"

PERMISSION_PRESETS = {
    "identity": {
        "name": "Identity proof",
        "description": "Learn and cryptographically prove the external Nostr identity.",
        "permissions": list(REQUIRED_PERMISSIONS),
    },
    "nostrmarket": {
        "name": "Nostr Market",
        "description": "Profiles, stalls, products, deletions and NIP-04 order messages.",
        "permissions": [
            *REQUIRED_PERMISSIONS,
            "sign_event:0",
            "sign_event:4",
            "sign_event:5",
            "sign_event:30017",
            "sign_event:30018",
            "nip04_encrypt",
            "nip04_decrypt",
        ],
    },
}


@dataclass(frozen=True)
class ParsedBunkerUri:
    remote_signer_pubkey: str
    relays: list[str]
    secret: str | None


def normalize_hex_pubkey(value: str) -> str:
    normalized = value.strip().lower()
    if not HEX_32_RE.fullmatch(normalized):
        raise ValueError("Expected a 32-byte hexadecimal public key.")
    return normalized


def normalize_relay_url(value: str) -> str:
    candidate = value.strip()
    if len(candidate) > 2048:
        raise ValueError("Relay URL is too long.")
    parsed = urlsplit(candidate)
    if parsed.scheme not in {"ws", "wss"} or not parsed.hostname:
        raise ValueError("Relay URLs must use ws:// or wss:// and include a host.")
    if parsed.username or parsed.password or parsed.fragment:
        raise ValueError("Relay URLs must not contain credentials or fragments.")
    if parsed.scheme == "ws":
        if parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("Public relay URLs must use wss://.")
        if not settings.debug:
            raise ValueError("Plain local relay URLs are allowed only in debug mode.")
    hostname = parsed.hostname.lower()
    if not settings.debug:
        lowered = hostname.rstrip(".")
        if lowered == "localhost" or lowered.endswith((".localhost", ".local", ".internal")):
            raise ValueError("Production relay URLs must not target a local network.")
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError:
            pass
        else:
            if not address.is_global:
                raise ValueError("Production relay URLs must use a public address.")
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    netloc = hostname
    if parsed.port:
        netloc = f"{hostname}:{parsed.port}"
    path = parsed.path or ""
    return urlunsplit((parsed.scheme.lower(), netloc, path, parsed.query, ""))


def normalize_relay_urls(values: list[str]) -> list[str]:
    relays: list[str] = []
    for value in values:
        relay = normalize_relay_url(value)
        if relay not in relays:
            relays.append(relay)
    if not relays:
        raise ValueError("At least one relay URL is required.")
    if len(relays) > 8:
        raise ValueError("At most eight relay URLs are allowed.")
    return relays


def normalize_permissions(values: list[str]) -> list[str]:
    permissions: list[str] = []
    for raw in values:
        permission = raw.strip()
        if not permission:
            continue
        if permission == "sign_event":
            raise ValueError("Broad sign_event permission is not allowed; name each event kind.")
        if permission.startswith("sign_event:"):
            _, _, kind_text = permission.partition(":")
            if not kind_text.isdigit() or not 0 <= int(kind_text) <= 65535:
                raise ValueError(f"Invalid kind-scoped permission: {permission}")
        elif permission not in SUPPORTED_METHODS:
            raise ValueError(f"Unsupported NIP-46 permission: {permission}")
        if permission not in permissions:
            permissions.append(permission)
    for required in REQUIRED_PERMISSIONS:
        if required not in permissions:
            permissions.insert(0, required)
    return permissions


def parse_bunker_uri(uri: str) -> ParsedBunkerUri:
    if len(uri) > 4096:
        raise ValueError("Bunker URI is too long.")
    parsed = urlsplit(uri.strip())
    if parsed.scheme.lower() != "bunker" or not parsed.netloc:
        raise ValueError("Expected a bunker:// URI.")
    if parsed.path not in {"", "/"} or parsed.fragment:
        raise ValueError("Bunker URI contains an unsupported path or fragment.")
    remote_signer_pubkey = normalize_hex_pubkey(parsed.netloc)
    query = parse_qs(parsed.query, keep_blank_values=True)
    relays = normalize_relay_urls(query.get("relay", []))
    secrets = query.get("secret", [])
    if len(secrets) > 1:
        raise ValueError("Bunker URI contains more than one connection secret.")
    secret = secrets[0] if secrets else None
    if secret is not None:
        if not secret or len(secret) > 512:
            raise ValueError("Bunker connection secret is empty or too long.")
    return ParsedBunkerUri(remote_signer_pubkey, relays, secret)


def build_nostrconnect_uri(
    client_pubkey: str,
    relays: list[str],
    secret: str,
    permissions: list[str],
    name: str,
) -> str:
    query: list[tuple[str, str]] = [("relay", relay) for relay in relays]
    query.extend(
        [
            ("secret", secret),
            ("perms", ",".join(permissions)),
            ("name", name),
            ("url", "https://github.com/TheCryptoDonkey/externalsigner"),
            (
                "image",
                "https://raw.githubusercontent.com/TheCryptoDonkey/externalsigner/"
                "main/static/icon.svg",
            ),
        ]
    )
    return f"nostrconnect://{normalize_hex_pubkey(client_pubkey)}?{urlencode(query)}"


def encrypt_secret(value: str | None) -> str | None:
    if value is None:
        return None
    nonce = get_random_bytes(12)
    cipher = AES.new(_storage_key(), AES.MODE_GCM, nonce=nonce)
    cipher.update(SECRET_ENVELOPE_AAD)
    ciphertext, tag = cipher.encrypt_and_digest(value.encode())
    encoded = urlsafe_b64encode(nonce + tag + ciphertext).decode().rstrip("=")
    return SECRET_ENVELOPE_PREFIX + encoded


def decrypt_secret(value: str | None) -> str | None:
    if value is None:
        return None
    if not value.startswith(SECRET_ENVELOPE_PREFIX):
        raise ValueError("Unknown external signer secret envelope version.")
    encoded = value[len(SECRET_ENVELOPE_PREFIX) :]
    try:
        raw = urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        canonical = urlsafe_b64encode(raw).decode().rstrip("=")
        if encoded != canonical:
            raise ValueError("Encrypted external signer secret is not canonical.")
        if len(raw) < 28:
            raise ValueError("Encrypted external signer secret is truncated.")
        nonce, tag, ciphertext = raw[:12], raw[12:28], raw[28:]
        cipher = AES.new(_storage_key(), AES.MODE_GCM, nonce=nonce)
        cipher.update(SECRET_ENVELOPE_AAD)
        return cipher.decrypt_and_verify(ciphertext, tag).decode()
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError("Encrypted external signer secret is invalid.") from exc


def _storage_key() -> bytes:
    raw_key = settings.auth_secret_key
    key_bytes = raw_key if isinstance(raw_key, bytes) else str(raw_key).encode()
    return sha256(SECRET_ENVELOPE_AAD + b"\x00" + key_bytes).digest()


def encrypt_json(value: object) -> str:
    encrypted = encrypt_secret(json.dumps(value, separators=(",", ":"), ensure_ascii=False))
    if not encrypted:
        raise ValueError("Failed to encrypt internal signer data.")
    return encrypted


def decrypt_json(value: str) -> object:
    decrypted = decrypt_secret(value)
    if decrypted is None:
        raise ValueError("Failed to decrypt internal signer data.")
    return json.loads(decrypted)
