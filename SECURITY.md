# Security policy

External Signer handles a delegated signing capability. Treat its database,
LNbits auth secret, process memory and backups accordingly.

## Supported versions

Only the latest released version is supported. Version `0.1.0` is currently a
local pre-release and has not been deployed to production.

## Report a vulnerability

Do not open a public issue containing an exploit, secret, pairing URI, relay
credential or signed private test data. Use the repository's private **Report a
vulnerability** form to contact The Crypto Donkey maintainers and include:

- the affected commit or release;
- the exact request and trust boundary involved;
- a minimal reproduction with all real keys and URLs replaced;
- the likely impact and whether a capability was exercised.

No bug bounty is promised.

## Threat model

The extension is designed to resist:

- database disclosure without the LNbits auth secret;
- forged, tampered, wrongly addressed or wrong-author NIP-46 responses;
- a remote signer returning a valid signature over a different event;
- pairing-response spoofing in the client-initiated flow;
- permission escalation from a named event kind to broad signing authority;
- replay changing a terminal operation;
- one LNbits account reading another account's connections or operations;
- relay metadata being broadcast to unrelated relays known by other
  extensions.

It does not protect against:

- compromise of the running LNbits process or both its database and auth
  secret;
- malicious code in LNbits, this extension, the inherited `nostr-sdk` runtime
  or the remote signer;
- a signer approving a broader policy than the request displays;
- traffic analysis by the selected relays;
- denial of service, relay censorship or loss of messages;
- an attacker who copied the disposable client secret before local revocation;
- sensitive plaintext that an authorised caller deliberately asks the signer
  to encrypt or decrypt;
- recovery of old ciphertext from database or filesystem backups.

## Storage and rotation

Secrets use AES-256-GCM with a random 96-bit nonce, an authenticated version
label and a key derived from the LNbits auth secret. Changing the LNbits auth
secret makes existing External Signer ciphertext undecryptable. Plan rotation
as a re-pairing event.

Runtime warnings contain a controlled failure category and exception class,
not the exception message. This prevents relay or dependency failures from
copying decrypted request data into logs.

Revocation clears the live client capability and operation history from the
current database. SQLite pages, filesystem snapshots and backups may retain old
ciphertext. Protect or expire them separately.

## Operational guidance

- Use `wss://` relays in production. Plain `ws://` is accepted only for local
  development endpoints.
- Request the smallest set of methods and exact event kinds.
- Keep signer-side confirmation enabled for consequential events.
- Revoke at both LNbits and the remote signer when a device or server is lost.
- Back up the remote signer according to its own recovery model; this extension
  cannot recover the user key.
- Do not interpret a completed signature as publication, payment settlement or
  physical-world evidence.
