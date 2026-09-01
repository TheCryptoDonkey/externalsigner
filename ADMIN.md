# Administrator guide

External Signer stores a delegated NIP-46 client capability. Treat its database
and the LNbits authentication secret as security-sensitive material.

## Supported baseline

- LNbits `>=1.5.6,<2`
- Python `>=3.10,<3.13`
- SQLite or PostgreSQL only after the corresponding release gate has passed
- one LNbits application worker until multi-worker soak evidence is recorded

The extension uses LNbits' existing `nostr-sdk`, `coincurve` and
`pycryptodomex` packages. It does not require the Nostr Client extension.

## Install a tagged release

Do not install an arbitrary branch or unverified ZIP in production.

After a public release exists:

1. Open the raw `manifest.json` from the public repository.
2. Add that URL to **Manage Server → Server → Extension Sources**.
3. Install the exact release shown by LNbits.
4. Verify that the archive SHA-256 matches the LNbits registry entry.
5. Restart LNbits and confirm the extension migration and route registration in
   the server log.
6. Enable it for a staging account before exposing it to other users.

The intended manifest URL is:

```text
https://raw.githubusercontent.com/TheCryptoDonkey/externalsigner/main/manifest.json
```

That URL is not an installation claim until the repository and release exist.

## Network policy

The LNbits server opens outbound WebSocket connections to user-selected Nostr
relays. External Signer enforces:

- `wss://` in production;
- no URL credentials or fragments;
- no localhost, private, link-local or special-use IP targets;
- DNS resolution entirely to globally routable addresses before connection.

DNS checks reduce server-side request-forgery exposure but do not replace an
outbound firewall. Restrict production egress to the relay policy appropriate
for the deployment and monitor DNS behaviour.

Plain `ws://` loopback relays are available only when LNbits debug mode is on.
Never enable debug merely to permit a production relay.

## Storage and lifecycle

The extension database is named `ext_externalsigner`. PostgreSQL uses the
`externalsigner` schema. Stored secret material uses versioned AES-256-GCM
envelopes derived from the LNbits authentication secret.

Changing `AUTH_SECRET_KEY` makes existing capability ciphertext unreadable.
Treat rotation as a planned re-pairing event:

1. notify users;
2. revoke clients in both LNbits and their signers;
3. rotate the authentication secret;
4. restart LNbits;
5. create fresh connections.

Operational limits are intentionally bounded:

| Limit | Value |
| --- | --- |
| Active connections per account | 10 |
| Unfinished operations per connection | 12 |
| User requests per connection per minute | 60 |
| Pairing QR lifetime | 10 minutes |
| Unanswered operation lifetime | 30 minutes |
| Completed/failed operation retention | 7 days |

Terminal operation parameters are scrubbed as soon as the final response is
processed. Revocation purges the complete operation history for that
connection.

## Backups

Back up LNbits and extension data together. A database without the matching
authentication secret cannot decrypt the client capabilities. A database and
authentication secret together are sensitive even though they do not contain
the user identity key.

Test all of these on staging:

- backup creation;
- restore to an isolated instance;
- successful decryption and signer ping after restore;
- revocation after restore;
- destruction or expiry of temporary restore media.

SQLite pages, volume snapshots and database backups may retain old encrypted
values after application-level deletion.

## Monitoring

Monitor for:

- repeated `NIP-46 runtime error` log entries;
- relay DNS or TLS failures;
- connections stuck in Connecting or Verifying;
- requests expiring after thirty minutes;
- a rising rate of invalid response events;
- unexpected database or operation-count growth.

Never log decrypted parameters, results, pairing links, approval URLs, client
secrets or account identifiers in external monitoring.

## Upgrade and rollback

Before upgrade:

1. record the running release and archive hash;
2. back up the database and authentication secret securely;
3. review migrations and the changelog;
4. verify the new release against the staging signer matrix.

Rollback is permitted only when the older code understands the current schema.
If a release introduces an irreversible migration, restore the matching backup
instead of running older code over a newer database.

## Production decision

Use [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md) as the go/no-go record. A green
unit suite is necessary, but does not substitute for a released archive,
PostgreSQL evidence, restart recovery, dependency triage or a staging soak.
