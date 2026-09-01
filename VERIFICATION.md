# Verification record

Date: 2026-09-01

This record separates extension evidence, host-dependency evidence,
interoperability evidence and physical-device evidence. It does not turn a
local test run into a public release.

## Final-source extension suite

The ordinary suite passed on Python 3.12 and LNbits 1.5.6:

```text
31 passed, 2 skipped
Ruff: passed
Black: passed
mypy: passed
Prettier: passed
pip check: passed
```

The two skips are the deliberately opt-in independent-signer modules. Both
were run separately and passed as recorded below.

The same final-source ordinary suite also passed `31 passed, 2 skipped` on
LNbits 1.6.0rc4 commit `a16dd7cee3b89785c69f08f41462e7a2cecb62d3`.

The ordinary suite includes a real in-process WebSocket relay test for the
public `nostr-sdk` transport. It proves per-relay subscription filters,
delivery of a signed kind-24133 response and targeted publication that does not
reach an excluded relay.

## Real LNbits browser smoke

LNbits 1.5.6 discovered the final extension, ran migrations 1 and 2, mounted
its UI, API and static routes and served an authenticated account. Headless
Chrome exercised both onboarding dialogs and the 390 px and 1440 px layouts.
The final empty and QR-state captures produced no failed HTTP response,
uncaught browser error or missing asset. The QR capture uses an explicitly fake
published fixture; it contains no live pairing capability.

This proves a source-mounted development installation. It does not prove an
extension-manager archive install or an upgrade from a previous public
release.

## Independent signer

`tests/test_interop_lnbits_nostr_bunker.py` passed against upstream LNbits
`nostr_bunker` commit `a74c58318020bfb094660ee9108cab1a172feb2c`.

The test crosses the two protocol implementations for:

1. connection-secret acknowledgement;
2. `get_public_key`;
3. exact signed identity proof;
4. `switch_relays`;
5. a kind-0 `sign_event` request and verified result.

The signer implementation is independent, while the relay transport is mocked
in this test so protocol behaviour can be isolated. The ordinary transport
test and Heartwood flow separately exercise the real relay transport.

## Heartwood

`heartwoodd` built from Heartwood ESP32 commit
`3db43d311169316d17d3615c850468ade4ea4a68`. The build completed with three
existing dead-code warnings and no error.

`tests/test_interop_heartwood.py` then passed in soft mode. The opt-in test used
an in-process loopback Nostr relay and temporary Heartwood data, and crossed
the real extension transport and real Heartwood daemon/backend for:

1. API-authenticated soft-keystore creation and unlock;
2. a temporary master and one-use connection slot;
3. bunker secret acknowledgement;
4. `get_public_key` and an exact kind-27235 identity proof;
5. Heartwood's explicit unsupported response to the best-effort
   `switch_relays` request;
6. a kind-0 `sign_event` request and independently verified result.

No signer or relay boundary was mocked in this test. No user event was
published to a public relay.

No physical Heartwood board was changed or tested in this final-source pass.
Therefore Heartwood daemon/soft-signer interoperability is proved, but
Heartwood physical-device interoperability is not.

## Dependency audit

The extension adds no runtime package beyond LNbits. `pip check` passed, but a
fresh `pip-audit 2.10.1` scan of the resolved LNbits 1.5.6 environment reported
known vulnerabilities in three inherited packages:

| Package | Resolved | Required fix shown by audit |
| --- | ---: | ---: |
| Pillow | 12.1.1 | 12.3.0 covers the reported set |
| PyJWT | 2.12.1 | 2.13.0 |
| Starlette | 0.47.3 | 1.3.1 covers the reported set |

The audit emitted 42 advisory rows, including duplicate aliases for some
findings. These findings block a production go decision until the host stack is
updated or each applicable finding has a written, time-bounded risk decision.
The extension must not silently override LNbits' core framework versions.

## Protocol and claim boundary

The implementation was checked against current NIP-46. It keeps the remote
signer and user public keys separate, uses NIP-44 v2 kind-24133 envelopes,
validates client-initiated pairing secrets, calls `get_public_key`, handles
validated approval URLs, requests `switch_relays` and treats `logout` as a
courtesy rather than the local revocation boundary.

A verified signature proves the key signed exact bytes. It does not prove relay
publication, payment settlement, signer custody beyond the stated protocol
boundary or any physical-world action.

## Publication state

This repository remains local with no commit, remote, CI run, signed tag,
release archive, archive hash, registry entry, PostgreSQL run, staging soak or
physical-device acceptance. Those are release gates, not implied by the green
local evidence above.
