# Verification record

Date: 2026-09-02

This record separates extension evidence, host-dependency evidence,
interoperability evidence and physical-device evidence. It does not turn a
local test run into a public release.

## Final-source extension suite

The ordinary suite passed on Python 3.12 and LNbits 1.5.6:

```text
52 passed, 3 skipped
Ruff: passed
Black: passed
mypy: passed
Prettier: passed
pip check: passed
```

The three skips are the deliberately opt-in independent-signer and hardware
modules. The software signer modules were run separately and passed as
recorded below; the physical-device boundary remains open.

The same final-source ordinary suite also passed on LNbits 1.6.0rc4 commit
`a16dd7cee3b89785c69f08f41462e7a2cecb62d3`.

Public `main` CI run
[`33572675403`](https://github.com/TheCryptoDonkey/externalsigner/actions/runs/33572675403)
passed the complete quality and ordinary test gates for all six combinations
of Python 3.10, 3.11 and 3.12 with LNbits 1.5.6 and the pinned LNbits
development commit. The same run passed fresh PostgreSQL migration and the
ordinary suite on both LNbits lines, the checksum-pinned released `nak` signer
job and the real-browser accessibility job. All ten jobs are required by
protected `main` with strict up-to-date checking.

The ordinary suite includes a real in-process WebSocket relay test for the
public `nostr-sdk` transport. It proves per-relay subscription filters,
delivery of a signed kind-24133 response and targeted publication that does not
reach an excluded relay. A second transport test stops and restarts the same
relay endpoint and proves the unchanged subscription is restored.

## Real LNbits browser smoke

LNbits 1.5.6 discovered the final extension, ran migrations 1 and 2, mounted
its UI, API and static routes and served an authenticated account. Headless
Chrome exercised both onboarding dialogs and the 390 px and 1440 px layouts.
The final empty and QR-state captures produced no failed HTTP response,
uncaught browser error or missing asset. The QR capture uses an explicitly fake
published fixture; it contains no live pairing capability.

Public merged-main CI run
[`33572675403`](https://github.com/TheCryptoDonkey/externalsigner/actions/runs/33572675403)
also mounted the exact candidate in a fresh LNbits 1.5.6 process and ran Chrome
with Axe 4.10.3. The light and dark desktop page, bunker dialog, 390 px mobile
page and QR dialog produced no WCAG 2 A/AA violation or browser error. The same
run rendered connected, expired-QR, disconnected, failed-operation and revoked
states at 1440 px and 390 px in both themes. Keyboard activation opened the
connection row, Test connection, Create fresh pairing, Retry connection and
the real revoke confirmation. No required explanation or action was missing,
no input asked for an `nsec`, and no state overflowed horizontally. At 200% root
text size, the extension retained both route choices and had no horizontal
overflow. This automated result supports, but does not replace, keyboard-only
and screen-reader acceptance by people.

This proves a source-mounted development installation. It does not prove an
extension-manager archive install or an upgrade from a previous public
release.

An exact Git archive of the pre-release commit was also passed through LNbits
1.5.6's `InstallableExtension.extract_archive()` path in isolated data and
extension directories. LNbits accepted the top-level archive layout, copied the
extension, found `config.json` and read version 0.1.0. This proves archive
structure and extraction only. The real manager download, release hash and
registry path remain blocked until a release exists.

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

## Released `nak` signer

Public merged-main CI run
[`33535055854`](https://github.com/TheCryptoDonkey/externalsigner/actions/runs/33535055854)
downloaded the upstream `nak` v0.20.6 Linux release, verified SHA-256
`b44b36c792fbc3fb73b7ba3bbc94beda2219826271aa8d5f130f569c3817c3b9`
before execution and printed `nak version v0.20.6`. Both released-signer tests
passed over a real temporary WebSocket relay.

The bunker-invite route proved connection, kind-0 signing, signer restart,
relay stop/restart recovery, a second verified signature and erasure of the
local encrypted client capability on revoke. The client-initiated
`nostrconnect://` route proved that the released signer accepted the QR
capability and completed another verified kind-0 signature.

This run found a transport defect before publication: an unchanged local route
did not restore its relay subscription after the relay lost server-side state.
The transport now uses the public `nostr-sdk` per-relay subscription API and a
bounded reconnect attempt. The ordinary suite carries the restart regression.

Local capability erasure is proved. `nak` logout does not provide evidence that
its persisted authorised-client entry was removed, so signer-side client
removal remains an explicit human acceptance gate.

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

An exact local scan of LNbits development commit
`a16dd7cee3b89785c69f08f41462e7a2cecb62d3` resolved Pillow 12.3.0 and reduced
the result to 16 advisory rows in two inherited packages: PyJWT 2.12.1 and
Starlette 0.48.0. This is an improvement, not a green production host. The
decision and closure criteria are in
[HOST_DEPENDENCIES.md](HOST_DEPENDENCIES.md).

Public dependency-audit run
[`33572801996`](https://github.com/TheCryptoDonkey/externalsigner/actions/runs/33572801996)
reran both complete inherited environments against merged commit
`06b14de590e257b93ee6c0b7f5b754ac32155c1d`. Both audits remained red and each
job uploaded its machine-readable JSON report despite the expected failure.
Production remains blocked by
[issue 4](https://github.com/TheCryptoDonkey/externalsigner/issues/4).

## Staging evidence path

`scripts/staging_acceptance.py` passed thirteen focused tests. The controller
refuses a soak shorter than seven days, anything other than one worker, an HTTP
origin or a probe gap above fifteen minutes. It records an append-only,
chronological SHA-256 chain of authenticated signer pings, observed relay/DNS/TLS
failure, recovery drills and sanitised monitoring-review artifact hashes. A
missing cookie cannot satisfy a planned network-failure check, and an answering
signer makes that expected-failure command fail.

This is evidence tooling, not elapsed evidence. No real HTTPS staging instance,
seven-day run, archive rollback or human operator sign-off was performed in this
source pass. The exact operating procedure and secret-handling boundary are in
[STAGING.md](STAGING.md), and
[issue 5](https://github.com/TheCryptoDonkey/externalsigner/issues/5) remains
open.

## PostgreSQL and recovery

A fresh `postgres:16-alpine` database ran the real LNbits 1.5.6 core migration
entry point followed by External Signer migrations 1 and 2. The complete
ordinary suite then passed `52 passed, 3 skipped` on PostgreSQL.

This run found and fixed a backend-specific defect: direct timestamp parameters
must use LNbits' database-aware timestamp placeholder. The claim, rate-limit,
timeout, pairing-expiry and retention queries now do so, and the same suite runs
against PostgreSQL in public CI.

A PostgreSQL custom-format backup containing an encrypted connected capability
was restored into a separate database. With the matching LNbits auth secret,
the restored process decrypted the disposable client capability and completed a
NIP-46 `ping` round trip against the deterministic test signer transport. This
proves database and encryption continuity; it does not claim a live remote
signer or public relay participated in the restore rehearsal.

The ordinary suite also advances a controlled clock across the thirty-minute
request expiry and seven-day terminal-record retention boundaries. Separate
tests prove recovery of sent, approval-required and completed operations after
runtime state is discarded, auth-secret rotation invalidates old ciphertext,
and runtime warning logs omit arbitrary exception data.

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

Pre-release hardening was merged through protected
[pull request 3](https://github.com/TheCryptoDonkey/externalsigner/pull/3) as
GitHub-verified commit
[`9a618f801d9872caffe887d22584db8dcd82e37e`](https://github.com/TheCryptoDonkey/externalsigner/commit/9a618f801d9872caffe887d22584db8dcd82e37e).
Released-signer, relay-recovery and browser acceptance then merged through
[pull request 8](https://github.com/TheCryptoDonkey/externalsigner/pull/8) as
GitHub-verified commit
[`9a3fb96c532d26d5c93e0f2d3fcebad2cc9d1b6c`](https://github.com/TheCryptoDonkey/externalsigner/commit/9a3fb96c532d26d5c93e0f2d3fcebad2cc9d1b6c).
Pre-release gate tooling and expanded state/accessibility acceptance merged
through [pull request 12](https://github.com/TheCryptoDonkey/externalsigner/pull/12)
as GitHub-verified commit
[`06b14de590e257b93ee6c0b7f5b754ac32155c1d`](https://github.com/TheCryptoDonkey/externalsigner/commit/06b14de590e257b93ee6c0b7f5b754ac32155c1d).
The repository is public at `TheCryptoDonkey/externalsigner`. GitHub recognises
the MIT licence; secret scanning, push protection and private vulnerability
reporting are enabled.

There is still no signed tag, release archive, archive hash, LNbits registry
entry, extension-manager install, staging soak or physical-device acceptance.
Those remain release gates and are not implied by the public repository,
database evidence or green extension CI. The dependency, operational and human
acceptance work is tracked in
[issue 4](https://github.com/TheCryptoDonkey/externalsigner/issues/4),
[issue 5](https://github.com/TheCryptoDonkey/externalsigner/issues/5) and
[issue 6](https://github.com/TheCryptoDonkey/externalsigner/issues/6).
