# Production release checklist

Every required item must have dated evidence. An unchecked item is a release
blocker unless the unsupported scope is explicitly removed from the release
claim.

## Ownership and repository

- [x] MIT licence names The Crypto Donkey.
- [x] Package and extension metadata name The Crypto Donkey.
- [x] Contribution and third-party notice files exist.
- [x] Repository-level funding links are explicit.
- [x] Public repository exists at the URLs in extension metadata.
- [x] Protected `main` branch and required CI checks are enabled.

## Build and release

- [x] Clean clone passes Python and frontend quality gates.
- [x] CI passes Python 3.10, 3.11 and 3.12 against stable and development LNbits.
- [ ] Dependency audit is green or every finding has a written, time-bounded
      risk decision.
- [ ] `CHANGELOG.md` replaces `Unreleased` with the release date before the tag
      is created.
- [ ] `v0.1.0` tag matches `config.json` and `pyproject.toml`.
- [ ] GitHub release and immutable archive URL exist.
- [ ] Workflow-attached archive SHA-256 is recorded and independently
      reproduced before the registry entry is accepted.
- [ ] LNbits registry manifest passes its checker.

## Functional acceptance

- [x] Unit and account-isolation tests pass.
- [x] Kind-scoped permission and malicious-response tests pass.
- [x] Independent `nostr_bunker` interoperability passes locally.
- [x] Heartwood daemon and soft-signer interoperability passes locally.
- [ ] A second independently maintained signer is tested from its released build.
- [ ] Clean install through the real LNbits extension manager passes.
- [ ] Upgrade from the previous released schema passes, when applicable.
- [ ] Revoke in LNbits and signer-side client removal both pass.

## Database and recovery

- [x] Fresh SQLite migration passes.
- [x] Fresh PostgreSQL migration passes.
- [x] Restart during pending, approval-required and completed operations passes.
- [x] Backup and isolated restore preserve a valid connection.
- [x] Auth-secret rotation invalidates old capabilities and requires re-pairing.
- [x] Seven-day retention and thirty-minute expiry pass a clock-controlled soak.

## Operations

- [ ] Single-worker staging soak passes for at least seven days.
- [x] Multi-worker behaviour is explicitly unsupported in release notes.
- [ ] Relay outage, DNS failure, TLS failure and recovery are exercised.
- [x] Runtime exception logs omit exception data; staging monitoring review remains
      part of the seven-day soak.
- [ ] Rollback procedure is rehearsed against the release archive and backup.

## User experience

- [ ] A first-time user pairs by bunker invite without verbal assistance.
- [ ] A first-time user pairs by QR without verbal assistance.
- [ ] The user can explain why an `nsec` must never be pasted into LNbits.
- [ ] The user understands the requested permission preset before approval.
- [ ] Error, expiry, retry, test and revoke journeys pass on desktop and mobile.
- [ ] Keyboard navigation, labels, contrast and screen-reader announcements pass.
- [x] Gallery images are generated/captured from the final release source and contain no secrets.

## Claims

- [x] Public copy matches only the evidence above.
- [x] No physical Heartwood support claim appears until a board completes pairing,
      signing, restart and revocation acceptance.
- [x] No copy implies that a signature proves publication, settlement or a
      physical-world event.

## Go/no-go record

Record the release commit, tag, archive hash, LNbits versions, signer versions,
database backends, staging URL or environment identifier, test date and person
making the decision. Do not replace missing evidence with “tests passed”.
