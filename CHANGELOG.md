# Changelog

## 0.1.0 - Unreleased

- Add `bunker://` and `nostrconnect://` pairing.
- Add separate remote-signer and user-key verification.
- Add kind-scoped permission enforcement and the Nostr Market preset.
- Add NIP-04/NIP-44 helpers, async approval handling and relay switching.
- Add authenticated encrypted storage, expiring QR secrets and revocation
  cleanup.
- Add account-scoped API, LNbits UI and independent signer interoperability
  coverage.
- Add live Heartwood daemon/soft-signer interoperability coverage over a
  temporary loopback relay.
- Replace the private Nostr Client integration with an isolated transport built
  only on LNbits' public `nostr-sdk` dependency.
- Add bounded queues, account and request quotas, retention, expiry, response
  claiming, targeted relay routing and production network-target validation.
- Reject unsafe authentication URLs, malformed response shapes, broad signing
  permissions and oversized request or response data.
- Add a first-use journey, plain-language status and recovery guidance,
  responsive dark/light styling and final-source browser screenshots.
- Add operator, integration, architecture, contribution, security and release
  documentation plus CI and release workflows.
- Correct all project copyright and authorship to The Crypto Donkey.
