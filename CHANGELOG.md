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
- Add checksum-pinned interoperability coverage against the released `nak`
  v0.20.6 signer for bunker invitation, client-initiated QR pairing, signing,
  signer restart, relay recovery and local capability revocation.
- Replace the private Nostr Client integration with an isolated transport built
  only on LNbits' public `nostr-sdk` dependency.
- Restore unchanged per-relay subscriptions after a relay outage instead of
  waiting for the process route set to change.
- Add bounded queues, account and request quotas, retention, expiry, response
  claiming, targeted relay routing and production network-target validation.
- Reject unsafe authentication URLs, malformed response shapes, broad signing
  permissions and oversized request or response data.
- Add a first-use journey, plain-language status and recovery guidance,
  responsive dark/light styling and final-source browser screenshots.
- Add public Axe WCAG 2 A/AA browser acceptance for light and dark themes,
  keyboard-opened pairing dialogs, mobile layout and 200% text reflow.
- Add operator, integration, architecture, contribution, security and release
  documentation plus CI and release workflows.
- Treat one LNbits application worker as the complete supported deployment
  scope for 0.1.0. Multi-worker operation is explicitly unsupported.
- Add restart, auth-secret rotation, clock-controlled expiry and retention, and
  data-safe runtime logging coverage.
- Record the inherited LNbits host dependency blocker without overriding core
  framework versions from the extension.
- Correct all project copyright and authorship to The Crypto Donkey.
