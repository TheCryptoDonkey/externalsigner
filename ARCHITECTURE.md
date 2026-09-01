# Architecture and trust boundary

## Components

```text
LNbits account / calling extension
        |
        | account-scoped service request
        v
External Signer
  - permission policy
  - encrypted operation state
  - disposable NIP-46 client key
        |
        | signed kind-24133 + NIP-44 v2
        v
selected Nostr relay or relays
        |
        v
remote signer
  - remote-signer communication key
  - user identity key
  - approval policy
```

The remote-signer communication key and user identity key are stored and
verified as separate identities. They may happen to be equal in a particular
signer, but the implementation never assumes that.

## Bootstrap

1. LNbits creates a random disposable client key.
2. A `bunker://` connect request or authenticated `nostrconnect://` response
   identifies the remote signer.
3. LNbits calls `get_public_key` to learn the user key.
4. LNbits creates an unpublishable kind-27235 challenge containing the
   connection ID and a 256-bit random value.
5. The remote signer signs that exact event with the user key.
6. LNbits verifies the signature, user key and every requested field before
   marking the connection Connected.
7. LNbits immediately asks the signer whether it wants to switch relays.

The identity proof closes the gap where an authenticated remote-signer channel
could otherwise return an unrelated user public key as an unproved string.

## Stored secrets

These values are encrypted at rest:

- disposable client secret;
- bunker or QR pairing secret;
- request parameters;
- results and error details;
- signer approval URLs.

Remote-signer and user public keys, selected relays, permission names, status
and timestamps are not secret. Selected relays can observe connection metadata
and timing.

## Relay isolation

The extension owns a dedicated `nostr-sdk` client. It uses the public targeted
send API rather than a shared relay broadcast or another extension's private
methods. Each relay receives only the subscription pubkeys and messages routed
to connections assigned to it.

Multiple application workers may receive the same relay response. Database
claims make response processing and NostrConnect handshake advancement
idempotent. A production multi-worker topology still requires an explicit soak
before it is added to the supported matrix.

## What signatures prove

A valid result proves that the expected user key signed the exact event. It
does not prove:

- relay publication, acceptance or retention;
- the identity of a human controlling the signer;
- Lightning payment or fiat settlement;
- delivery of goods or completion of a physical-world action;
- exclusive custody of the identity key.
