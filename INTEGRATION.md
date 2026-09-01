# Integration contract

This document is for another LNbits extension calling External Signer.

## Authority boundary

The caller supplies the LNbits account ID and a connection ID owned by that
account. External Signer checks ownership, connection state and approved
permissions before publishing a request.

Do not bypass the service layer by reading encrypted database rows or using the
disposable client key directly.

## Sign an event

```python
from lnbits.extensions.externalsigner.services import sign_event

signed_event = await sign_event(
    user_id,
    connection_id,
    {
        "kind": 1,
        "content": "Hello from a remote signer",
        "tags": [],
        "created_at": created_at,
    },
    timeout=120,
)
```

The unsigned event must contain exactly the caller-controlled Nostr fields:
`kind`, `content`, `tags` and `created_at`. It must not contain `id`, `pubkey`
or `sig`.

Before returning, the helper verifies:

- the returned user public key matches the proved connection identity;
- all four unsigned fields are byte-for-byte equivalent after JSON parsing;
- the Nostr event ID and Schnorr signature are valid.

The connection must grant `sign_event:<kind>`. Broad `sign_event` is never
accepted.

## Encrypt and decrypt

```python
from lnbits.extensions.externalsigner.services import (
    nip04_decrypt,
    nip04_encrypt,
    nip44_decrypt,
    nip44_encrypt,
)
```

Each helper takes `user_id`, `connection_id`, the other party's hexadecimal
public key, the plaintext or ciphertext and an optional timeout. Each returns a
string only after a final authenticated NIP-46 response.

## Async API

For a UI-driven integration, submit an operation to:

```text
POST /externalsigner/api/v1/connections/{connection_id}/requests
```

Then poll:

```text
GET /externalsigner/api/v1/operations/{operation_id}
```

Both endpoints require the current LNbits account session. They are not
cross-account service credentials.

Operation states:

| State | Meaning |
| --- | --- |
| `pending` | Stored but not yet published |
| `sent` | Published to the selected connection relays |
| `processing` | A worker claimed and is validating the response |
| `auth_required` | Open the validated HTTPS approval URL and keep polling |
| `complete` | A final result is available |
| `failed` | A bounded error is available |

The raw async endpoint returns the signer's protocol result. Code that requests
`sign_event` through this low-level route must validate the signed event before
publishing it. Prefer the `sign_event` service helper when possible.

## Errors

Expect:

- `ValueError` for malformed data, missing connections or invalid results;
- `PermissionError` for scope violations;
- `SignerCapacityError` when too many operations are outstanding;
- `SignerRateLimitError` after sixty user requests in one minute;
- `TimeoutError` when a synchronous helper receives no final response before
  its timeout.

An approval challenge is not a failure. The same request ID remains active
until the signer returns a final response or the operation expires.

## Publication and settlement

External Signer returns signatures and cryptographic transforms. It does not
publish user events, wait for relay acceptance, make Lightning payments or
prove settlement. Those responsibilities remain with the calling extension.
