# External Signer quick start

This guide is for the person connecting a Nostr signer to an LNbits account.
You do not need to know how NIP-46 encryption works.

## What you need

- access to the LNbits account where External Signer is enabled;
- a remote signer with NIP-46 support;
- either a `bunker://` invite from that signer or its scan-client-QR action;
- the signer open and able to reach at least one relay used by LNbits.

You do **not** need to export the identity `nsec`. If any step appears to ask
for one, stop. External Signer has no field that accepts it.

## Pick one route

### The signer gives you a bunker link

Use this when the signer can create a client connection and show a link
beginning `bunker://`.

1. Create a new connection inside the signer and label it for this LNbits
   instance.
2. Copy the complete invite. Do not edit the relay or secret parameters.
3. Select **I have a signer invite** in External Signer.
4. Enter a name that identifies the signer or purpose.
5. Paste the invite and choose a permission preset.
6. Select **Send invite**.
7. In the signer, inspect and approve each connection request.

### The signer scans a client QR

Use this when the signer has a **Connect app**, **Add client** or **Scan client
QR** action.

1. Select **My signer scans QR codes** in External Signer.
2. Enter a name and choose a permission preset.
3. Select **Create QR**.
4. Scan the QR from the signer's connection screen. A normal camera app is not
   sufficient unless it passes the link into the signer.
5. Check the permissions and approve.

The page counts down the ten-minute secret. If it expires, select **Create
fresh pairing** and scan the new QR. The previous QR stays invalid.

## Understand the status

| Status | What is happening | What you should do |
| --- | --- | --- |
| Waiting for signer | LNbits is listening for the QR response | Scan and approve in the intended signer |
| Connecting | LNbits sent the bunker connection request | Open the signer and approve it |
| Verifying | The signer answered and LNbits is proving the user key | Approve the public-key and identity-proof requests |
| Connected | The user key signed the exact challenge successfully | Use **Test connection** if you want a live ping |
| Error | Pairing, relay delivery or verification failed | Read **What went wrong**, correct it and retry |
| Revoked | LNbits erased its local client capability | Remove the same client in the signer if still listed |

## Choose permissions safely

Start with **Identity proof**. It can read and prove the user public key but
cannot sign normal notes, profiles or market events.

Choose **Nostr Market** only when connecting an integration that needs those
specific event kinds. Open the advanced section only when you understand the
NIP-46 method and event-kind list required by the calling extension.

External Signer refuses an unqualified `sign_event` permission.

## Troubleshooting

### Nothing happens after sending an invite

- Confirm the signer is online and unlocked.
- Confirm both sides use at least one identical relay.
- Confirm the relay begins `wss://` in production.
- Look in the signer for a pending connection approval.
- Select **Retry connection** after correcting the problem.

### The QR expires

Select **Create fresh pairing**. Scan only the new QR. Keeping the old QR open
does not extend its lifetime.

### The signer rejects the identity-proof event

The extension requires `sign_event:27235` during bootstrap. The event is an
unpublishable, connection-specific challenge. The signer must either approve
that exact kind or implement a compatible identity-proof policy.

### Connected, but another extension cannot sign

Expand **Technical connection details** and check the approved scope. The
connection must include the exact requested method or `sign_event:<kind>`.
Reconnect with a suitable preset if the existing client is too narrow.

### Test connection works, but an event is not visible

A signature is not publication. The calling extension must publish the signed
event and verify relay acceptance separately.

## Revoke safely

1. Select **Revoke** in External Signer.
2. Confirm that LNbits erased the local client capability.
3. Open the remote signer and remove or revoke the same client there.
4. Protect backups separately; deleted ciphertext can remain in old database or
   filesystem snapshots.
