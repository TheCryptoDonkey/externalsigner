# External Signer

Sign from LNbits while the identity key stays in a separate NIP-46 signer.

Choose the route your signer supports:

- paste its `bunker://` connection invite; or
- create a ten-minute `nostrconnect://` QR for the signer to scan.

External Signer creates an encrypted, disposable client capability. It asks for
exact methods and event kinds, learns the user public key and accepts the
connection only after that key signs an exact identity challenge.

The default preset proves identity only. A separate Nostr Market preset covers
its profile, encrypted-order, deletion, stall and product events. Broad
`sign_event` authority is refused.

**Never paste an `nsec` into this extension.** The remote signer remains the
final approval authority. A valid signature does not by itself prove relay
publication, payment settlement or any physical-world action.
