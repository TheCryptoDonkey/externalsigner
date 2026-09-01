# Terms and conditions

External Signer is provided under the MIT licence, without warranty.

Copyright (c) 2026 The Crypto Donkey.

By enabling it, you acknowledge that:

- a NIP-46 client key is a delegated signing capability even though it is not
  the user's identity key;
- the selected remote signer decides whether to approve each operation;
- selected Nostr relays can observe connection metadata and timing but not
  NIP-44-encrypted request contents;
- relay delivery and a valid signature do not prove publication, payment
  settlement or any physical-world event;
- local revocation cannot erase copies of a capability held elsewhere;
- changing the LNbits auth secret requires existing connections to be paired
  again;
- you are responsible for signer recovery, relay selection, backups and the
  consequences of the permissions you approve.
