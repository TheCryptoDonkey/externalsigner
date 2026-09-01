# Contributing

External Signer handles delegated signing authority. Small, reviewable changes
with explicit tests are preferred.

## Create a development environment

Use Python 3.10, 3.11 or 3.12 and Node.js 20 or newer. From the extension
checkout:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install \
  "lnbits @ git+https://github.com/lnbits/lnbits.git@v1.5.6" \
  black httpx mypy pytest pytest-asyncio ruff websockets
```

The tests load this checkout as `lnbits.extensions.externalsigner`; no editable
package installation is required. Node is used only to check the browser
assets with Prettier.

## Before opening a pull request

1. Do not include an `nsec`, pairing URI, client secret, account identifier,
   private relay URL or production database in code, fixtures, screenshots or
   logs.
2. Add tests for successful behaviour and the relevant failure or abuse case.
3. Run the complete local gate:

   ```bash
   make verify
   ```

4. Explain any change to custody, permissions, encryption, relay routing,
   account scoping or stored data in the pull request.
5. Update the user instructions when behaviour or wording changes.

Security reports must follow [SECURITY.md](SECURITY.md), not a public issue.

Unless stated otherwise in writing, contributions intentionally submitted to
this repository are licensed under the repository's MIT licence.
