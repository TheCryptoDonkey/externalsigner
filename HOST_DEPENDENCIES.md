# Host dependency gate

External Signer deliberately adds no runtime package beyond LNbits.  It must
not replace LNbits' web framework, authentication or image-processing
dependencies from an extension install.

## Current decision

**Production release is blocked.** On 2026-09-02, LNbits' latest stable release
was still `v1.5.6` and the pinned development candidate was still commit
`a16dd7cee3b89785c69f08f41462e7a2cecb62d3`. Strict `pip-audit` scans of fresh
host environments found unresolved advisories inherited from those LNbits
sources.

| LNbits source | Resolved vulnerable packages | Audit rows |
| --- | --- | ---: |
| `v1.5.6` | Pillow 12.1.1, PyJWT 2.12.1, Starlette 0.47.3 | 42 |
| `dev` commit `a16dd7cee3b89785c69f08f41462e7a2cecb62d3` | PyJWT 2.12.1, Starlette 0.48.0 | 16 |

The development branch fixes the reported Pillow set by resolving 12.3.0.
The audit still requires PyJWT 2.13.0 and, across the reported Starlette set,
Starlette 1.3.1.  LNbits currently constrains those packages to older lines.

LNbits' open
[`Migrate to pydantic v2` issue](https://github.com/lnbits/lnbits/issues/3709)
records part of the host-framework migration still required before the current
FastAPI/Starlette stack can be upgraded safely. That upstream issue is context,
not a promise that every advisory will be fixed by one change.

No risk acceptance has been made.  Review this gate when LNbits publishes a
compatible host version with the fixes, or when each applicable advisory has a
named owner, compensating controls, an expiry date and a written production
decision.

## Why this extension does not pin around the host

LNbits owns and imports these packages.  The extension manager does not treat
this project's `pyproject.toml` as authority to replace LNbits core packages.
Forcing newer framework versions into the server could break LNbits and would
create an untested host combination.  A superficially green extension scan
would therefore be misleading.

The scheduled dependency workflow audits both the latest supported stable
release and the exact development commit recorded above. It preserves a
machine-readable JSON report even when findings make the job fail. A failing
audit is expected while this gate is open and must not be waived merely to
publish a release.

## Evidence needed to close the gate

1. Update the supported LNbits baseline to a released, compatible host build.
2. Resolve a fresh environment from that exact source.
3. Run `pip check` and strict `pip-audit` against the complete environment.
4. Record the resolved versions and public workflow run in
   [VERIFICATION.md](VERIFICATION.md).
5. Re-run the extension CI, browser, database, recovery and signer acceptance
   matrix before making a production claim.
