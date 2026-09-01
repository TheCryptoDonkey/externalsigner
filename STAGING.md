# Staging acceptance runbook

This runbook turns the seven-day production gate into reproducible evidence.
It does not make an unpublished branch production-ready and it does not replace
the host-dependency, human-accessibility, physical-device or final-release gates.

## Start only from the final candidate

Do not start the clock from a working branch. First merge the complete candidate
through protected `main`, then deploy that exact 40-character commit to a separate
LNbits staging instance.

Record all of these before starting:

- the candidate commit and exact LNbits version;
- SQLite or PostgreSQL and the backup method used for it;
- exactly one LNbits application worker;
- an HTTPS origin with a valid public certificate;
- one named External Signer connection using only controlled `wss://` relays;
- a real remote signer that can answer `ping` throughout the run;
- monitoring for LNbits availability, extension runtime errors, DNS and TLS;
- the operator identity `TheCryptoDonkey` or another project account, not a
  private personal attribution.

The release-candidate archive does not exist yet. The rollback/archive drill
therefore remains blocked until that immutable input exists. Do not invent an
archive hash or treat a source checkout as manager-install evidence.

## Keep authentication outside the repository

The probe uses the normal authenticated External Signer API. Create a dedicated
staging account, enable the extension for it and establish the signer connection
through the user interface first.

Save that account's LNbits cookie in Netscape cookie-jar format at
`output/staging/cookies.txt`. For username/password authentication, a safe route
is to put this JSON in a mode-`0600` temporary file rather than the shell history:

```json
{"username":"staging-account","password":"replace-this-locally"}
```

Then submit it to `POST /api/v1/auth` with `curl --cookie-jar`, delete the JSON
file and set the resulting cookie jar to mode `0600`. Confirm the cookie works
with `GET /api/v1/auth`. Do not print it, attach it to an issue or copy it into
the evidence file. The entire `output/` directory is ignored by Git.

For example, after editing the temporary file locally:

```bash
install -m 600 /dev/null output/staging/login.json
${EDITOR:-vi} output/staging/login.json
curl --silent --show-error --fail \
  --cookie-jar output/staging/cookies.txt \
  --header 'Content-Type: application/json' \
  --data-binary @output/staging/login.json \
  https://staging.example.com/api/v1/auth
chmod 600 output/staging/cookies.txt
rm output/staging/login.json
curl --silent --show-error --fail \
  --cookie output/staging/cookies.txt \
  https://staging.example.com/api/v1/auth
```

Replace the origin first. If the staging host uses a different enabled LNbits
authentication method, establish the session through that method and export the
resulting cookie jar without weakening it to username/password login.

## Initialise the evidence chain

From a clean checkout of the deployed commit:

```bash
mkdir -p output/staging
chmod 700 output/staging
./scripts/staging_acceptance.py init \
  --evidence output/staging/soak.jsonl \
  --candidate-commit 0123456789abcdef0123456789abcdef01234567 \
  --lnbits-version 1.5.6 \
  --database-engine postgresql \
  --base-url https://staging.example.com \
  --connection-name release-candidate \
  --relay wss://relay.example.com \
  --operator TheCryptoDonkey
```

Replace every example value. Repeat `--relay` for every relay on the connection.
The command refuses short commit IDs, non-HTTPS hosts, credential-bearing URLs,
plain WebSocket relays, multiple workers, a run shorter than seven days or a
maximum probe gap longer than fifteen minutes.

Run one probe before starting the controller:

```bash
./scripts/staging_acceptance.py probe \
  --evidence output/staging/soak.jsonl \
  --cookie-jar output/staging/cookies.txt
```

## Run for at least seven real days

Run the controller under the staging service manager so an operator logout does
not stop it:

```bash
./scripts/staging_acceptance.py run \
  --evidence output/staging/soak.jsonl \
  --cookie-jar output/staging/cookies.txt \
  --interval-seconds 300
```

Every probe finds the connection by its recorded name, requires authenticated
account access, sends a real NIP-46 `ping`, waits for its terminal result and
appends only a category and duration. Connection IDs, operation IDs, cookies,
pairing links and signer secrets are not written to evidence. A normal failed
probe makes the run ineligible; do not edit it out or restart the evidence file.

On at least seven separate UTC dates, review the service, LNbits and monitoring
outputs. Create a separate sanitised review note containing timestamps, counts
and categories only. Hash it with `shasum -a 256`, then record the review:

```bash
./scripts/staging_acceptance.py review \
  --evidence output/staging/soak.jsonl \
  --result pass \
  --note "Reviewed availability and sanitised runtime categories for UTC day 1." \
  --artifact-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

Use `--result fail` whenever the review finds an unexplained error, missing
monitoring interval or secret-bearing log. A failed review is evidence, not
something to remove from the record.

## Rehearse the failures

Keep every controlled network interruption below the fifteen-minute probe-gap
limit. For each one:

1. record a normal passing probe;
2. apply the failure to every relay used by the staging connection;
3. run the corresponding expected-failure probe below;
4. restore the dependency;
5. record another normal passing probe;
6. save a sanitised, timestamped operator note and its SHA-256;
7. record the completed drill as `pass` only if all observations matched.

```bash
./scripts/staging_acceptance.py probe \
  --evidence output/staging/soak.jsonl \
  --cookie-jar output/staging/cookies.txt \
  --expect-failure-during relay_outage

./scripts/staging_acceptance.py drill \
  --evidence output/staging/soak.jsonl \
  --drill relay_outage \
  --result pass \
  --note "Relay stopped, authenticated signer ping failed, relay restored and ping passed." \
  --artifact-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

Repeat with `dns_failure` and `tls_failure`. Use an actual DNS resolution failure
and an actual invalid/expired certificate path respectively; a firewall block is
not evidence for both. The expected-failure command fails if the signer still
answers. An authentication or missing-cookie error never satisfies a network
failure drill.

Use the same `drill` command to record these remaining rehearsals:

- `process_restart_pending`: stop LNbits after the request is sent but before a
  signer response, restart it and prove the operation reaches the correct state;
- `process_restart_auth_required`: restart while the signer requires approval,
  follow the validated approval route and prove completion;
- `process_restart_complete`: restart after completion and prove the terminal
  result remains correct without sending the mutation again;
- `database_restore`: stop the primary, restore the database and matching LNbits
  authentication secret into an isolated instance, then prove a signer ping;
- `rollback`: install the previous compatible version from its exact archive
  against the rehearsed backup, then restore the candidate from its exact
  archive and prove both schema compatibility and signer recovery.

Never run the primary and restored instance against the same signer client at
the same time. Never put database dumps, authentication secrets, approval URLs,
raw logs or pairing capabilities into the evidence note.

## Verify and anchor the result

After at least 168 elapsed hours, stop the controller, perform a final normal
probe and run:

```bash
./scripts/staging_acceptance.py verify \
  --evidence output/staging/soak.jsonl
```

An eligible result requires:

- the full elapsed duration, HTTPS and one worker;
- two or more successful authenticated signer probes;
- no unexplained failed probe and no gap longer than fifteen minutes;
- observed signer failure and recovery for relay, DNS and TLS drills;
- all eight drills recorded as passing;
- passing monitoring reviews on seven UTC dates;
- an intact, chronological SHA-256 event chain.

Copy the final evidence SHA-256 and the non-sensitive summary into
[VERIFICATION.md](VERIFICATION.md) and the release issue. Keep the raw evidence,
cookie jar and drill artifacts in protected project storage. Publishing only the
final hash anchors the private record without publishing staging account details.
