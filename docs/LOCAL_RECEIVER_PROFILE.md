# Experimental local receiver profile v1

`cpr-memory --profile FILE` selects an adopter-owned contract for the local
file receiver. The profile is validated against the command's context, scope,
and Ed25519 public key, then its canonical JSON bytes are pinned in the
receiver trust database at `init`. Changing it requires a new receiver trust
database and an explicit operator migration decision; old databases are not
silently upgraded.

The profile declares the relative file inventory and required versus optional entries and the declared UTF-8
memory files the `resume` command may emit. Publish and recall enforce the
inventory at their actual data gates. Its trust section binds a context, the
raw 32-byte Ed25519 public-key fingerprint, the receiver-owned current
reference, and the system UTC clock. `--now` test overrides are refused by
this CLI. The authority and consent fields record only the local operator's
assertions; they do not establish a subject's grant, issuer identity, or
revocation. Retention is explicit: the current generation remains until an
explicit replacement and older generations can remain on disk. Refusal is
fail-closed for missing policy/reference, untrusted or stale evidence, an
inventory mismatch, or a missing/invalid selected memory file.

## Reproduce one receiving case

Run from a source checkout with Python 3.11+ and `cryptography` installed.
This example sends only the operator-selected `resume.txt` file through the
local receiver. It is not a Crystal or WhiteMagic completeness claim.

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
mkdir -p /tmp/cpr-profile-demo/input
printf 'Local receiver note.\n' > /tmp/cpr-profile-demo/input/resume.txt
openssl genpkey -algorithm ED25519 -out /tmp/cpr-profile-demo/key.pem
openssl pkey -in /tmp/cpr-profile-demo/key.pem -pubout -out /tmp/cpr-profile-demo/pub.pem
KEY_HASH="sha256:$(openssl pkey -pubin -in /tmp/cpr-profile-demo/pub.pem -outform DER | tail -c 32 | sha256sum | cut -d ' ' -f 1)"
jq -n --arg key "$KEY_HASH" '{kind:"cpr-experimental-local-receiver-profile",version:1,id:"local-resume-file-v1",export:{scope:"operator:local-resume-file",inventory:["resume.txt"],optional:[],memory_paths:["resume.txt"]},trust:{context:"local-resume-file",key_sha256:$key,reference:"receiver-trust-db/current_reference; advanced only by explicit local publish",clock:"system-utc"},authority:{status:"operator-asserted",basis:"outside this verifier"},consent:{status:"operator-asserted",subject_consent_verified:false},retention:{mode:"retain current generation until explicit replacement; prior generations may remain on disk",deletion:"operator-managed"},refusal:["missing policy or reference","untrusted or stale evidence","inventory mismatch","selected memory file missing or invalid UTF-8"]}' > /tmp/cpr-profile-demo/profile.json
COMMON="--data-root /tmp/cpr-profile-demo/data --trust-db /tmp/cpr-profile-demo/trust/receiver.sqlite3 --context local-resume-file --scope operator:local-resume-file --public-key /tmp/cpr-profile-demo/pub.pem --profile /tmp/cpr-profile-demo/profile.json"
mkdir -p /tmp/cpr-profile-demo/trust
cpr-memory init $COMMON
cpr-memory publish $COMMON --key-pem /tmp/cpr-profile-demo/key.pem --expected-reference none --input-root /tmp/cpr-profile-demo/input
cpr-memory status $COMMON
cpr-memory resume $COMMON --memory-path resume.txt
```

The shell `COMMON` variable above must be expanded as separate arguments by
the invoking shell; users may paste the options directly if they use a shell
that does not perform word splitting for quoted variables. `status` reports
the pinned profile id/digest and accepted reference. A profile declaring an
additional path rejects this input tree at publish; a changed profile against
the initialized trust DB is rejected as a policy mismatch. Restoring both an
older data tree and its matching trust DB can restore an older accepted
reference; this prototype does not solve joint rollback. The CLI gates only
this named local receive path and does not intercept other application reads.
