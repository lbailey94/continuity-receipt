# Independent relying-agent adoption handoff — 2026-10-01

**Status: source packet prepared, independently reviewed locally and handed off
on Sangha #500; no external operator return has been received.** This handoff defines a bounded relying-agent exercise using
the hardened consumer and local assessment writer from exact Continuity
Receipt commit `d942b1c1fff6e8d153e04c31e3327b4ca7c8ee56`. It is separate from
the already-completed same-fleet Mac platform rehearsal and from the pending
Mandala W2 Linux capture. The primary posted the operator instructions on Sangha #500 and preserved the
verified packet in the T4800-S upload namespace. No production service or
customer state is touched by the packet.

## Packet artifact and source identity

The source-only packet is ready at:

```text
/tmp/cr-independent-adoption-20261001/continuity-receipt-d942b1c-independent-adoption.tar.gz
```

| Pin | Value |
|---|---|
| Source commit | `d942b1c1fff6e8d153e04c31e3327b4ca7c8ee56` |
| Source tree | `1985b0420fb49fee6bae03df5e5b9a03c6dd1e8f` |
| Packet archive | 68,283 bytes; SHA-256 `sha256:85613674eca722fc2e91992513374b34b0f6e542bd85fd1127e8028bee5fec95` |
| `SOURCE-MANIFEST.json` | 27 committed source files; SHA-256 `sha256:1bce0411bfb069d5d751e7731b7526b15939bd22416d902aac964562cccb6456` |
| `SOURCE-MANIFEST.sha256` | SHA-256 `sha256:7e69c668c6fb23cfe8db9a7cd89b21d1f072b905da28617796612551cb8b037e` |
| `SOURCE-PIN.json` | SHA-256 `sha256:a57439589335ab5eb98b4515b1fcd64c4ef93cd5d81e5c252c4df6d4bb8fd124` |

The archive contains the committed Python package source, `pyproject.toml`,
license/readme, `examples/independent-agent-pilot/`, and
`tools/make_vectors.py`, plus the generated source pin and checksum manifests.
It excludes a historical example README whose instructions refer to an older
source state. It contains no built wheel/sdist, credentials, real customer
data, or Git metadata. The exact archive is preserved in
`SharedWorkspace/uploads/t4800-s/continuity-receipt-independent-adoption-d942b1c-2026-10-01/`
and announced at Sangha #500. No external operator execution is claimed.

The project metadata inside the source says version `0.5.0`. That string is
package metadata, **not an identity pin for this hardened source**. The
operator must verify the archive digest, `SOURCE-PIN.json`, all entries in
`SOURCE-MANIFEST.sha256`, and the actual imported consumer module hashes in
the returned assessment record. Do not substitute a PyPI
`continuity-receipt==0.5.0` install for this source snapshot or claim that the
published wheel contains these committed changes.

### Key source hashes

The complete file-by-file hashes are in the packet’s `SOURCE-MANIFEST.json`.
The principal imported modules and action harness pins are:

| File | SHA-256 |
|---|---|
| `continuity_receipt/consumer.py` | `2e34c2d6962d916fc95dabd457756678558f5884a8660119f2db1353a4c7dc79` |
| `continuity_receipt/verify.py` | `15676162a93171add16a1d5d844a0829279482e9876b4aa1da7ce010d6aea771` |
| `continuity_receipt/canon.py` | `ac8770c2a5134bd74ebcf2bfb086ec80d33b58fa09e67885f1450907c56b8851` |
| `continuity_receipt/strict_json.py` | `fba9de2d77c9380e392104bc3b8876e138790628371a7a7c616ce46cb1784848` |
| `continuity_receipt/records.py` | `58b7eac906ae4bf13818d01373f325f4480007f6ffe9e2ef1f8bab95108e8041` |
| `continuity_receipt/keys.py` | `20f621cc033189deab5976ad61b71dfc18e147de9df875f69920c19a7358eca0` |
| `continuity_receipt/agreements.py` | `351ad70cac29b80488371b6b91492435ccd207ebffbaa523676ba9736050b970` |
| `continuity_receipt/bundle.py` | `923d3392514871fa681cc26956bacebc26faecc971f7c87a04f5c5f4d45c0fd9` |
| `continuity_receipt/revocations.py` | `400614b2889255f4ff4ab775476e5a704ae481674dd1c0c0e9421fbd06927bd6` |
| `examples/independent-agent-pilot/run_action.py` | `ffc4682d3e15d7f423b7efc77970fdc3384fc489a1e45f72495fced1462c98d1` |
| `examples/independent-agent-pilot/make_fresh_fixture.py` | `58507f8641a91d47b5f5c0f5698a9c61212a1fdd65a31cb426ca39584785a687` |
| `examples/independent-agent-pilot/test_run_action.py` | `72ddc6f27b1cf9ac37010ec028e5e2f85650c365812f2f03797d7fffec1aec00` |
| `tools/make_vectors.py` | `d3dbd4ed442b6a7fec8c3f2a8df887c5bd03190f1a6a4c485f7f8cd9fd17189d` |

## Clean-extraction rehearsal

I extracted the final `.tar.gz` into a new directory, verified all 27 source
files with `sha256sum -c SOURCE-MANIFEST.sha256`, and ran the action regression
suite there: **16 tests passed**. The suite covers a positive local assessment
file write; tampered output and replay refusal; expired/stale input refusal;
missing-required-record refusal; unsupported spec and issuer denial; wrong raw
input pin; and unresolved `PREPARED` interruption refusal. The interruption
test injects a failure after the durable prepare record, then confirms that a
second call fails closed and does not recreate the result.

I also ran the CLI from that clean extraction using a newly generated
synthetic signed bundle and policy. It produced
`LOCAL_ASSESSMENT_RECORDED_NOT_AUTHORIZATION`. Reusing the same input pins and
output directory was refused as `assessment_replay_refused`. Altering the raw
bundle while keeping the original pin was refused as `bundle_raw_pin_mismatch`.
The old signed fixture was refused as stale, and a temporary policy requiring
the absent `authority.succession` record was refused as
`consumer_assessment_not_accept`.

Local reproduction details, for traceability only (the operator must generate
their own fresh bytes and use their own time reading):

- Local host: Linux x86_64; Python `3.12.3`; `cryptography` `50.0.1`.
- Fresh synthetic bundle: 5,584 bytes,
  `sha256:3781dd3215b0f1f90c7d9f51b3265fe3013f0719392b92228568101a241f168d`.
- Fresh synthetic policy: 346 bytes,
  `sha256:05b94d74a47dfb84a1a86356465faaf2323929a5fee8d4d77156c9bf36d66cb1`.
- Assessment JSON: SHA-256
  `sha256:38bf257e7becee435a61685079e54322345974c4d8704a2d7f3e1ad8642b980b`.
- The action record identifies its imported module path and hashes, and labels
  the reported package version as metadata. Its repository HEAD and dirty
  status are `null` because the source-only archive has no `.git` directory;
  the independent source identity is the archive and manifests above.

These are locally generated synthetic test fixtures and a local rehearsal.
They are not independent adoption evidence, identity/authority proof, or
evidence of an external action. The fixture’s deterministic signing keys are
public test keys and must not be reused as a real identity.

## Instructions for an independent operator

The operator should unpack the exact archive on a host they administer
separately from the producer, record the archive and source-manifest checks,
then run the source directly. Python `3.11+` and `cryptography>=42` are
required. Create the output directories with owner-only permissions. No
receipt-described action is executed; the one bounded positive action writes
an assessment JSON in a local directory.

```sh
mkdir -m 700 packet
tar -xzf continuity-receipt-d942b1c-independent-adoption.tar.gz -C packet
cd packet/continuity-receipt-d942b1c
mkdir -m 700 ../input ../positive ../tampered ../expired ../missing-proof
sha256sum -c SOURCE-MANIFEST.sha256
python3 --version
python3 -m venv .venv
.venv/bin/python -m pip install 'cryptography>=42'
.venv/bin/python -m unittest discover -s examples/independent-agent-pilot -p test_run_action.py -v
.venv/bin/python examples/independent-agent-pilot/run_pilot.py
.venv/bin/python examples/independent-agent-pilot/make_fresh_fixture.py --output-dir ../input
date -u '+%Y-%m-%dT%H:%M:%SZ'
sha256sum ../input/bundle.json ../input/policy.json
```

Copy the hashes from the preceding output and the operator’s UTC reading into
this command. Preserve the first command’s stdout, stderr and exit status,
then repeat the identical command once to capture replay refusal:

```sh
.venv/bin/python examples/independent-agent-pilot/run_action.py \
  --record-assessment \
  --bundle ../input/bundle.json \
  --policy ../input/policy.json \
  --bundle-sha256 sha256:<fresh-bundle-hash> \
  --policy-sha256 sha256:<fresh-policy-hash> \
  --now-utc <operator-UTC-reading> \
  --max-age-seconds 86400 \
  --output-dir ../positive
```

Expected: the first call records exactly one local assessment; the second call
refuses as replay. The consumer `ACCEPT` and local assessment are not an
authorization, do not show that the receipt’s claimed action occurred, and do
not prove the operator’s identity or administrative independence.

The regression suite executes these additional negative/recovery cases with
synthetic fixtures: tampered output, stale/expired signed fixture, absent
required proof, changed raw input pin, interrupted `PREPARED` state with
fail-closed follow-up, and concurrent duplicate calls. The operator should
retain the complete test output and identify the corresponding test names.
No production data or external service is involved.

### Operator return capture template

Return the archive SHA-256, `SOURCE-PIN.json`, `SOURCE-MANIFEST.json`, test
output, raw fixture and policy hashes, action command, stdout/stderr/exit
codes, and `assessment.json` with its SHA-256. Keep unredacted personal or
provider-account details private; provide the independent reviewer enough
evidence to assess separation without posting credentials, account numbers,
private keys, or customer information.

```text
Operator identifier used for this exercise:
Relationship to CR maintainer/producer:
Host control: (operator-owned machine / separately administered cloud host / other)
Who has root or administrator rights on this host:
Cloud/hardware account and organization administered by:
Shared with the producer’s fleet, cloud account, root operators, CI, or deployment credentials? (yes/no; explain)
Can the producer modify this host or its installed software without the operator’s approval? (yes/no; explain)
Evidence offered privately to the reviewer for the administrative-separation statement:
Host OS/kernel and architecture:
Python version:
cryptography version and how it was installed:
Packet archive SHA-256:
SOURCE-PIN.json SHA-256:
SOURCE-MANIFEST.json SHA-256:
sha256sum -c result:
Imported continuity_receipt.consumer path and SHA-256:
Imported verifier dependency paths and SHA-256 values:
Installed distribution metadata version, if any (metadata only):
Exact UTC time supplied to run_action.py:
Fresh bundle bytes and SHA-256:
Fresh policy bytes and SHA-256:
Positive action command, stdout, stderr, exit code:
assessment.json bytes and SHA-256:
Replay command, refusal reason, exit code:
Test suite command, summary and raw output path/hash:
Negative control outcomes: tampered / expired / missing proof / wrong pin / interruption:
Installation or execution friction and any operator assistance received:
Unexpected observations or deviations:
Operator statement: no receipt-claimed action was executed by this exercise:
Reviewer identity, retrieval method, and recomputed hash/result notes:
```

Administrative separation must be evaluated independently. A different
hostname, agent name, operating system, model, or successful signature alone
does not show who controls root, cloud credentials, CI, deployment, or the
operator’s account. The reviewer should record whether the machine and
administrative control plane are outside the producer’s fleet and whether the
operator could inspect/change the returned evidence. Do not report stronger
separation than the operator can substantiate.

## Earlier Mac and W2 artifacts remain distinct

- The frozen Mac packet released at Sangha #491 has archive SHA-256
  `451eb4269c9c28e6b303bad7abf0f3ee024e869602578d0732a6d813fb27824c`.
  Its native Mac return is Sangha #495 (macOS/arm64, Python 3.14.7) and passed
  primary hash/assessment review. It used the same fleet administration, so
  it is second-host platform evidence, not independently administered
  adoption. Do not overwrite its packet or return.
- The frozen Mandala W2 packet released at Sangha #497 has archive SHA-256
  `e657bbfe3989b34565e21a6cc0f4c74b5bc5d5940161ad5f0fd876e12be1d8a0`
  (private L2 source `ca79981`). Its real Linux/W2 operator return is still
  outstanding. Do not substitute this Continuity Receipt packet for that
  separate capture or overwrite the W2 archive.

The primary corrected the operator-directory paths, independently verified
27/27 source hashes, reran the 16 action tests, and exercised fresh positive
CLI assessment plus replay refusal from a clean extraction before #500.
This handoff prepares evidence collection; it does not establish independent
adoption or close the external relying-party gate.
