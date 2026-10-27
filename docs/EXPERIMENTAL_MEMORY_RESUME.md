# Experimental checkpointed memory receiver

This local prototype snapshots a closed directory of regular files, signs one
CPR 0.5 `state.commitment`, and releases selected UTF-8 text only after the
existing receiver checkpoint is accepted. The checkpoint reference, receiver
context, scope, PEM public key, and freshness limit are explicit local policy.
No command refreshes trust during recall or resume.

Install the checkout in an isolated environment with `python -m pip install
-e .`. The installed command is `cpr-memory`; the equivalent module command is
`python -m continuity_receipt.memory_resume`. Every command requires
`--data-root`, `--trust-db`, `--context`, `--scope`, and `--public-key` (an
Ed25519 PEM public key). `--max-age` defaults to 3600 seconds and `--now`
accepts a UTC timestamp for controlled local runs.
The clock and `--now` override are trusted operator inputs. Backdating the
evaluation instant can make old evidence appear within its age window; this
flag supplies test time and is not a remote freshness guarantee. Normal use
omits it and evaluates the current UTC time.

Initialize the receiver's local trust policy explicitly:

```sh
cpr-memory init --data-root ./memory-receiver --trust-db ./memory-trust.sqlite \
  --context local-memory --scope user:local --public-key ./writer-public.pem
```

Publish a fresh snapshot using the matching Ed25519 private key. The initial
expected reference is `none`; later publishes must supply the current
checkpoint digest returned by `status` or the prior publish result.

```sh
cpr-memory publish --data-root ./memory-receiver --trust-db ./memory-trust.sqlite \
  --context local-memory --scope user:local --public-key ./writer-public.pem \
  --key-pem ./writer-private.pem --expected-reference none --input-root ./memory-export
```

Inspect the retained reference, then recall metadata and file paths/digests:

```sh
cpr-memory status --data-root ./memory-receiver --trust-db ./memory-trust.sqlite \
  --context local-memory --scope user:local --public-key ./writer-public.pem
cpr-memory recall --data-root ./memory-receiver --trust-db ./memory-trust.sqlite \
  --context local-memory --scope user:local --public-key ./writer-public.pem
```

Resume one selected file. On acceptance, stdout contains only that exact
UTF-8 text; the assessment goes to stderr. Empty files are valid and produce
empty stdout. Refusal produces no stdout. Exit status is 0 for ACCEPT, 1 for
NEEDS_EVIDENCE, and 2 for REJECT or an operator error.

```sh
cpr-memory resume --data-root ./memory-receiver --trust-db ./memory-trust.sqlite \
  --context local-memory --scope user:local --public-key ./writer-public.pem \
  --memory-path notes/today.txt
```

The captured snapshot is capped at 64 files, 1 MiB per file, 4 MiB total,
4096 tree entries, and 32 directory levels.
Paths are relative POSIX paths normalized to Unicode NFC; symlinks and special
files are refused. Full selected-snapshot verification happens before a path
is emitted. This is local experimental custody: signed integrity does not
establish completeness, truth, freshness beyond the configured checkpoint,
issuer honesty, or universal erasure. Old immutable generations remain on
disk, and restoring the trust database together with old data can restore an
older accepted reference.

The current durable publisher requires POSIX descriptor-relative no-follow
I/O and Linux `renameat2(RENAME_NOREPLACE)`. Unsupported publication fails
explicitly; no cross-platform durability claim is made. Crash probes terminate
processes at four boundaries and inspect restart recovery. They do not simulate
power loss or storage-device write-cache failure.
