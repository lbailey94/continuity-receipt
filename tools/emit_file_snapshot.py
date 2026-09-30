#!/usr/bin/env python3
"""Example 0.5 producer: sign a file's byte count and SHA-256 at read time.

This is an issuer statement. Consumers must receive and hash the file to
corroborate the state commitment. The private key stays in a caller-owned PEM.
"""
import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives.serialization import load_pem_private_key

from continuity_receipt.bundle import TaskChain
from continuity_receipt.canon import canonical_bytes, sha256_prefixed
from continuity_receipt.keys import pubkey_to_did_key
from continuity_receipt.verify import verify_bundle


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot', type=Path, help='file to read and commit')
    parser.add_argument('--mandate', type=Path, required=True, help='local authorization document to hash')
    parser.add_argument('--key-pem', type=Path, required=True, help='caller-owned Ed25519 private key')
    parser.add_argument('--scope', required=True, help='opaque identifier for this snapshot scope')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()

    if args.output.resolve() in (args.snapshot.resolve(), args.mandate.resolve(), args.key_pem.resolve()):
        parser.error('--output must be separate from the snapshot, mandate, and private key')

    key = load_pem_private_key(args.key_pem.read_bytes(), password=None)
    did = pubkey_to_did_key(key.public_key())
    snapshot_bytes = args.snapshot.read_bytes()
    snapshot_hash = sha256_prefixed(snapshot_bytes)
    mandate_hash = sha256_prefixed(args.mandate.read_bytes())
    args_hash = sha256_prefixed(canonical_bytes({'scope': args.scope, 'operation': 'file-snapshot'}))
    now = datetime.now(timezone.utc).replace(microsecond=0)
    expires = (now + timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
    policy = 'example/local-file-snapshot/1'
    chain = TaskChain(spec='continuity-receipt/0.5')
    chain.add('session.pass.created', 'agent', did, key, {
        'gate_id': 'local:' + args.scope, 'mandala_class': 'local',
        'quotas': {'cpu_ms': 0, 'mem_mb': 0, 'disk_mb': 0, 'wall_ms': 0},
        'expires_at': expires, 'policy_version': policy,
        'mandate_ref': mandate_hash, 'agent_id': did,
    })
    chain.add('task.decision', 'agent', did, key, {
        'action': 'file.snapshot', 'action_args_hash': args_hash,
        'model': {'provider': 'local', 'id': 'file-snapshot-script'},
        'input_provenance': {'policy_id': policy, 'allowed_sources': ['local-file'],
                             'observed_sources_hash': snapshot_hash},
        'decision': 'allow', 'policy_version': policy,
    })
    chain.add('task.execution', 'agent', did, key, {
        'tool_calls': [{'name': 'read-and-hash', 'args_hash': args_hash, 'result_hash': snapshot_hash}],
        'egress': [], 'resources': {'cpu_ms': 0, 'mem_peak_mb': 0, 'disk_peak_mb': 0},
        'sandbox_class': 'none',
    })
    chain.add('state.commitment', 'agent', did, key, {
        'state_kind': 'file-snapshot-bytes', 'scope': args.scope,
        'count': len(snapshot_bytes), 'head_digest': snapshot_hash,
    })
    chain.add('task.termination', 'agent', did, key, {
        'reason': 'completed', 'limits_at_stop': {'cpu_ms': 0, 'wall_ms': 0,
        'spend_minor': 0, 'currency': 'USD'}, 'remaining': {},
    })
    bundle = chain.bundle()
    result = verify_bundle(bundle)
    if result.verdict != 'TRUSTED':
        raise SystemExit(f'generated bundle failed local verification: {result.as_dict()}')
    args.output.write_text(json.dumps(bundle, indent=2) + '\n')
    print(json.dumps({'bundle': str(args.output), 'verdict': result.verdict,
                      'snapshot_sha256': snapshot_hash, 'snapshot_bytes': len(snapshot_bytes)}))


if __name__ == '__main__':
    main()
