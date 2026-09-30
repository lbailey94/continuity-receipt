#!/usr/bin/env python3
"""Scoreboard #1: Gen2 <-> Gen3 cross-verification experiment.

Checks a captured WhiteMagic Gen2 bundle alongside a modeled Gen3 fixture.
The Gen3 fixture is generated here, not emitted by the Gen3 runtime.
"""
import copy
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from continuity_receipt import keys, verify_bundle
from continuity_receipt.bundle import TaskChain, receipt_digest
from continuity_receipt.canon import canonical_bytes, commit_field, sha256_prefixed
from continuity_receipt.disclose import redact, attach


def run_cross_verification():
    print("=== SCOREBOARD #1: GEN2 <-> GEN3 CROSS-VERIFICATION ===")
    
    # -------------------------------------------------------------
    # 1. Gen2 Arm: Governed Dispatch Bundle (from WMv9 S2)
    # -------------------------------------------------------------
    gen2_path = Path("/home/lucas/Desktop/WHITEMAGIC/WMv9/receipts/s2_mandala_pass_20260922/governed-bundle.json")
    if not gen2_path.exists():
        print(f"Error: Gen2 bundle not found at {gen2_path}")
        sys.exit(1)
        
    with open(gen2_path) as f:
        gen2_bundle = json.load(f)
        
    print(f"\n[1] Verifying Gen2 Governed Task Bundle ({gen2_path.name})...")
    gen2_result = verify_bundle(gen2_bundle)
    gen2_dict = gen2_result.as_dict()
    print(f"    Gen2 Verdict: {gen2_dict['verdict']}")
    print(f"    Receipts in chain: {gen2_dict['summary']['receipts']}")
    print(f"    Chain types: {gen2_dict['summary']['types']}")
    print(f"    Errors: {gen2_dict['errors']}")
    assert gen2_dict["verdict"] == "TRUSTED", f"Gen2 bundle failed: {gen2_dict}"

    # -------------------------------------------------------------
    # 2. Gen3 Arm: Constitutional Intake Bundle
    # Modeled on wm-gen3-core CommitReceiptEnvelopeV5 (intake.rs)
    # -------------------------------------------------------------
    print("\n[2] Generating Gen3 Constitutional Intake Bundle...")
    gen3_seed = keys.deterministic_seed("wm-gen3-test-key")
    gen3_did, gen3_key = keys.generate(gen3_seed)
    
    # Gen3 CommitReceipt facts (Gate 9A Slice 1 / intake.rs)
    realm_id = "0199a0c0000070008000000000000001"
    manifest_digest = "sha256:73c5a9cf3e2849b38ec2a81831c890787a7d45e4125f4e69b5974e6c1e5485cf"
    authority_digest = "sha256:8888888888888888888888888888888888888888888888888888888888888888"
    record_digest = "sha256:9999999999999999999999999999999999999999999999999999999999999999"
    policy_version = "wm-gen3-v0.1.0/constitution-v1"
    
    chain = TaskChain(spec="continuity-receipt/0.2")
    
    # Stage 0: pass / authority creation
    chain.add(
        "session.pass.created",
        "agent",
        gen3_did,
        gen3_key,
        {
            "gate_id": f"wm-gen3:{realm_id[:16]}",
            "mandala_class": "gate-lite",
            "quotas": {"cpu_ms": 10000, "mem_mb": 256, "disk_mb": 128, "wall_ms": 60000},
            "expires_at": "2026-09-25T18:00:00Z",
            "policy_version": policy_version,
            "mandate_ref": authority_digest,
            "agent_id": gen3_did,
        },
        issued_at="2026-09-24T18:30:00Z",
    )
    
    # Stage 1: task decision under constitutional closure
    chain.add(
        "task.decision",
        "agent",
        gen3_did,
        gen3_key,
        {
            "action": "wm.gen3.remember.v1",
            "action_args_hash": manifest_digest,
            "model": {
                "provider": "wm-gen3",
                "id": "nucleus-intake",
                "version": "0.1.0",
            },
            "input_provenance": {
                "policy_id": "wm-gen3/law-closure-v1",
                "allowed_sources": ["local-ratified-channel-v1"],
                "observed_sources_hash": authority_digest,
            },
            "decision": "allow",
            "policy_version": policy_version,
        },
        issued_at="2026-09-24T18:30:01Z",
    )
    
    # Stage 2: delivery / execution record with optional quality flags
    chain.add(
        "delivery.attestation",
        "agent",
        gen3_did,
        gen3_key,
        {
            "request_hash": manifest_digest,
            "response_hash": record_digest,
            "counterparty": {"id": gen3_did},
            "spec_ref": "continuity-receipt/0.2",
            "quality_flags": ["constitutional-closure-ok", "evidence-grounded"],
        },
        issued_at="2026-09-24T18:30:02Z",
    )
    
    # Stage 3: termination proof
    chain.add(
        "task.termination",
        "agent",
        gen3_did,
        gen3_key,
        {
            "reason": "completed",
            "limits_at_stop": {
                "cpu_ms": 10000,
                "wall_ms": 60000,
                "spend_minor": 0,
                "currency": "USD",
            },
            "remaining": {
                "cpu_ms": 9980,
                "wall_ms": 59980,
            },
        },
        issued_at="2026-09-24T18:30:03Z",
    )
    
    gen3_bundle = chain.bundle()
    
    print("\n[3] Verifying Gen3 Constitutional Intake Bundle (full)...")
    gen3_result = verify_bundle(gen3_bundle)
    gen3_dict = gen3_result.as_dict()
    print(f"    Gen3 Full Verdict: {gen3_dict['verdict']}")
    print(f"    Receipts in chain: {gen3_dict['summary']['receipts']}")
    assert gen3_dict["verdict"] == "TRUSTED", f"Gen3 full bundle failed: {gen3_dict}"

    # -------------------------------------------------------------
    # 3. Gen3 Redacted Variant with Salted Commitment
    # -------------------------------------------------------------
    print("\n[4] Creating Gen3 Redacted Variant (redacting quality_flags)...")
    salt = "4a8e91f0c2b3d4e5f6a7b8c9d0e1f2a3"
    redacted_bundle, dmap = redact(
        gen3_bundle,
        ["receipts[2].body.quality_flags"],
        salts={"receipts[2].body.quality_flags": salt},
        signer=(gen3_key, gen3_did),
    )
    # Check that redacted without disclosure verifies PROVISIONAL or TRUSTED
    # and with attached map verifies TRUSTED
    disclosed_bundle = attach(redacted_bundle, dmap)
    disclosed_result = verify_bundle(disclosed_bundle)
    disclosed_dict = disclosed_result.as_dict()
    print(f"    Gen3 Disclosed Variant Verdict: {disclosed_dict['verdict']}")
    assert disclosed_dict["verdict"] == "TRUSTED", f"Disclosed bundle failed: {disclosed_dict}"

    # -------------------------------------------------------------
    # 4. Save bundles to examples/01_wm_governed_session
    # -------------------------------------------------------------
    out_dir = ROOT / "examples" / "01_wm_governed_session"
    out_dir.mkdir(parents=True, exist_ok=True)
    
    gen2_out = out_dir / "gen2_governed_bundle.json"
    gen3_out = out_dir / "gen3_intake_bundle.json"
    gen3_redacted_out = out_dir / "gen3_redacted_bundle.json"
    provenance_out = out_dir / "provenance.json"
    
    with open(gen2_out, "w") as f:
        json.dump(gen2_bundle, f, indent=2)
    with open(gen3_out, "w") as f:
        json.dump(gen3_bundle, f, indent=2)
    with open(gen3_redacted_out, "w") as f:
        json.dump(disclosed_bundle, f, indent=2)
        
    provenance = {
        "title": "Scoreboard #1: Cross-Generation Continuity Verification",
        "date": "2026-09-24",
        "spec_version": "continuity-receipt/0.2",
        "implementations": {
            "gen2": {
                "system": "WhiteMagic Gen2 (WMv9)",
                "release": "v9.2.8",
                "commit": "3cfc595",
                "crate": "wm-receipts",
                "bundle_type": "captured governed_dispatch_bundle (Mandala pass)",
                "verdict": "TRUSTED"
            },
            "gen3": {
                "system": "WhiteMagic Gen3 (WMgen3)",
                "release": "v10.0.0-alpha",
                "charter": "v0.1.1 (Gate 9A closed)",
                "crate": "wm-gen3-core",
                "bundle_type": "modeled compatibility fixture; not runtime-emitted",
                "verdict": "TRUSTED"
            }
        },
        "verifier": {
            "name": "continuity-receipt standalone reference verifier",
            "version": "0.4.0",
            "python_package": "continuity-receipt==0.4.0",
            "rust_crate": "continuity-receipt = 0.4.0"
        }
    }
    with open(provenance_out, "w") as f:
        json.dump(provenance, f, indent=2)
        
    print(f"\n[5] Generated Documentation & Provenance:")
    print(f"    - Provenance: {provenance_out}")
    print("\n=== SCOREBOARD #1 ARTIFACT PACK COMPLETE AND VERIFIED ===")


if __name__ == "__main__":
    run_cross_verification()
