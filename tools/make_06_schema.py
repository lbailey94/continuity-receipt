#!/usr/bin/env python3
"""Derive the 0.6 schema from the 0.5 schema (additive only).

The 0.6 schema allows everything the 0.5 schema allows, adds the
`authority.grant` receipt type (0.6-only), and lets 0.6 receipts use the 0.5
`state.commitment` type and 0.5 execution-profile bodies.
"""
import copy
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "schema" / "continuity-receipt-0.5.schema.json"
DST = ROOT / "schema" / "continuity-receipt-0.6.schema.json"

AUTHORITY_BODY = {
    "type": "object",
    "required": ["grant_id", "principal", "agent", "scope", "granted_at"],
    "additionalProperties": False,
    "properties": {
        "grant_id": {"type": "string", "minLength": 1},
        "principal": {
            "type": "object",
            "required": ["id", "assurance"],
            "additionalProperties": False,
            "properties": {
                "id": {"type": "string", "minLength": 1},
                "assurance": {"enum": ["self_asserted", "issuer_verified"]},
            },
        },
        "agent": {"type": "string", "minLength": 1},
        "scope": {"type": "array", "minItems": 1, "items": {"type": "string", "minLength": 1}},
        "granted_at": {"$ref": "#/$defs/timestamp"},
        "expires_at": {"$ref": "#/$defs/timestamp"},
        "constraints": {"type": "object"},
        "review_policy": {"enum": ["none", "flagged", "full"]},
        "policy_ref": {"$ref": "#/$defs/hash"},
        "gate_ref": {"type": "string", "minLength": 1},
    },
}


def main() -> None:
    schema = json.loads(SRC.read_text(encoding="utf-8"))
    schema["$id"] = schema["$id"].replace("0.5", "0.6")
    schema["title"] = "Continuity Receipt bundle (continuity-receipt/0.1–0.6)"
    schema["properties"]["spec"]["enum"].append("continuity-receipt/0.6")

    receipt = schema["$defs"]["receipt"]
    receipt["properties"]["type"]["enum"].append("authority.grant")
    receipt["properties"]["spec"]["enum"].append("continuity-receipt/0.6")

    # mirror the spec-pinned 0.5 execution entry for 0.6
    for entry in list(receipt["allOf"]):
        cond = entry.get("if", {}).get("properties", {})
        if cond.get("spec", {}).get("const") == "continuity-receipt/0.5":
            clone = copy.deepcopy(entry)
            clone["if"]["properties"]["spec"]["const"] = "continuity-receipt/0.6"
            receipt["allOf"].append(clone)

    # the state.commitment pin accepts 0.5 or 0.6 receipts
    for entry in receipt["allOf"]:
        then_spec = entry.get("then", {}).get("properties", {}).get("spec")
        if then_spec == {"const": "continuity-receipt/0.5"}:
            entry["then"]["properties"]["spec"] = {
                "enum": ["continuity-receipt/0.5", "continuity-receipt/0.6"]
            }

    # authority.grant: body shape + 0.6-only pin
    receipt["allOf"].append({
        "if": {"properties": {"type": {"const": "authority.grant"}}},
        "then": {"properties": {"body": {"$ref": "#/$defs/body_authority_grant"}}},
    })
    receipt["allOf"].append({
        "if": {"properties": {"type": {"const": "authority.grant"}}},
        "then": {"properties": {"spec": {"const": "continuity-receipt/0.6"}}},
    })

    schema["$defs"]["body_authority_grant"] = AUTHORITY_BODY
    DST.write_text(json.dumps(schema, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {DST} ({len(json.dumps(schema))} bytes)")


if __name__ == "__main__":
    main()
