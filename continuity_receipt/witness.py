"""Validate a caller-supplied checkpoint floor before receiver delivery.

This module performs no network retrieval, authentication or discovery of the
latest state. The caller must retain its reference outside the restore boundary.
"""
from __future__ import annotations

from dataclasses import dataclass
import re


_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_GENERATION_RE = re.compile(r"[0-9a-f]{32}\Z")


def _sequence_valid(value) -> bool:
    return type(value) is int and value >= 1


def _digest_valid(value) -> bool:
    return type(value) is str and _DIGEST_RE.fullmatch(value) is not None


def _generation_valid(value) -> bool:
    return value is None or (type(value) is str and _GENERATION_RE.fullmatch(value) is not None)


@dataclass(frozen=True, kw_only=True)
class OffHostWitness:
    """A supplied sequence floor and its checkpoint binding, not a service.

    At the floor, checkpoint and optional generation must match. A higher local
    sequence is permitted. ``expected_checkpoint_digest`` pins the supplied
    witness to a reference obtained separately by the caller; neither this pin
    nor an observation timestamp proves which reference is globally newest.
    """

    min_sequence: int
    latest_checkpoint: str
    generation_id: str | None = None
    expected_checkpoint_digest: str | None = None

    def __post_init__(self):
        if not _sequence_valid(self.min_sequence):
            raise ValueError("off_host_witness_sequence_invalid")
        if not _digest_valid(self.latest_checkpoint):
            raise ValueError("off_host_witness_checkpoint_invalid")
        if not _generation_valid(self.generation_id):
            raise ValueError("off_host_witness_generation_invalid")
        if self.expected_checkpoint_digest is not None:
            if not _digest_valid(self.expected_checkpoint_digest):
                raise ValueError("off_host_witness_expected_reference_invalid")
            if self.expected_checkpoint_digest != self.latest_checkpoint:
                raise ValueError("off_host_witness_reference_mismatch")

    @classmethod
    def from_dict(cls, data: dict, *, expected_checkpoint_digest: str | None = None) -> OffHostWitness:
        required = {"sequence", "checkpoint_digest"}
        allowed = required | {"generation_id"}
        if type(data) is not dict or not required <= set(data) <= allowed:
            raise ValueError("off_host_witness_invalid")
        return cls(min_sequence=data["sequence"], latest_checkpoint=data["checkpoint_digest"],
                   generation_id=data.get("generation_id"),
                   expected_checkpoint_digest=expected_checkpoint_digest)

    def verify(self, *, sequence: int, checkpoint_digest: str, generation_id: str | None = None) -> dict:
        if not _sequence_valid(sequence):
            return {"trusted": False, "reason": "off_host_witness_sequence_invalid"}
        if not _digest_valid(checkpoint_digest):
            return {"trusted": False, "reason": "off_host_witness_checkpoint_invalid"}
        if not _generation_valid(generation_id):
            return {"trusted": False, "reason": "off_host_witness_generation_invalid"}
        if sequence < self.min_sequence:
            return {
                "trusted": False,
                "reason": f"joint_rollback_detected:sequence_{sequence}_below_witness_{self.min_sequence}",
            }
        if sequence == self.min_sequence:
            if checkpoint_digest != self.latest_checkpoint:
                return {
                    "trusted": False,
                    "reason": f"joint_rollback_detected:checkpoint_mismatch_at_sequence_{sequence}",
                }
            if self.generation_id is not None and generation_id != self.generation_id:
                return {
                    "trusted": False,
                    "reason": f"joint_rollback_detected:generation_mismatch_at_sequence_{sequence}",
                }
        return {"trusted": True, "reason": "witness_verified"}
