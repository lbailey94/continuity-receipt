"""Off-Host Witness and Monotonic Counter Provider for Rollback Resistance."""
from __future__ import annotations

class OffHostWitness:
    """Witness maintaining independent, non-rewindable state references (SCITT / TPM monotonic / external)."""

    def __init__(self, *, min_sequence: int = 0, latest_checkpoint: str | None = None):
        self.min_sequence = min_sequence
        self.latest_checkpoint = latest_checkpoint

    @classmethod
    def from_dict(cls, data: dict) -> OffHostWitness:
        return cls(
            min_sequence=data.get("sequence", 0),
            latest_checkpoint=data.get("checkpoint_digest"),
        )

    def verify(self, *, sequence: int, checkpoint_digest: str, generation_id: str | None = None) -> dict:
        if sequence < self.min_sequence:
            return {
                "trusted": False,
                "reason": f"joint_rollback_detected:sequence_{sequence}_below_witness_{self.min_sequence}",
            }
        if self.latest_checkpoint and sequence == self.min_sequence and checkpoint_digest != self.latest_checkpoint:
            return {
                "trusted": False,
                "reason": f"joint_rollback_detected:checkpoint_mismatch_at_sequence_{sequence}",
            }
        return {"trusted": True, "reason": "witness_verified"}
