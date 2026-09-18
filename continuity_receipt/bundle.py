"""Task chains and bundles (0.1 + 0.2).

Chain-link rule (freezes a spec ambiguity): `prev` and signatures are both
computed over the canonical bytes of the receipt **excluding** the `sig`
member. One canonicalization rule for both.
"""
from . import records
from .canon import canonical_bytes, sha256_prefixed


def receipt_digest(receipt: dict) -> str:
    return sha256_prefixed(canonical_bytes(records.unsigned_view(receipt)))


class TaskChain:
    def __init__(self, task_id: str | None = None, spec: str | None = None, ms_timestamps: bool = False):
        self.task_id = task_id or ("urn:uuid:" + str(records.uuid7()))
        self.spec = spec or records.SPEC_ID
        self.ms_timestamps = ms_timestamps
        self.receipts: list[dict] = []

    def add(
        self,
        record_type: str,
        issuer_kind: str,
        issuer_did: str,
        private_key,
        body: dict,
    ) -> dict:
        prev = receipt_digest(self.receipts[-1]) if self.receipts else None
        receipt = records.new_envelope(
            self.task_id,
            issuer_kind,
            issuer_did,
            record_type,
            len(self.receipts),
            prev,
            body,
            spec=self.spec,
            issued_at=records.utc_now_rfc3339(ms=self.ms_timestamps),
        )
        receipt = records.sign_receipt(receipt, private_key, issuer_did)
        self.receipts.append(receipt)
        return receipt

    def bundle(
        self,
        disclosure_map: dict | None = None,
        anchors: list | None = None,
        revocations: list | None = None,
    ) -> dict:
        bundle = {
            "spec": self.spec,
            "task_id": self.task_id,
            "receipts": self.receipts,
        }
        if disclosure_map:
            bundle["disclosure_map"] = disclosure_map
        if anchors:
            bundle["anchors"] = anchors
        if revocations:
            bundle["revocations"] = revocations
        return bundle
