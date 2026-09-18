"""Task chains and bundles (v0).

Chain-link rule (freezes a spec ambiguity): `prev` and signatures are both
computed over the canonical bytes of the receipt **excluding** the `sig`
member. One canonicalization rule for both.
"""
from . import records
from .canon import canonical_bytes, sha256_prefixed


def receipt_digest(receipt: dict) -> str:
    return sha256_prefixed(canonical_bytes(records.unsigned_view(receipt)))


class TaskChain:
    def __init__(self, task_id: str | None = None):
        self.task_id = task_id or ("urn:uuid:" + str(records.uuid7()))
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
        )
        receipt = records.sign_receipt(receipt, private_key, issuer_did)
        self.receipts.append(receipt)
        return receipt

    def bundle(self, disclosure_map: dict | None = None, anchors: list | None = None) -> dict:
        bundle = {
            "spec": records.SPEC_ID,
            "task_id": self.task_id,
            "receipts": self.receipts,
        }
        if disclosure_map:
            bundle["disclosure_map"] = disclosure_map
        if anchors:
            bundle["anchors"] = anchors
        return bundle
