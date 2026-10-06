"""Narrow review-policy checks for the runnable text-claim fixture."""


def validate_claim_review(claims: dict, source_bytes: bytes) -> list[dict]:
    """Validate the fixture's bounded grades and return its claim rows.

    These checks ensure structural consistency and exact quoted support. They
    do not infer meaning or establish that a statement in the source is true.
    """
    if not isinstance(claims, dict):
        raise ValueError("claims must be an object")
    source = claims.get("source")
    if not isinstance(source, dict) or any(
        not isinstance(source.get(field), str) or not source[field].strip()
        for field in ("url", "snapshot_path", "snapshot_commit", "capture_note")
    ):
        raise ValueError("claims.source must contain non-empty URL, snapshot, commit, and capture note")
    rows = claims.get("claims")
    if not isinstance(rows, list) or not rows:
        raise ValueError("claims must be a non-empty list")
    seen_ids = set()
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("each claim row must be an object")
        for field in ("id", "claim", "limit"):
            if not isinstance(row.get(field), str) or not row[field].strip():
                raise ValueError(f"claim row {field} must be a non-empty string")
        if row["id"] in seen_ids:
            raise ValueError("claim row ids must be unique")
        seen_ids.add(row["id"])
        if row.get("grade") not in ("supported_by_excerpt", "not_established_by_excerpt"):
            raise ValueError("claim grade is outside the example's explicit grade vocabulary")
        span = row.get("supporting_text")
        if row["grade"] == "supported_by_excerpt":
            if not isinstance(span, str) or not span or span.encode("utf-8") not in source_bytes:
                raise ValueError("supported_by_excerpt rows must quote bytes present in the supplied snapshot")
        elif span is not None:
            raise ValueError("not_established_by_excerpt rows must not carry a supporting quote")
    return rows
