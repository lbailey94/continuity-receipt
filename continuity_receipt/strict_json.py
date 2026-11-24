"""Strict raw JSON parsing for signed receipt and verification inputs.

JSON objects with repeated member names are ambiguous across parsers and are
not permitted by the receipt wire formats. Keep this check at the byte/text
boundary, before converting objects to dictionaries.
"""
import json


def _unique_members(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        seen = set()
        for key, _ in pairs:
            if key in seen:
                raise ValueError(f"duplicate JSON object member: {key!r}")
            seen.add(key)
    return result


_STRICT_DECODER = json.JSONDecoder(object_pairs_hook=_unique_members)


def loads(data):
    """Decode JSON while rejecting repeated member names at any nesting depth."""
    if type(data) is str:
        return _STRICT_DECODER.decode(data)
    return json.loads(data, object_pairs_hook=_unique_members)


def load(handle):
    """Read and strictly decode JSON from a text or binary stream."""
    return loads(handle.read())
