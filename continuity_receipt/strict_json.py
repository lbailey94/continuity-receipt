"""Strict raw JSON parsing for signed receipt and verification inputs.

JSON objects with repeated member names are ambiguous across parsers and are
not permitted by the receipt wire formats. Keep this check at the byte/text
boundary, before converting objects to dictionaries.
"""
import json


def _unique_members(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object member: {key!r}")
        result[key] = value
    return result


def loads(data):
    """Decode JSON while rejecting repeated member names at any nesting depth."""
    return json.loads(data, object_pairs_hook=_unique_members)


def load(handle):
    """Read and strictly decode JSON from a text or binary stream."""
    return loads(handle.read())
