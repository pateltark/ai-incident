"""
fingerprint.py

Turns an error message into a stable ID, so the same underlying problem
always produces the same fingerprint - even though the exact numbers,
IDs, and IPs inside the message differ every time it happens.

Example (from the plan):
    raw:         connection pool exhausted (active=50/50) for user 88231
    normalized:  connection pool exhausted (active=<n>/<n>) for user <n>
    fingerprint: sha1(normalized)[:12]

This is what makes deduplication possible: 200 instances of the same
error, with 200 different user IDs, all collapse to one fingerprint - so
the detector opens exactly one incident instead of 200.

Order matters when normalizing: UUIDs and IPs are replaced before plain
numbers, because a plain-number pass would otherwise chew through an IP
address or a UUID one digit group at a time and leave a mangled result.
"""

import hashlib
import re

_UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE
)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Long hex-looking tokens (request IDs, container IDs, hashes) - 6+ hex
# chars, and must contain at least one a-f letter. Without that lookahead,
# a purely-numeric run like "999999" is technically valid hex too and would
# get caught here instead of by _NUM_RE, giving it a different placeholder
# than a shorter numeric ID like "50" - breaking the very consistency
# fingerprinting depends on.
_HEX_RE = re.compile(r"\b(?=[0-9a-f]*[a-f])[0-9a-f]{6,}\b", re.IGNORECASE)
_NUM_RE = re.compile(r"\b\d+\b")
_WS_RE = re.compile(r"\s+")


def normalize(message: str) -> str:
    """Lowercase a message and replace volatile parts (UUIDs, IPs, hex
    tokens, plain numbers) with placeholders, so two messages that differ
    only in those parts normalize to the same string."""
    text = message.lower().strip()
    text = _UUID_RE.sub("<uuid>", text)
    text = _IP_RE.sub("<ip>", text)
    text = _HEX_RE.sub("<hex>", text)
    text = _NUM_RE.sub("<n>", text)
    text = _WS_RE.sub(" ", text)
    return text


def fingerprint(message: str, length: int = 12) -> str:
    """Returns a short stable hex ID for a message. Same underlying
    problem -> same fingerprint, regardless of embedded numbers/IDs."""
    normalized = normalize(message)
    digest = hashlib.sha1(normalized.encode("utf-8")).hexdigest()
    return digest[:length]


if __name__ == "__main__":
    # Quick self-check against the example from the plan, plus a few
    # realistic variants your fault scenarios will actually produce.
    examples = [
        "connection pool exhausted (active=50/50) for user 88231",
        "connection pool exhausted (active=48/50) for user 12",
        "connection pool exhausted (active=50/50) for user 999999",
        'duplicate key value violates unique constraint "orders_pkey"',
        "gateway timeout after 30000ms for request 8f3a1c2d9b3e4f1a",
        "gateway timeout after 30000ms for request aa11bb22cc33dd44",
        "sku not found",
    ]
    print(f"{'fingerprint':<14} normalized")
    print("-" * 70)
    for msg in examples:
        fp = fingerprint(msg)
        print(f"{fp:<14} {normalize(msg)}")

    # sanity: the two pool-exhaustion variants (different user, different
    # active count) must collapse to the same fingerprint
    fp1 = fingerprint(examples[0])
    fp2 = fingerprint(examples[1])
    fp3 = fingerprint(examples[2])
    assert fp1 == fp2 == fp3, "pool exhaustion variants should share one fingerprint"

    # the two gateway-timeout variants (different request id) must also match
    fp4 = fingerprint(examples[4])
    fp5 = fingerprint(examples[5])
    assert fp4 == fp5, "gateway timeout variants should share one fingerprint"

    # but pool exhaustion and gateway timeout must NOT collide with each other
    assert fp1 != fp4

    print("\nself-check passed: same problem -> same fingerprint, different problems -> different fingerprints")