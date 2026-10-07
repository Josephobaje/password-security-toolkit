"""Breach checks against Have I Been Pwned's *Pwned Passwords* API.

Privacy model (k-anonymity)
---------------------------
The password is hashed locally with SHA-1. Only the **first 5 hex characters**
of that hash are sent to ``https://api.pwnedpasswords.com/range/<prefix>``.
The API answers with every known hash suffix that shares the prefix (typically
800-1,000 of them, and padded with decoys because we send ``Add-Padding``),
and the comparison with our own suffix happens locally. Neither the password
nor its full hash ever leaves the machine.
"""

from __future__ import annotations

import hashlib
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

API_URL = "https://api.pwnedpasswords.com/range/{prefix}"
USER_AGENT = (
    "password-security-toolkit/1.0 (+https://github.com/Josephobaje/password-security-toolkit)"
)
PREFIX_LENGTH = 5
DEFAULT_TIMEOUT = 10.0

Fetcher = Callable[[str, float], str]


class BreachCheckError(RuntimeError):
    """Raised when the Pwned Passwords API cannot be reached or answers badly."""


@dataclass(frozen=True)
class BreachResult:
    """Outcome of a breach lookup. Contains no password material beyond the prefix."""

    pwned: bool
    count: int
    prefix: str
    suffixes_checked: int

    def to_dict(self) -> dict[str, Any]:
        """Serialise for JSON output."""
        return {
            "pwned": self.pwned,
            "count": self.count,
            "hash_prefix_sent": self.prefix,
            "candidate_suffixes_received": self.suffixes_checked,
            "source": "Have I Been Pwned - Pwned Passwords",
        }


def sha1_hex(password: str) -> str:
    """Return the upper-case SHA-1 hex digest of ``password`` (UTF-8).

    SHA-1 is used only because it is the format of the HIBP dataset; it is
    not used here for any security property.
    """
    return hashlib.sha1(password.encode("utf-8"), usedforsecurity=False).hexdigest().upper()


def split_hash(digest: str) -> tuple[str, str]:
    """Split a SHA-1 hex digest into the 5-char prefix (sent) and suffix (kept local)."""
    return digest[:PREFIX_LENGTH], digest[PREFIX_LENGTH:]


def fetch_range(prefix: str, timeout: float = DEFAULT_TIMEOUT) -> str:
    """Download the hash-suffix list for ``prefix`` from the Pwned Passwords API.

    Raises:
        ValueError: If ``prefix`` is not exactly 5 hex characters (a safety
            check that guarantees we never transmit more of the hash).
        BreachCheckError: On any network or HTTP error.
    """
    if len(prefix) != PREFIX_LENGTH or any(c not in "0123456789ABCDEF" for c in prefix):
        raise ValueError("prefix must be exactly 5 upper-case hex characters")
    request = urllib.request.Request(  # noqa: S310 - fixed https:// URL
        API_URL.format(prefix=prefix),
        headers={"User-Agent": USER_AGENT, "Add-Padding": "true"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            body: bytes = response.read()
    except urllib.error.HTTPError as exc:
        raise BreachCheckError(f"Pwned Passwords API returned HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        raise BreachCheckError(f"Could not reach the Pwned Passwords API: {reason}") from exc
    return body.decode("utf-8", errors="replace")


def parse_range(body: str) -> dict[str, int]:
    """Parse a range response (``SUFFIX:COUNT`` per line) into ``{suffix: count}``.

    Padding entries (count 0) and malformed lines are ignored.
    """
    results: dict[str, int] = {}
    for line in body.splitlines():
        suffix, sep, count = line.strip().partition(":")
        if not sep:
            continue
        try:
            value = int(count)
        except ValueError:
            continue
        if value > 0:
            results[suffix.upper()] = value
    return results


def check_pwned(
    password: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    retries: int = 2,
    backoff: float = 1.0,
    fetcher: Fetcher | None = None,
) -> BreachResult:
    """Check whether ``password`` appears in the Pwned Passwords corpus.

    Args:
        password: The password to check. Only its SHA-1 prefix is transmitted.
        timeout: Per-request timeout in seconds.
        retries: Extra attempts after a network failure.
        backoff: Base delay (seconds) between attempts; doubles each retry.
        fetcher: Optional replacement for :func:`fetch_range` (used in tests).

    Raises:
        ValueError: If ``password`` is empty.
        BreachCheckError: If the API cannot be reached after all retries.
    """
    if not password:
        raise ValueError("password must not be empty")
    fetch = fetcher or fetch_range
    prefix, suffix = split_hash(sha1_hex(password))

    last_error: BreachCheckError | None = None
    for attempt in range(retries + 1):
        try:
            body = fetch(prefix, timeout)
            break
        except BreachCheckError as exc:
            last_error = exc
            if attempt < retries:
                time.sleep(backoff * (2**attempt))
    else:
        raise last_error or BreachCheckError("breach check failed")

    hits = parse_range(body)
    count = hits.get(suffix, 0)
    return BreachResult(pwned=count > 0, count=count, prefix=prefix, suffixes_checked=len(hits))


__all__ = [
    "API_URL",
    "BreachCheckError",
    "BreachResult",
    "check_pwned",
    "fetch_range",
    "parse_range",
    "sha1_hex",
    "split_hash",
]
