"""Loading of the bundled data files (common passwords and passphrase wordlist)."""

from __future__ import annotations

from functools import lru_cache
from importlib.resources import files

COMMON_PASSWORDS_FILE = "common_passwords.txt"
PASSPHRASE_WORDLIST_FILE = "eff_large_wordlist.txt"  # noqa: S105 - a filename


def _read_lines(filename: str) -> list[str]:
    """Return the non-empty, stripped lines of a bundled data file."""
    text = (files("pwtool") / "data" / filename).read_text(encoding="utf-8")
    return [line.strip() for line in text.splitlines() if line.strip()]


@lru_cache(maxsize=1)
def common_passwords() -> dict[str, int]:
    """Return the bundled common-password list as ``{password: rank}``.

    Rank 1 is the most common password. Entries are lower-cased; if a
    lower-cased entry appears more than once, its best (lowest) rank is kept.
    """
    ranked: dict[str, int] = {}
    for rank, entry in enumerate(_read_lines(COMMON_PASSWORDS_FILE), start=1):
        ranked.setdefault(entry.lower(), rank)
    return ranked


@lru_cache(maxsize=1)
def passphrase_words() -> tuple[str, ...]:
    """Return the bundled passphrase wordlist (EFF large wordlist, letters only)."""
    return tuple(dict.fromkeys(_read_lines(PASSPHRASE_WORDLIST_FILE)))


@lru_cache(maxsize=1)
def dictionary_words() -> frozenset[str]:
    """Return the passphrase wordlist as a set for fast membership tests."""
    return frozenset(passphrase_words())
