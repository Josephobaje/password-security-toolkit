"""Cryptographically secure password and passphrase generation.

All randomness comes from :mod:`secrets` (the operating system's CSPRNG).
:mod:`random` is never used.
"""

from __future__ import annotations

import math
import secrets
import string
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from pwtool.wordlists import passphrase_words

DEFAULT_LENGTH = 20
MIN_LENGTH = 4
MAX_LENGTH = 1024
DEFAULT_WORDS = 6
MIN_WORDS = 3
MAX_WORDS = 64

#: Symbols that are safe to type on most keyboards and in most forms.
DEFAULT_SYMBOLS = "!#$%&()*+,-./:;<=>?@[]^_{|}~"
#: Characters that are easily confused when read or typed.
AMBIGUOUS = set("Il1O0o|`'\"")


@dataclass(frozen=True)
class GeneratedSecrets:
    """A batch of generated passwords or passphrases plus metadata."""

    mode: str
    values: tuple[str, ...]
    entropy_bits: float
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialise for JSON output."""
        return {
            "mode": self.mode,
            "count": len(self.values),
            "entropy_bits": round(self.entropy_bits, 2),
            **self.details,
            "values": list(self.values),
        }


def _filter(chars: str, exclude_ambiguous: bool) -> str:
    return "".join(c for c in chars if not (exclude_ambiguous and c in AMBIGUOUS))


def build_pools(
    *,
    upper: bool = True,
    digits: bool = True,
    symbols: bool = True,
    exclude_ambiguous: bool = False,
) -> list[str]:
    """Return the character pools to draw from (lower-case is always included)."""
    pools = [string.ascii_lowercase]
    if upper:
        pools.append(string.ascii_uppercase)
    if digits:
        pools.append(string.digits)
    if symbols:
        pools.append(DEFAULT_SYMBOLS)
    return [_filter(p, exclude_ambiguous) for p in pools]


def password_entropy(length: int, alphabet_size: int) -> float:
    """Entropy in bits of a uniformly random password."""
    return length * math.log2(alphabet_size)


def generate_password(
    length: int = DEFAULT_LENGTH,
    *,
    upper: bool = True,
    digits: bool = True,
    symbols: bool = True,
    exclude_ambiguous: bool = False,
) -> str:
    """Generate a random password using the OS CSPRNG.

    The password is guaranteed to contain at least one character from every
    enabled pool, and character positions are shuffled with
    :class:`secrets.SystemRandom`.

    Raises:
        ValueError: If ``length`` is out of range or too short for the pools.
    """
    pools = build_pools(
        upper=upper, digits=digits, symbols=symbols, exclude_ambiguous=exclude_ambiguous
    )
    if not MIN_LENGTH <= length <= MAX_LENGTH:
        raise ValueError(f"length must be between {MIN_LENGTH} and {MAX_LENGTH}")
    if length < len(pools):
        raise ValueError(f"length must be at least {len(pools)} for the selected options")
    alphabet = "".join(pools)
    chars = [secrets.choice(pool) for pool in pools]
    chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def generate_passphrase(
    words: int = DEFAULT_WORDS,
    *,
    separator: str = "-",
    capitalize: bool = False,
    add_number: bool = False,
    wordlist: Sequence[str] | None = None,
) -> str:
    """Generate a Diceware-style passphrase from the bundled EFF wordlist.

    Args:
        words: Number of words to draw.
        separator: String placed between words.
        capitalize: Capitalise the first letter of each word.
        add_number: Append a random digit to one random word.
        wordlist: Alternative wordlist (defaults to the bundled EFF list).

    Raises:
        ValueError: If ``words`` is out of range or the wordlist is empty.
    """
    if not MIN_WORDS <= words <= MAX_WORDS:
        raise ValueError(f"words must be between {MIN_WORDS} and {MAX_WORDS}")
    pool = wordlist if wordlist is not None else passphrase_words()
    if not pool:
        raise ValueError("wordlist must not be empty")
    chosen = [secrets.choice(pool) for _ in range(words)]
    if capitalize:
        chosen = [w[:1].upper() + w[1:] for w in chosen]
    if add_number:
        index = secrets.randbelow(len(chosen))
        chosen[index] = f"{chosen[index]}{secrets.randbelow(10)}"
    return separator.join(chosen)


def passphrase_entropy(words: int, wordlist_size: int, add_number: bool = False) -> float:
    """Entropy in bits of a passphrase of ``words`` uniformly chosen words."""
    bits = words * math.log2(wordlist_size)
    if add_number:
        bits += math.log2(10) + math.log2(words)
    return bits


def generate_passwords(
    count: int = 1,
    length: int = DEFAULT_LENGTH,
    *,
    upper: bool = True,
    digits: bool = True,
    symbols: bool = True,
    exclude_ambiguous: bool = False,
) -> GeneratedSecrets:
    """Generate ``count`` passwords and report their entropy."""
    _check_count(count)
    values = tuple(
        generate_password(
            length,
            upper=upper,
            digits=digits,
            symbols=symbols,
            exclude_ambiguous=exclude_ambiguous,
        )
        for _ in range(count)
    )
    alphabet = len(
        "".join(
            build_pools(
                upper=upper, digits=digits, symbols=symbols, exclude_ambiguous=exclude_ambiguous
            )
        )
    )
    return GeneratedSecrets(
        mode="password",
        values=values,
        entropy_bits=password_entropy(length, alphabet),
        details={"length": length, "alphabet_size": alphabet},
    )


def generate_passphrases(
    count: int = 1,
    words: int = DEFAULT_WORDS,
    *,
    separator: str = "-",
    capitalize: bool = False,
    add_number: bool = False,
) -> GeneratedSecrets:
    """Generate ``count`` passphrases and report their entropy."""
    _check_count(count)
    values = tuple(
        generate_passphrase(
            words, separator=separator, capitalize=capitalize, add_number=add_number
        )
        for _ in range(count)
    )
    size = len(passphrase_words())
    return GeneratedSecrets(
        mode="passphrase",
        values=values,
        entropy_bits=passphrase_entropy(words, size, add_number),
        details={"words": words, "wordlist_size": size, "separator": separator},
    )


def _check_count(count: int) -> None:
    if not 1 <= count <= 1000:
        raise ValueError("count must be between 1 and 1000")
