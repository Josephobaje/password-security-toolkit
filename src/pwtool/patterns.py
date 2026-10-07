"""Detection of predictable patterns inside passwords.

Each detector returns :class:`PatternMatch` objects describing *where* a
pattern was found and roughly how many bits of entropy an attacker needs to
guess that part of the password. The matched text itself is never stored, so
reports can be printed or serialised without leaking password fragments.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

MIN_DICTIONARY_TOKEN = 4
MAX_DICTIONARY_TOKEN = 24
MIN_KEYBOARD_RUN = 4
MIN_SEQUENCE_RUN = 3

#: Rows and common "walks" of a US QWERTY keyboard plus a numeric keypad.
KEYBOARD_PATTERNS: tuple[str, ...] = (
    "`1234567890-=",
    "qwertyuiop[]\\",
    "asdfghjkl;'",
    "zxcvbnm,./",
    "~!@#$%^&*()_+",
    "1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik,9ol.0p;/-['=]",
    "qazwsxedcrfvtgbyhnujmikolp",
    "zaqxswcdevfrbgtnhymjukilop",
    "7894561230",
    "1472583690",
)

#: Common "leetspeak" substitutions, mapped back to the letter they replace.
LEET_MAP: dict[str, str] = {
    "0": "o",
    "1": "i",
    "!": "i",
    "3": "e",
    "4": "a",
    "@": "a",
    "5": "s",
    "$": "s",
    "7": "t",
    "+": "t",
    "8": "b",
    "9": "g",
}

_YEAR_RE = re.compile(r"(?<!\d)(?:19|20)\d{2}(?!\d)")
_SEPARATED_DATE_RE = re.compile(r"(?<!\d)\d{1,2}([-/._])\d{1,2}\1(?:\d{4}|\d{2})(?!\d)")
_COMPACT_DATE_RE = re.compile(r"(?<!\d)\d{8}(?!\d)")
_REPEAT_RE = re.compile(r"(.+?)\1+", re.DOTALL)


@dataclass(frozen=True)
class PatternMatch:
    """A predictable pattern found in a password.

    Attributes:
        kind: Pattern family: ``dictionary``, ``keyboard``, ``sequence``,
            ``repeat`` or ``date``.
        start: Index of the first character covered by the pattern.
        end: Index one past the last character covered (exclusive).
        bits: Estimated entropy (log2 of guesses) needed to guess this part.
        description: Human-readable explanation that never contains the
            matched characters themselves.
    """

    kind: str
    start: int
    end: int
    bits: float
    description: str

    @property
    def length(self) -> int:
        """Number of password characters covered by the match."""
        return self.end - self.start

    def overlaps(self, other: PatternMatch) -> bool:
        """Return ``True`` if this match shares any character with ``other``."""
        return self.start < other.end and other.start < self.end

    def to_dict(self) -> dict[str, Any]:
        """Serialise the match (without the matched text) for JSON output."""
        return {
            "kind": self.kind,
            "start": self.start,
            "end": self.end,
            "length": self.length,
            "bits": round(self.bits, 2),
            "description": self.description,
        }


def deleet(text: str) -> str:
    """Undo common leetspeak substitutions (``p@ssw0rd`` -> ``password``)."""
    return "".join(LEET_MAP.get(ch, ch) for ch in text.lower())


def _case_variation_bits(token: str) -> float:
    """Extra guesses needed to cover the capitalisation used in ``token``."""
    letters = [c for c in token if c.isalpha()]
    if not letters or all(c.islower() for c in letters):
        return 0.0
    if all(c.isupper() for c in letters) or (
        letters[0].isupper() and all(c.islower() for c in letters[1:])
    ):
        return 1.0
    upper = sum(1 for c in letters if c.isupper())
    return math.log2(math.comb(len(letters), upper) + 1)


def _lookup(
    candidate: str, ranked_passwords: Mapping[str, int], words: frozenset[str]
) -> tuple[float, str] | None:
    """Return ``(bits, source)`` if ``candidate`` is a known password or word."""
    if candidate in ranked_passwords:
        return math.log2(ranked_passwords[candidate]), "common password"
    if candidate in words:
        return math.log2(len(words)), "dictionary word"
    return None


def find_dictionary(
    password: str,
    ranked_passwords: Mapping[str, int],
    words: frozenset[str] = frozenset(),
) -> list[PatternMatch]:
    """Find common passwords and dictionary words embedded in ``password``.

    Matching is case-insensitive and also tries the de-leeted form, so
    ``P@ssw0rd`` is recognised as ``password``.

    Args:
        password: The password to inspect.
        ranked_passwords: Mapping of common password -> popularity rank.
        words: Additional dictionary words (each costs ``log2(len(words))`` bits).
    """
    lowered = password.lower()
    leeted = deleet(password)
    matches: list[PatternMatch] = []
    n = len(password)
    for i in range(n):
        for j in range(i + MIN_DICTIONARY_TOKEN, min(n, i + MAX_DICTIONARY_TOKEN) + 1):
            options: list[tuple[float, str, int]] = []
            plain = _lookup(lowered[i:j], ranked_passwords, words)
            if plain is not None:
                options.append((plain[0], plain[1], 0))
            if leeted[i:j] != lowered[i:j]:
                hit = _lookup(leeted[i:j], ranked_passwords, words)
                if hit is not None:
                    subs = sum(1 for a, b in zip(lowered[i:j], leeted[i:j], strict=True) if a != b)
                    options.append((hit[0] + subs, hit[1], subs))
            if not options:
                continue
            bits, source, subs = min(options)
            detail = " with leetspeak substitutions" if subs else ""
            matches.append(
                PatternMatch(
                    kind="dictionary",
                    start=i,
                    end=j,
                    bits=bits + _case_variation_bits(password[i:j]),
                    description=f"{source.capitalize()}{detail}",
                )
            )
    return matches


def find_keyboard(password: str) -> list[PatternMatch]:
    """Find keyboard walks such as ``qwerty``, ``asdf`` or ``1qaz2wsx``."""
    lowered = password.lower()
    rows = KEYBOARD_PATTERNS + tuple(row[::-1] for row in KEYBOARD_PATTERNS)
    keys = len(set("".join(KEYBOARD_PATTERNS)))
    matches: list[PatternMatch] = []
    i = 0
    n = len(lowered)
    while i < n:
        j = i + 1
        while j < n and any(lowered[i : j + 1] in row for row in rows):
            j += 1
        if j - i >= MIN_KEYBOARD_RUN and any(lowered[i:j] in row for row in rows):
            bits = math.log2(keys * 2) + math.log2(j - i) + _case_variation_bits(password[i:j])
            matches.append(
                PatternMatch("keyboard", i, j, bits, f"Keyboard pattern ({j - i} adjacent keys)")
            )
            i = j
        else:
            i += 1
    return matches


def _char_group(ch: str) -> str | None:
    if "a" <= ch <= "z":
        return "lower"
    if "A" <= ch <= "Z":
        return "upper"
    if ch.isdigit():
        return "digit"
    return None


def find_sequences(password: str) -> list[PatternMatch]:
    """Find runs like ``abc``, ``4567`` or ``zyx`` (ascending or descending)."""
    matches: list[PatternMatch] = []
    n = len(password)
    i = 0
    while i < n - 1:
        group = _char_group(password[i])
        delta = ord(password[i + 1]) - ord(password[i])
        if group is None or delta not in (1, -1) or _char_group(password[i + 1]) != group:
            i += 1
            continue
        j = i + 1
        while (
            j < n
            and _char_group(password[j]) == group
            and ord(password[j]) - ord(password[j - 1]) == delta
        ):
            j += 1
        if j - i >= MIN_SEQUENCE_RUN:
            alphabet = 10 if group == "digit" else 26
            bits = math.log2(alphabet) + math.log2(j - i) + (1.0 if delta < 0 else 0.0)
            direction = "descending" if delta < 0 else "ascending"
            matches.append(
                PatternMatch("sequence", i, j, bits, f"{direction.capitalize()} sequence")
            )
            i = j
        else:
            i += 1
    return matches


def find_repeats(password: str, bits_per_char: float) -> list[PatternMatch]:
    """Find repeated characters (``aaaa``) and repeated chunks (``abcabc``).

    Args:
        password: The password to inspect.
        bits_per_char: Entropy of a single character given the password's charset.
    """
    matches: list[PatternMatch] = []
    for m in _REPEAT_RE.finditer(password):
        base = m.group(1)
        count = len(m.group(0)) // len(base)
        if len(m.group(0)) < 3 or (len(base) == 1 and count < 3):
            continue
        bits = len(base) * bits_per_char + math.log2(count)
        label = "Repeated character" if len(base) == 1 else "Repeated chunk"
        matches.append(
            PatternMatch("repeat", m.start(), m.end(), bits, f"{label} ({len(base)} x {count})")
        )
    return matches


def _valid_compact_date(digits: str) -> bool:
    """Return ``True`` for plausible DDMMYYYY, MMDDYYYY or YYYYMMDD strings."""

    def ok(day: int, month: int, year: int) -> bool:
        return 1 <= day <= 31 and 1 <= month <= 12 and 1900 <= year <= 2099

    a, b, c = int(digits[:2]), int(digits[2:4]), int(digits[4:])
    y, m, d = int(digits[:4]), int(digits[4:6]), int(digits[6:])
    return ok(a, b, c) or ok(b, a, c) or ok(d, m, y)


def find_dates(password: str) -> list[PatternMatch]:
    """Find years (``1990``) and dates (``01/02/1990``, ``19900102``)."""
    matches: list[PatternMatch] = []
    year_bits = math.log2(200)
    date_bits = math.log2(366 * 200) + 1
    for m in _SEPARATED_DATE_RE.finditer(password):
        matches.append(PatternMatch("date", m.start(), m.end(), date_bits, "Calendar date"))
    for m in _COMPACT_DATE_RE.finditer(password):
        if _valid_compact_date(m.group(0)):
            matches.append(PatternMatch("date", m.start(), m.end(), date_bits, "Calendar date"))
    for m in _YEAR_RE.finditer(password):
        matches.append(PatternMatch("date", m.start(), m.end(), year_bits, "Looks like a year"))
    return matches


def select_matches(matches: Iterable[PatternMatch], bits_per_char: float) -> list[PatternMatch]:
    """Pick a non-overlapping set of matches that explains the password cheaply.

    Matches are chosen greedily by how many bits they *save* compared to
    treating the same characters as random, which favours long, cheap matches.
    """
    ranked = sorted(
        matches,
        key=lambda m: (m.length * bits_per_char - m.bits, m.length),
        reverse=True,
    )
    chosen: list[PatternMatch] = []
    for match in ranked:
        if match.length * bits_per_char - match.bits <= 0:
            continue
        if not any(match.overlaps(c) for c in chosen):
            chosen.append(match)
    return sorted(chosen, key=lambda m: m.start)
