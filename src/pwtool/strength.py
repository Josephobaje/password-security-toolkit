"""Password strength analysis.

The analyser combines three ideas:

1. **Charset entropy** - ``length x log2(alphabet size)``, the upper bound for a
   truly random password built from the same character classes.
2. **Pattern discounting** - parts of the password that match predictable
   patterns (common passwords, dictionary words, keyboard walks, sequences,
   repeats, dates) are charged only the few bits an attacker needs to guess
   them, similar in spirit to Dropbox's *zxcvbn*.
3. **Common-password lookup** - an exact match against a bundled list of the
   10,000 most common passwords (including leetspeak variants) is always
   scored 0.

The result is mapped to a 0-4 score with actionable feedback.
"""

from __future__ import annotations

import math
import string
from dataclasses import dataclass, field
from typing import Any

from pwtool import patterns
from pwtool.wordlists import common_passwords, dictionary_words

SCORE_LABELS: tuple[str, ...] = ("Very weak", "Weak", "Fair", "Strong", "Very strong")

#: Entropy (bits) thresholds for scores 1, 2, 3 and 4.
SCORE_THRESHOLDS: tuple[float, ...] = (28.0, 36.0, 60.0, 75.0)

MIN_RECOMMENDED_LENGTH = 12
MIN_ACCEPTABLE_LENGTH = 8

#: Attack scenarios used for crack-time estimates (guesses per second).
ATTACK_SCENARIOS: dict[str, tuple[str, float]] = {
    "online_throttled": ("Online, rate-limited (100/hour)", 100 / 3600),
    "online_unthrottled": ("Online, unthrottled (10/s)", 10.0),
    "offline_slow_hash": ("Offline, slow hash - bcrypt (10k/s)", 1e4),
    "offline_fast_hash": ("Offline, fast hash - MD5 on GPUs (10B/s)", 1e10),
}

SYMBOLS = set(string.punctuation + " ")

_PATTERN_ADVICE: dict[str, tuple[str, str]] = {
    "dictionary": (
        "Contains common words or passwords that appear in attacker wordlists.",
        "Avoid dictionary words and well-known passwords, even with l33t substitutions.",
    ),
    "keyboard": (
        "Contains a keyboard pattern (like 'qwerty' or 'asdf').",
        "Avoid keyboard walks - they are among the first things crackers try.",
    ),
    "sequence": (
        "Contains an easy sequence (like 'abc' or '1234').",
        "Avoid alphabetical or numerical sequences.",
    ),
    "repeat": (
        "Contains repeated characters or chunks.",
        "Avoid repeating characters or chunks like 'aaa' or 'abcabc'.",
    ),
    "date": (
        "Contains a year or date.",
        "Avoid years and dates, especially ones associated with you.",
    ),
}


@dataclass(frozen=True)
class CharacterClasses:
    """Which character classes are present in a password."""

    lowercase: bool
    uppercase: bool
    digits: bool
    symbols: bool
    other: bool

    @classmethod
    def of(cls, password: str) -> CharacterClasses:
        """Detect the character classes used by ``password``."""
        return cls(
            lowercase=any(c in string.ascii_lowercase for c in password),
            uppercase=any(c in string.ascii_uppercase for c in password),
            digits=any(c in string.digits for c in password),
            symbols=any(c in SYMBOLS for c in password),
            other=any(
                c not in string.ascii_letters and c not in string.digits and c not in SYMBOLS
                for c in password
            ),
        )

    @property
    def count(self) -> int:
        """Number of distinct classes present."""
        return sum((self.lowercase, self.uppercase, self.digits, self.symbols, self.other))

    @property
    def pool_size(self) -> int:
        """Size of the alphabet an attacker would have to brute-force."""
        size = 0
        size += 26 if self.lowercase else 0
        size += 26 if self.uppercase else 0
        size += 10 if self.digits else 0
        size += len(SYMBOLS) if self.symbols else 0
        size += 100 if self.other else 0
        return size

    def to_dict(self) -> dict[str, bool]:
        """Serialise for JSON output."""
        return {
            "lowercase": self.lowercase,
            "uppercase": self.uppercase,
            "digits": self.digits,
            "symbols": self.symbols,
            "other": self.other,
        }


@dataclass(frozen=True)
class StrengthReport:
    """Result of :func:`analyze`. Never contains the password itself."""

    length: int
    classes: CharacterClasses
    charset_entropy: float
    entropy: float
    score: int
    is_common: bool
    common_rank: int | None
    patterns: tuple[patterns.PatternMatch, ...]
    warnings: tuple[str, ...]
    suggestions: tuple[str, ...]
    crack_times: dict[str, float] = field(default_factory=dict)

    @property
    def label(self) -> str:
        """Human-readable label for :attr:`score`."""
        return SCORE_LABELS[self.score]

    def to_dict(self) -> dict[str, Any]:
        """Serialise the report for JSON output."""
        return {
            "score": self.score,
            "max_score": len(SCORE_LABELS) - 1,
            "label": self.label,
            "length": self.length,
            "character_classes": self.classes.to_dict(),
            "charset_size": self.classes.pool_size,
            "charset_entropy_bits": round(self.charset_entropy, 2),
            "estimated_entropy_bits": round(self.entropy, 2),
            "is_common_password": self.is_common,
            "common_password_rank": self.common_rank,
            "patterns": [p.to_dict() for p in self.patterns],
            "crack_time_seconds": dict(self.crack_times),
            "crack_time_display": {k: format_duration(v) for k, v in self.crack_times.items()},
            "warnings": list(self.warnings),
            "suggestions": list(self.suggestions),
        }


def entropy_to_score(bits: float) -> int:
    """Map an entropy estimate (bits) to a 0-4 score."""
    return sum(1 for threshold in SCORE_THRESHOLDS if bits >= threshold)


def estimate_crack_times(bits: float) -> dict[str, float]:
    """Average seconds to guess a secret with ``bits`` of entropy per scenario.

    On average an attacker searches half the space, i.e. ``2 ** (bits - 1)`` guesses.
    """
    guesses = 2 ** max(bits - 1, 0.0)
    return {key: guesses / rate for key, (_, rate) in ATTACK_SCENARIOS.items()}


def format_duration(seconds: float) -> str:
    """Render a duration in seconds as a short human-friendly string."""
    if seconds < 1:
        return "instant"
    units = (
        ("century", "centuries", 100 * 365.25 * 86400),
        ("year", "years", 365.25 * 86400),
        ("month", "months", 30.44 * 86400),
        ("day", "days", 86400),
        ("hour", "hours", 3600),
        ("minute", "minutes", 60),
        ("second", "seconds", 1),
    )
    for singular, plural, size in units:
        if seconds >= size:
            value = seconds / size
            if singular == "century" and value >= 1000:
                return "longer than 100,000 years"
            rounded = round(value)
            return f"{rounded} {singular if rounded == 1 else plural}"
    return "instant"  # pragma: no cover - unreachable, seconds >= 1 here


def _common_rank(password: str) -> int | None:
    ranked = common_passwords()
    candidates = (password.lower(), patterns.deleet(password))
    ranks = [ranked[c] for c in candidates if c in ranked]
    return min(ranks) if ranks else None


def _build_feedback(
    length: int,
    classes: CharacterClasses,
    is_common: bool,
    matches: tuple[patterns.PatternMatch, ...],
    score: int,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    warnings: list[str] = []
    suggestions: list[str] = []

    if is_common:
        warnings.append("This is one of the most common passwords - it would be guessed instantly.")
        suggestions.append("Never use a password that appears on common-password lists.")
    if length < MIN_ACCEPTABLE_LENGTH:
        warnings.append(f"Too short: {length} characters (minimum {MIN_ACCEPTABLE_LENGTH}).")
    if length < MIN_RECOMMENDED_LENGTH:
        suggestions.append(
            f"Use at least {MIN_RECOMMENDED_LENGTH}-16 characters; length beats complexity."
        )
    seen_kinds: list[str] = []
    for match in matches:
        if match.kind not in seen_kinds:
            seen_kinds.append(match.kind)
    for kind in seen_kinds:
        if is_common and kind == "dictionary":
            continue
        warning, suggestion = _PATTERN_ADVICE[kind]
        warnings.append(warning)
        suggestions.append(suggestion)
    if classes.count < 3 and length < 20:
        missing = [
            name
            for name, present in (
                ("uppercase letters", classes.uppercase),
                ("lowercase letters", classes.lowercase),
                ("digits", classes.digits),
                ("symbols", classes.symbols),
            )
            if not present
        ]
        suggestions.append("Mix more character types - consider adding " + ", ".join(missing) + ".")
    if score < 3:
        suggestions.append("Let the computer choose: try `pwtool generate --passphrase`.")
        suggestions.append("Store passwords in a password manager and enable MFA where possible.")
    return tuple(warnings), tuple(suggestions)


def analyze(password: str) -> StrengthReport:
    """Analyse ``password`` and return a :class:`StrengthReport`.

    The password is processed entirely in memory; it is never logged, stored,
    or included in the returned report.

    Raises:
        ValueError: If ``password`` is empty.
    """
    if not password:
        raise ValueError("password must not be empty")

    length = len(password)
    classes = CharacterClasses.of(password)
    bits_per_char = math.log2(classes.pool_size)
    charset_entropy = length * bits_per_char

    candidates: list[patterns.PatternMatch] = []
    candidates += patterns.find_dictionary(password, common_passwords(), dictionary_words())
    candidates += patterns.find_keyboard(password)
    candidates += patterns.find_sequences(password)
    candidates += patterns.find_repeats(password, bits_per_char)
    candidates += patterns.find_dates(password)
    chosen = tuple(patterns.select_matches(candidates, bits_per_char))

    covered = sum(m.length for m in chosen)
    entropy = sum(m.bits for m in chosen) + (length - covered) * bits_per_char
    if len(chosen) > 1:
        # An attacker must also guess how the pieces are combined.
        entropy += math.log2(len(chosen))

    rank = _common_rank(password)
    is_common = rank is not None
    if rank is not None:
        entropy = min(entropy, math.log2(rank + 1))

    entropy = min(entropy, charset_entropy)
    score = entropy_to_score(entropy)
    if is_common:
        score = 0
    elif length < MIN_ACCEPTABLE_LENGTH:
        score = min(score, 1)

    warnings, suggestions = _build_feedback(length, classes, is_common, chosen, score)
    return StrengthReport(
        length=length,
        classes=classes,
        charset_entropy=charset_entropy,
        entropy=entropy,
        score=score,
        is_common=is_common,
        common_rank=rank,
        patterns=chosen,
        warnings=warnings,
        suggestions=suggestions,
        crack_times=estimate_crack_times(entropy),
    )
