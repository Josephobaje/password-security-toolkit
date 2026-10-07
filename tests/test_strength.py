import json

import pytest

from pwtool.strength import (
    SCORE_LABELS,
    CharacterClasses,
    analyze,
    entropy_to_score,
    estimate_crack_times,
    format_duration,
)


@pytest.mark.parametrize(
    "pw", ["password", "123456", "qwerty", "P@ssw0rd", "iloveyou", "Dragon", "letmein"]
)
def test_common_passwords_score_zero(pw: str) -> None:
    report = analyze(pw)
    assert report.score == 0
    assert report.is_common
    assert report.common_rank is not None
    assert any("most common" in w for w in report.warnings)


@pytest.mark.parametrize(
    ("pw", "kind"),
    [
        ("qwertyuiop!!Zx", "keyboard"),
        ("abcdefgh#Q9", "sequence"),
        ("zzzzzzzzzzzz", "repeat"),
        ("Melinda#1987", "date"),
        ("Sunshine#Rocks", "dictionary"),
    ],
)
def test_patterns_are_reported_and_penalised(pw: str, kind: str) -> None:
    report = analyze(pw)
    assert kind in {p.kind for p in report.patterns}
    assert report.entropy < report.charset_entropy
    assert report.warnings


@pytest.mark.parametrize("pw", ["x7#Kp9!vQ2mZ", "kV9#pL2!qX7&wM4$", "Gq8$zT1!nW5^rB3*"])
def test_random_passwords_are_very_strong(pw: str) -> None:
    report = analyze(pw)
    assert report.score == 4
    assert report.label == "Very strong"
    assert not report.patterns
    assert not report.warnings


def test_random_passphrase_is_strong() -> None:
    report = analyze("travesty-footless-mantis-renewed-unlikable-unnamed")
    assert report.score >= 3
    assert {p.kind for p in report.patterns} == {"dictionary"}


def test_short_passwords_are_capped() -> None:
    report = analyze("k#9Lq!2")
    assert report.score <= 1
    assert any("Too short" in w for w in report.warnings)
    assert any("at least 12" in s for s in report.suggestions)


def test_missing_classes_suggestion() -> None:
    report = analyze("lowercaseonlyxq")
    assert any("uppercase letters" in s and "digits" in s for s in report.suggestions)


def test_weak_password_suggests_generator() -> None:
    assert any("pwtool generate" in s for s in analyze("Summer2024!").suggestions)


def test_empty_password_rejected() -> None:
    with pytest.raises(ValueError, match="empty"):
        analyze("")


def test_report_never_contains_the_password() -> None:
    secret = "MyS3cretDragon1990!"
    report = analyze(secret)
    blob = json.dumps(report.to_dict())
    for fragment in ("MyS3cret", "Dragon", "dragon", "1990", secret):
        assert fragment not in blob


def test_to_dict_shape() -> None:
    data = analyze("Tr0ub4dor&3").to_dict()
    assert data["max_score"] == 4
    assert data["label"] == SCORE_LABELS[data["score"]]
    assert set(data["character_classes"]) == {
        "lowercase",
        "uppercase",
        "digits",
        "symbols",
        "other",
    }
    assert set(data["crack_time_display"]) == set(data["crack_time_seconds"])


def test_character_classes_unicode() -> None:
    classes = CharacterClasses.of("añb")
    assert classes.other
    assert classes.lowercase
    assert classes.count == 2
    assert classes.pool_size == 126


@pytest.mark.parametrize(
    ("bits", "score"), [(0, 0), (27.9, 0), (28, 1), (36, 2), (59.9, 2), (60, 3), (75, 4), (200, 4)]
)
def test_entropy_to_score(bits: float, score: int) -> None:
    assert entropy_to_score(bits) == score


def test_crack_times_scale_with_entropy() -> None:
    weak, strong = estimate_crack_times(20), estimate_crack_times(60)
    assert set(weak) == {
        "online_throttled",
        "online_unthrottled",
        "offline_slow_hash",
        "offline_fast_hash",
    }
    assert all(strong[k] > weak[k] for k in weak)
    assert estimate_crack_times(0)["offline_fast_hash"] == pytest.approx(1e-10)


@pytest.mark.parametrize(
    ("seconds", "text"),
    [
        (0.5, "instant"),
        (1, "1 second"),
        (59, "59 seconds"),
        (60, "1 minute"),
        (7200, "2 hours"),
        (86400 * 3, "3 days"),
        (86400 * 61, "2 months"),
        (86400 * 365.25 * 5, "5 years"),
        (86400 * 365.25 * 300, "3 centuries"),
        (1e30, "longer than 100,000 years"),
    ],
)
def test_format_duration(seconds: float, text: str) -> None:
    assert format_duration(seconds) == text
