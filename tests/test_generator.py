import math
import string

import pytest

from pwtool import generator
from pwtool.generator import (
    AMBIGUOUS,
    DEFAULT_SYMBOLS,
    generate_passphrase,
    generate_passphrases,
    generate_password,
    generate_passwords,
)
from pwtool.wordlists import passphrase_words


@pytest.mark.parametrize("length", [4, 12, 20, 64, 256])
def test_password_length_and_all_classes(length: int) -> None:
    pw = generate_password(length)
    assert len(pw) == length
    assert any(c in string.ascii_lowercase for c in pw)
    assert any(c in string.ascii_uppercase for c in pw)
    assert any(c in string.digits for c in pw)
    assert any(c in DEFAULT_SYMBOLS for c in pw)


def test_password_options_restrict_alphabet() -> None:
    for _ in range(50):
        pw = generate_password(32, upper=False, digits=False, symbols=False)
        assert set(pw) <= set(string.ascii_lowercase)


def test_exclude_ambiguous() -> None:
    for _ in range(50):
        assert not set(generate_password(64, exclude_ambiguous=True)) & AMBIGUOUS


def test_passwords_are_unique() -> None:
    assert len({generate_password(16) for _ in range(200)}) == 200


@pytest.mark.parametrize("length", [0, 3, 1025])
def test_invalid_length(length: int) -> None:
    with pytest.raises(ValueError, match="length"):
        generate_password(length)


def test_uses_secrets_module(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    real_choice = generator.secrets.choice

    def spy(seq):  # type: ignore[no-untyped-def]
        calls.append("choice")
        return real_choice(seq)

    monkeypatch.setattr(generator.secrets, "choice", spy)
    generate_password(10)
    assert len(calls) == 10


def test_passphrase_defaults() -> None:
    words = generate_passphrase().split("-")
    assert len(words) == 6
    assert set(words) <= set(passphrase_words())


def test_passphrase_options() -> None:
    phrase = generate_passphrase(4, separator=" ", capitalize=True, add_number=True)
    words = phrase.split(" ")
    assert len(words) == 4
    assert all(w[0].isupper() for w in words)
    assert sum(any(c.isdigit() for c in w) for w in words) == 1


def test_passphrase_custom_wordlist() -> None:
    assert generate_passphrase(3, wordlist=["a"]) == "a-a-a"
    with pytest.raises(ValueError, match="empty"):
        generate_passphrase(3, wordlist=[])


@pytest.mark.parametrize("words", [2, 65])
def test_invalid_word_count(words: int) -> None:
    with pytest.raises(ValueError, match="words"):
        generate_passphrase(words)


def test_generate_passwords_batch() -> None:
    batch = generate_passwords(5, 16, symbols=False)
    assert len(batch.values) == 5
    assert batch.details["alphabet_size"] == 62
    assert batch.entropy_bits == pytest.approx(16 * math.log2(62))
    data = batch.to_dict()
    assert data["mode"] == "password"
    assert data["count"] == 5


def test_generate_passphrases_batch() -> None:
    batch = generate_passphrases(2, 5, add_number=True)
    size = len(passphrase_words())
    assert batch.entropy_bits == pytest.approx(5 * math.log2(size) + math.log2(10) + math.log2(5))
    assert batch.to_dict()["wordlist_size"] == size


@pytest.mark.parametrize("count", [0, 1001])
def test_invalid_count(count: int) -> None:
    with pytest.raises(ValueError, match="count"):
        generate_passwords(count)


def test_too_short_for_selected_pools(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(generator, "MIN_LENGTH", 1)
    with pytest.raises(ValueError, match="at least 4"):
        generate_password(3)
