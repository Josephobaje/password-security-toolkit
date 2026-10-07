import math
from typing import ClassVar

import pytest

from pwtool import patterns
from pwtool.patterns import PatternMatch


def kinds(matches: list[PatternMatch]) -> list[str]:
    return [m.kind for m in matches]


class TestDeleet:
    def test_reverses_common_substitutions(self) -> None:
        assert patterns.deleet("P@$$w0rd") == "password"

    def test_leaves_plain_text_untouched(self) -> None:
        assert patterns.deleet("hello") == "hello"


class TestKeyboard:
    @pytest.mark.parametrize("pw", ["qwerty", "ASDFGH", "zxcvbnm", "1qaz2wsx", "poiuy", "7894"])
    def test_detects_keyboard_walks(self, pw: str) -> None:
        found = patterns.find_keyboard(pw)
        assert found
        assert found[0].start == 0
        assert found[0].end == len(pw)

    def test_detects_embedded_walk(self) -> None:
        found = patterns.find_keyboard("Xyqwerty!!")
        assert [(m.start, m.end) for m in found] == [(2, 8)]

    def test_ignores_short_or_random_runs(self) -> None:
        assert patterns.find_keyboard("qwe") == []
        assert patterns.find_keyboard("k3%Lp") == []

    def test_uppercase_costs_an_extra_bit(self) -> None:
        lower = patterns.find_keyboard("qwerty")[0]
        upper = patterns.find_keyboard("Qwerty")[0]
        assert upper.bits == pytest.approx(lower.bits + 1)


class TestSequences:
    @pytest.mark.parametrize(
        ("pw", "description"),
        [("abcd", "Ascending"), ("4321", "Descending"), ("XYZ", "Ascending")],
    )
    def test_detects_sequences(self, pw: str, description: str) -> None:
        (match,) = patterns.find_sequences(pw)
        assert match.length == len(pw)
        assert match.description.startswith(description)

    def test_descending_is_slightly_harder(self) -> None:
        (asc,) = patterns.find_sequences("123")
        (desc,) = patterns.find_sequences("321")
        assert desc.bits == pytest.approx(asc.bits + 1)

    def test_does_not_cross_character_groups(self) -> None:
        assert patterns.find_sequences("yzA") == []
        assert patterns.find_sequences("89:") == []

    def test_ignores_two_char_runs_and_mixed_steps(self) -> None:
        assert patterns.find_sequences("ab!") == []
        assert patterns.find_sequences("acegx") == []

    def test_finds_multiple_runs(self) -> None:
        found = patterns.find_sequences("abc!987")
        assert [(m.start, m.end) for m in found] == [(0, 3), (4, 7)]


class TestRepeats:
    def test_repeated_character(self) -> None:
        (match,) = patterns.find_repeats("xaaaay", bits_per_char=5.0)
        assert (match.start, match.end) == (1, 5)
        assert match.bits == pytest.approx(5.0 + math.log2(4))
        assert match.description.startswith("Repeated character")

    def test_repeated_chunk(self) -> None:
        (match,) = patterns.find_repeats("abcabcabc", bits_per_char=4.7)
        assert match.length == 9
        assert match.description.startswith("Repeated chunk")

    def test_double_characters_are_ignored(self) -> None:
        assert patterns.find_repeats("aabbcc", bits_per_char=4.7) == []


class TestDates:
    def test_year(self) -> None:
        (match,) = patterns.find_dates("summer1999")
        assert (match.start, match.end) == (6, 10)
        assert match.description == "Looks like a year"

    def test_year_inside_longer_number_is_ignored(self) -> None:
        assert patterns.find_dates("319991") == []

    @pytest.mark.parametrize("pw", ["01/02/1990", "1-2-99", "25.12.2020"])
    def test_separated_dates(self, pw: str) -> None:
        assert "Calendar date" in [m.description for m in patterns.find_dates(pw)]

    @pytest.mark.parametrize("pw", ["25121990", "12251990", "19901225"])
    def test_compact_dates(self, pw: str) -> None:
        assert "Calendar date" in [m.description for m in patterns.find_dates(pw)]

    def test_invalid_compact_date(self) -> None:
        assert patterns.find_dates("99999999") == []


class TestDictionary:
    RANKED: ClassVar[dict[str, int]] = {"password": 1, "dragon": 50, "monkey": 20}
    WORDS = frozenset({"horse", "staple", "battery"})

    def test_common_password_rank_drives_bits(self) -> None:
        found = patterns.find_dictionary("xxdragonxx", self.RANKED)
        (match,) = [m for m in found if m.length == 6]
        assert match.bits == pytest.approx(math.log2(50))
        assert match.description == "Common password"

    def test_dictionary_word(self) -> None:
        found = patterns.find_dictionary("horse", {}, self.WORDS)
        assert found[0].bits == pytest.approx(math.log2(3))
        assert found[0].description == "Dictionary word"

    def test_leetspeak_variant_is_found_and_penalised(self) -> None:
        found = patterns.find_dictionary("P@ssw0rd", self.RANKED)
        (match,) = found
        assert "leetspeak" in match.description
        # rank 1 => 0 bits, +2 substitutions, +1 for capitalised first letter
        assert match.bits == pytest.approx(3.0)

    def test_mixed_case_costs_more_than_capitalised(self) -> None:
        capital = patterns.find_dictionary("Monkey", self.RANKED)[0]
        mixed = patterns.find_dictionary("mOnKeY", self.RANKED)[0]
        assert mixed.bits > capital.bits

    def test_no_match(self) -> None:
        assert patterns.find_dictionary("zq7#", self.RANKED, self.WORDS) == []


class TestSelection:
    def test_prefers_long_cheap_matches_without_overlap(self) -> None:
        long = PatternMatch("dictionary", 0, 8, 1.0, "long")
        short = PatternMatch("dictionary", 4, 8, 1.0, "short")
        other = PatternMatch("date", 8, 12, 7.6, "year")
        chosen = patterns.select_matches([short, other, long], bits_per_char=6.0)
        assert chosen == [long, other]

    def test_drops_matches_that_do_not_save_bits(self) -> None:
        costly = PatternMatch("sequence", 0, 3, 50.0, "costly")
        assert patterns.select_matches([costly], bits_per_char=4.0) == []

    def test_overlap_and_serialisation(self) -> None:
        a = PatternMatch("repeat", 0, 3, 2.0, "a")
        b = PatternMatch("repeat", 2, 5, 2.0, "b")
        c = PatternMatch("repeat", 3, 5, 2.0, "c")
        assert a.overlaps(b)
        assert not a.overlaps(c)
        assert a.to_dict() == {
            "kind": "repeat",
            "start": 0,
            "end": 3,
            "length": 3,
            "bits": 2.0,
            "description": "a",
        }
