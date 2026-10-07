from pwtool.wordlists import common_passwords, dictionary_words, passphrase_words


def test_common_passwords_are_ranked() -> None:
    ranked = common_passwords()
    assert len(ranked) >= 9_000
    assert ranked["password"] == 1
    assert ranked["123456"] < ranked["qwerty"]
    assert all(key == key.lower() for key in list(ranked)[:500])


def test_passphrase_wordlist_is_clean_and_unique() -> None:
    words = passphrase_words()
    assert len(words) > 7_000
    assert len(set(words)) == len(words)
    assert all(word.isalpha() and word.islower() for word in words)
    assert dictionary_words() == frozenset(words)
