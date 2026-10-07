"""Shared pytest fixtures."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from pwtool.breach import sha1_hex, split_hash

FetchLog = list[tuple[str, float]]


def make_range_body(password: str | None, count: int, *, padding: int = 5) -> str:
    """Build a fake Pwned Passwords range response.

    If ``password`` is given, its suffix is included with ``count`` occurrences.
    Padding rows (count 0) are added like the real API does with ``Add-Padding``.
    """
    lines = [f"{i:035X}:{i + 3}" for i in range(1, 6)]
    lines += [f"{'F' * 30}{i:05X}:0" for i in range(padding)]
    if password is not None:
        _, suffix = split_hash(sha1_hex(password))
        lines.insert(2, f"{suffix}:{count}")
    return "\r\n".join(lines)


@pytest.fixture
def fake_fetcher() -> Callable[..., tuple[Callable[[str, float], str], FetchLog]]:
    """Factory returning a fake HIBP fetcher and a log of the prefixes it received."""

    def factory(password: str | None = None, count: int = 0):
        calls: FetchLog = []

        def fetch(prefix: str, timeout: float) -> str:
            calls.append((prefix, timeout))
            return make_range_body(password, count)

        return fetch, calls

    return factory


@pytest.fixture(autouse=True)
def _plain_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make Rich output deterministic regardless of the developer's terminal."""
    for var in ("FORCE_COLOR", "TTY_COMPATIBLE", "TTY_INTERACTIVE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setenv("TERM", "dumb")
    monkeypatch.setenv("COLUMNS", "100")


@pytest.fixture(autouse=True)
def _no_real_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail loudly if any test tries to reach the real network."""

    def guard(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("tests must not access the network")

    monkeypatch.setattr("urllib.request.urlopen", guard)
