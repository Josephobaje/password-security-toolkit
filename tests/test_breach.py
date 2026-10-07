import io
import urllib.error
import urllib.request

import pytest

from pwtool import breach
from pwtool.breach import BreachCheckError, check_pwned, fetch_range, parse_range, sha1_hex

PASSWORD_SHA1 = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"


class FakeResponse(io.BytesIO):
    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def test_sha1_matches_known_vector() -> None:
    assert sha1_hex("password") == PASSWORD_SHA1


def test_split_hash() -> None:
    assert breach.split_hash(PASSWORD_SHA1) == ("5BAA6", PASSWORD_SHA1[5:])


def test_parse_range_ignores_padding_and_garbage() -> None:
    body = "ABC:12\r\nDEF:0\nnot-a-line\nXYZ:abc\n\nabd:3"
    assert parse_range(body) == {"ABC": 12, "ABD": 3}


def test_check_pwned_found(fake_fetcher) -> None:
    fetch, calls = fake_fetcher("password", 9_545_824)
    result = check_pwned("password", fetcher=fetch)
    assert result.pwned
    assert result.count == 9_545_824
    assert result.prefix == "5BAA6"
    assert result.suffixes_checked == 6
    assert calls == [("5BAA6", breach.DEFAULT_TIMEOUT)]


def test_check_pwned_not_found(fake_fetcher) -> None:
    fetch, _ = fake_fetcher(None)
    result = check_pwned("correct-horse-battery-staple-xyz", fetcher=fetch, timeout=3)
    assert not result.pwned
    assert result.count == 0
    assert result.to_dict()["pwned"] is False


def test_only_five_char_prefix_is_sent(fake_fetcher) -> None:
    fetch, calls = fake_fetcher(None)
    secret = "hunter2-super-secret"
    check_pwned(secret, fetcher=fetch)
    (sent, _timeout) = calls[0]
    assert len(sent) == 5
    assert sent == sha1_hex(secret)[:5]
    assert secret not in sent
    assert sha1_hex(secret)[5:] not in sent


def test_empty_password_rejected() -> None:
    with pytest.raises(ValueError, match="empty"):
        check_pwned("")


def test_retries_then_succeeds(monkeypatch: pytest.MonkeyPatch, fake_fetcher) -> None:
    sleeps: list[float] = []
    monkeypatch.setattr(breach.time, "sleep", sleeps.append)
    good, _ = fake_fetcher("password", 1)
    attempts = {"n": 0}

    def flaky(prefix: str, timeout: float) -> str:
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise BreachCheckError("boom")
        return good(prefix, timeout)

    result = check_pwned("password", fetcher=flaky, retries=2, backoff=0.5)
    assert result.pwned
    assert sleeps == [0.5, 1.0]


def test_retries_exhausted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(breach.time, "sleep", lambda _s: None)

    def broken(prefix: str, timeout: float) -> str:
        raise BreachCheckError("offline")

    with pytest.raises(BreachCheckError, match="offline"):
        check_pwned("password", fetcher=broken, retries=1)


class TestFetchRange:
    def test_success_sends_prefix_only_with_padding_header(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seen: dict[str, object] = {}

        def fake_urlopen(request: urllib.request.Request, timeout: float) -> FakeResponse:
            seen["url"] = request.full_url
            seen["headers"] = dict(request.header_items())
            seen["timeout"] = timeout
            return FakeResponse(b"1E4C9B93F3F0682250B6CF8331B7EE68FD8:42\r\n")

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
        body = fetch_range("5BAA6", timeout=4)
        assert body.startswith("1E4C9B93")
        assert seen["url"] == "https://api.pwnedpasswords.com/range/5BAA6"
        headers = {k.lower(): v for k, v in seen["headers"].items()}  # type: ignore[union-attr]
        assert headers["add-padding"] == "true"
        assert "password-security-toolkit" in headers["user-agent"]
        assert seen["timeout"] == 4

    def test_end_to_end_with_mocked_urlopen(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            urllib.request,
            "urlopen",
            lambda request, timeout: FakeResponse(b"1E4C9B93F3F0682250B6CF8331B7EE68FD8:42"),
        )
        result = check_pwned("password")
        assert result.pwned
        assert result.count == 42

    @pytest.mark.parametrize("prefix", ["5BAA", "5BAA61", "5baa6", "ZZZZZ"])
    def test_rejects_anything_but_a_5_char_hex_prefix(self, prefix: str) -> None:
        with pytest.raises(ValueError, match="5 upper-case hex"):
            fetch_range(prefix)

    def test_http_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def raise_http(request: urllib.request.Request, timeout: float) -> None:
            raise urllib.error.HTTPError(request.full_url, 503, "busy", {}, None)  # type: ignore[arg-type]

        monkeypatch.setattr(urllib.request, "urlopen", raise_http)
        with pytest.raises(BreachCheckError, match="HTTP 503"):
            fetch_range("5BAA6")

    @pytest.mark.parametrize(
        "error", [urllib.error.URLError("no route"), TimeoutError("timed out"), OSError("reset")]
    )
    def test_network_errors(self, monkeypatch: pytest.MonkeyPatch, error: Exception) -> None:
        def raise_error(request: urllib.request.Request, timeout: float) -> None:
            raise error

        monkeypatch.setattr(urllib.request, "urlopen", raise_error)
        with pytest.raises(BreachCheckError, match="Could not reach"):
            fetch_range("5BAA6")
