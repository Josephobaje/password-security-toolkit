import io
import json
import runpy
import sys

import pytest

from pwtool import __version__, cli
from pwtool.breach import BreachCheckError, BreachResult


def run(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    argv: list[str],
    stdin: str | None = None,
) -> tuple[int, str, str]:
    if stdin is not None:
        monkeypatch.setattr(sys, "stdin", io.StringIO(stdin))
    code = cli.main(argv)
    out, err = capsys.readouterr()
    return code, out, err


@pytest.fixture
def no_getpass(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(prompt: str = "") -> str:
        raise AssertionError("getpass should not be called")

    monkeypatch.setattr(cli.getpass, "getpass", fail)


def test_check_uses_getpass_by_default(monkeypatch, capsys) -> None:
    prompts: list[str] = []

    def fake_getpass(prompt: str = "") -> str:
        prompts.append(prompt)
        return "password"

    monkeypatch.setattr(cli.getpass, "getpass", fake_getpass)
    code, out, _ = run(monkeypatch, capsys, ["check", "--no-color"])
    assert code == 0
    assert len(prompts) == 1
    assert "hidden" in prompts[0]
    assert "Very weak" in out
    assert "Password Strength Report" in out


def test_check_json_from_stdin(monkeypatch, capsys, no_getpass) -> None:
    code, out, _ = run(monkeypatch, capsys, ["check", "--stdin", "--json"], "x7#Kp9!vQ2mZ\n")
    data = json.loads(out)
    assert code == 0
    assert data["score"] == 4
    assert "x7#Kp9!vQ2mZ" not in out


def test_check_output_never_echoes_password(monkeypatch, capsys, no_getpass) -> None:
    secret = "Dragon2019qwerty"
    _, out, err = run(monkeypatch, capsys, ["check", "--stdin"], secret + "\n")
    for fragment in (secret, "Dragon", "2019", "qwerty"):
        assert fragment not in out + err


@pytest.mark.parametrize(("pw", "expected"), [("password", 1), ("kV9#pL2!qX7&wM4$", 0)])
def test_check_min_score_exit_code(monkeypatch, capsys, pw: str, expected: int) -> None:
    code, _, _ = run(monkeypatch, capsys, ["check", "--stdin", "--min-score", "3"], pw + "\n")
    assert code == expected


def test_check_with_breach(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        cli, "check_pwned", lambda pw, timeout: BreachResult(True, 1234, "5BAA6", 900)
    )
    code, out, _ = run(monkeypatch, capsys, ["check", "--stdin", "--breach"], "password\n")
    assert code == 0
    assert "PWNED" in out
    assert "1,234" in out


def test_check_breach_pwned_fails_min_score(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "check_pwned", lambda pw, timeout: BreachResult(True, 3, "ABCDE", 9))
    argv = ["check", "--stdin", "--breach", "--min-score", "0", "--json"]
    code, out, _ = run(monkeypatch, capsys, argv, "kV9#pL2!qX7&wM4$\n")
    assert code == 1
    assert json.loads(out)["breach"]["pwned"] is True


def test_check_breach_network_error(monkeypatch, capsys) -> None:
    def boom(pw: str, timeout: float) -> BreachResult:
        raise BreachCheckError("offline")

    monkeypatch.setattr(cli, "check_pwned", boom)
    code, out, _ = run(monkeypatch, capsys, ["check", "--stdin", "--breach"], "password\n")
    assert code == 0
    assert "Breach check skipped" in out
    code, out, _ = run(
        monkeypatch, capsys, ["check", "--stdin", "--breach", "--json"], "password\n"
    )
    assert json.loads(out)["breach"] == {"error": "offline"}


def test_breach_found_and_not_found(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "check_pwned", lambda pw, timeout: BreachResult(True, 1, "5BAA6", 5))
    code, out, _ = run(monkeypatch, capsys, ["breach", "--stdin"], "password\n")
    assert code == 1
    assert "1 time " in out

    monkeypatch.setattr(cli, "check_pwned", lambda pw, timeout: BreachResult(False, 0, "ABCDE", 5))
    code, out, _ = run(monkeypatch, capsys, ["breach", "--stdin"], "something-unique\n")
    assert code == 0
    assert "not found" in out
    code, out, _ = run(monkeypatch, capsys, ["breach", "--stdin", "--json"], "something\n")
    assert json.loads(out)["hash_prefix_sent"] == "ABCDE"


def test_breach_network_error(monkeypatch, capsys) -> None:
    def boom(pw: str, timeout: float) -> BreachResult:
        raise BreachCheckError("Could not reach the Pwned Passwords API: no route")

    monkeypatch.setattr(cli, "check_pwned", boom)
    code, out, _ = run(monkeypatch, capsys, ["breach", "--stdin"], "password\n")
    assert code == 2
    assert "Could not reach" in out
    code, out, _ = run(monkeypatch, capsys, ["breach", "--stdin", "--json"], "password\n")
    assert code == 2
    assert "error" in json.loads(out)


def test_breach_uses_mocked_network_end_to_end(monkeypatch, capsys, fake_fetcher) -> None:
    fetch, calls = fake_fetcher("hunter2", 17_043)
    monkeypatch.setattr("pwtool.breach.fetch_range", fetch)
    code, out, _ = run(monkeypatch, capsys, ["breach", "--stdin", "--json"], "hunter2\n")
    assert code == 1
    assert json.loads(out)["count"] == 17_043
    assert len(calls[0][0]) == 5


def test_generate_password_json(monkeypatch, capsys) -> None:
    argv = ["generate", "-l", "24", "-n", "3", "--no-symbols", "--json"]
    code, out, _ = run(monkeypatch, capsys, argv)
    data = json.loads(out)
    assert code == 0
    assert data["count"] == 3
    assert all(len(v) == 24 and v.isalnum() for v in data["values"])


def test_generate_passphrase_table(monkeypatch, capsys) -> None:
    argv = ["gen", "--passphrase", "-w", "4", "-s", "_", "--capitalize", "--add-number"]
    code, out, _ = run(monkeypatch, capsys, argv)
    assert code == 0
    assert "Generated passphrase" in out
    assert "bits" in out


def test_generate_invalid_values(monkeypatch, capsys) -> None:
    code, _, err = run(monkeypatch, capsys, ["generate", "-l", "2000"])
    assert code == 2
    assert "length" in err
    with pytest.raises(SystemExit):
        cli.main(["generate", "-l", "zero"])
    with pytest.raises(SystemExit):
        cli.main(["generate", "-n", "0"])


def test_invalid_min_score(capsys) -> None:
    with pytest.raises(SystemExit):
        cli.main(["check", "--min-score", "9"])
    assert "between 0 and 4" in capsys.readouterr().err


def test_empty_password_is_an_error(monkeypatch, capsys) -> None:
    code, _, err = run(monkeypatch, capsys, ["check", "--stdin"], "\n")
    assert code == 2
    assert "No password" in err


def test_ctrl_c_exits_cleanly(monkeypatch, capsys) -> None:
    def interrupt(prompt: str = "") -> str:
        raise KeyboardInterrupt

    monkeypatch.setattr(cli.getpass, "getpass", interrupt)
    code, _, err = run(monkeypatch, capsys, ["breach"])
    assert code == 130
    assert "Aborted" in err


def test_version(capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_command_required(capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main([])
    assert exc.value.code == 2


def test_python_dash_m(monkeypatch, capsys) -> None:
    monkeypatch.setattr(sys, "argv", ["pwtool", "generate", "--json"])
    with pytest.raises(SystemExit) as exc:
        runpy.run_module("pwtool", run_name="__main__")
    assert exc.value.code == 0
    assert json.loads(capsys.readouterr().out)["mode"] == "password"
