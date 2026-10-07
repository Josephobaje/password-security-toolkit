"""Command-line interface: ``pwtool check | breach | generate``."""

from __future__ import annotations

import argparse
import getpass
import sys
from collections.abc import Sequence
from typing import TextIO

from rich.console import Console

from pwtool import __version__
from pwtool.breach import DEFAULT_TIMEOUT, BreachCheckError, check_pwned
from pwtool.generator import (
    DEFAULT_LENGTH,
    DEFAULT_WORDS,
    generate_passphrases,
    generate_passwords,
)
from pwtool.output import emit_json, render_breach, render_generated, render_strength
from pwtool.strength import analyze

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_ERROR = 2
EXIT_INTERRUPTED = 130


class InputError(Exception):
    """Raised when no usable password could be read."""


def read_password(
    use_stdin: bool,
    *,
    prompt: str = "Password (input hidden): ",
    stdin: TextIO | None = None,
) -> str:
    """Read a password without echoing it or exposing it in shell history.

    By default the password is read interactively with :func:`getpass.getpass`.
    With ``use_stdin`` the first line of standard input is used instead, which
    is handy for piping from a password manager (``pass show x | pwtool check --stdin``).

    Raises:
        InputError: If the password is empty.
    """
    if use_stdin:
        stream = stdin if stdin is not None else sys.stdin
        password = stream.readline().rstrip("\r\n")
    else:
        password = getpass.getpass(prompt)
    if not password:
        raise InputError("No password provided.")
    return password


def _positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"expected an integer, got {value!r}") from exc
    if number < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def _score(value: str) -> int:
    number = int(value) if value.isdigit() else -1
    if not 0 <= number <= 4:
        raise argparse.ArgumentTypeError("score must be between 0 and 4")
    return number


def build_parser() -> argparse.ArgumentParser:
    """Create the argument parser for ``pwtool``."""
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    common.add_argument("--no-color", action="store_true", help="disable coloured output")

    secret_input = argparse.ArgumentParser(add_help=False)
    secret_input.add_argument(
        "--stdin",
        action="store_true",
        help="read the password from the first line of stdin instead of prompting",
    )

    parser = argparse.ArgumentParser(
        prog="pwtool",
        description=(
            "Password Security Toolkit - analyse strength, check breaches with "
            "HIBP k-anonymity, and generate secure passwords."
        ),
        epilog="Passwords are never accepted as command-line arguments, logged, or stored.",
    )
    parser.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND", required=True)

    check = sub.add_parser(
        "check",
        parents=[common, secret_input],
        help="analyse password strength (score 0-4)",
        description="Analyse a password's strength. The password is read via a hidden prompt.",
    )
    check.add_argument(
        "--breach",
        action="store_true",
        help="also check the password against Have I Been Pwned",
    )
    check.add_argument(
        "--min-score",
        type=_score,
        metavar="N",
        help="exit with status 1 if the score is below N (0-4); useful in scripts",
    )
    check.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help=argparse.SUPPRESS)

    breach = sub.add_parser(
        "breach",
        parents=[common, secret_input],
        help="check a password against Have I Been Pwned (k-anonymity)",
        description=(
            "Check whether a password appears in known breaches. Only the first 5 "
            "characters of its SHA-1 hash are sent to the Pwned Passwords API."
        ),
    )
    breach.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"network timeout in seconds (default: {DEFAULT_TIMEOUT:g})",
    )

    gen = sub.add_parser(
        "generate",
        aliases=["gen"],
        parents=[common],
        help="generate secure passwords or passphrases",
        description="Generate passwords or passphrases using the OS CSPRNG (`secrets`).",
    )
    gen.add_argument(
        "-l",
        "--length",
        type=_positive_int,
        default=DEFAULT_LENGTH,
        help=f"password length (default: {DEFAULT_LENGTH})",
    )
    gen.add_argument(
        "-n", "--count", type=_positive_int, default=1, help="how many to generate (default: 1)"
    )
    gen.add_argument("--no-symbols", action="store_true", help="exclude symbols")
    gen.add_argument("--no-digits", action="store_true", help="exclude digits")
    gen.add_argument("--no-upper", action="store_true", help="exclude upper-case letters")
    gen.add_argument(
        "--exclude-ambiguous", action="store_true", help="exclude look-alikes such as l, 1, O, 0"
    )
    gen.add_argument(
        "-p", "--passphrase", action="store_true", help="generate a Diceware-style passphrase"
    )
    gen.add_argument(
        "-w",
        "--words",
        type=_positive_int,
        default=DEFAULT_WORDS,
        help=f"words per passphrase (default: {DEFAULT_WORDS})",
    )
    gen.add_argument("-s", "--separator", default="-", help="passphrase word separator")
    gen.add_argument("--capitalize", action="store_true", help="capitalise passphrase words")
    gen.add_argument(
        "--add-number", action="store_true", help="append a digit to one passphrase word"
    )
    return parser


def _make_console(args: argparse.Namespace) -> Console:
    return Console(no_color=bool(args.no_color), highlight=False)


def _cmd_check(args: argparse.Namespace, console: Console) -> int:
    password = read_password(args.stdin)
    report = analyze(password)
    breach_payload: dict[str, object] | None = None
    breach_error: str | None = None
    breach_result = None
    if args.breach:
        try:
            breach_result = check_pwned(password, timeout=args.timeout)
            breach_payload = breach_result.to_dict()
        except BreachCheckError as exc:
            breach_error = str(exc)
    del password

    if args.json:
        payload = report.to_dict()
        if args.breach:
            payload["breach"] = breach_payload if breach_payload else {"error": breach_error}
        emit_json(console, payload)
    else:
        render_strength(console, report)
        if breach_result is not None:
            render_breach(console, breach_result)
        elif breach_error:
            console.print(f"[yellow]⚠ Breach check skipped:[/yellow] {breach_error}")

    failed = args.min_score is not None and report.score < args.min_score
    if breach_result is not None and breach_result.pwned and args.min_score is not None:
        failed = True
    return EXIT_FAIL if failed else EXIT_OK


def _cmd_breach(args: argparse.Namespace, console: Console) -> int:
    password = read_password(args.stdin)
    try:
        result = check_pwned(password, timeout=args.timeout)
    except BreachCheckError as exc:
        if args.json:
            emit_json(console, {"error": str(exc)})
        else:
            console.print(f"[bold red]Error:[/bold red] {exc}")
            console.print("[dim]Check your internet connection and try again.[/dim]")
        return EXIT_ERROR
    finally:
        del password
    if args.json:
        emit_json(console, result.to_dict())
    else:
        render_breach(console, result)
    return EXIT_FAIL if result.pwned else EXIT_OK


def _cmd_generate(args: argparse.Namespace, console: Console) -> int:
    if args.passphrase:
        generated = generate_passphrases(
            args.count,
            args.words,
            separator=args.separator,
            capitalize=args.capitalize,
            add_number=args.add_number,
        )
    else:
        generated = generate_passwords(
            args.count,
            args.length,
            upper=not args.no_upper,
            digits=not args.no_digits,
            symbols=not args.no_symbols,
            exclude_ambiguous=args.exclude_ambiguous,
        )
    if args.json:
        emit_json(console, generated.to_dict())
    else:
        render_generated(console, generated)
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for the ``pwtool`` console script.

    Returns:
        Process exit status: 0 on success, 1 when a check "fails" (breached
        password or score below ``--min-score``), 2 on errors, 130 on Ctrl+C.
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    console = _make_console(args)
    handlers = {
        "check": _cmd_check,
        "breach": _cmd_breach,
        "generate": _cmd_generate,
        "gen": _cmd_generate,
    }
    try:
        return handlers[args.command](args, console)
    except InputError as exc:
        Console(stderr=True).print(f"[bold red]Error:[/bold red] {exc}")
        return EXIT_ERROR
    except ValueError as exc:
        Console(stderr=True).print(f"[bold red]Error:[/bold red] {exc}")
        return EXIT_ERROR
    except (KeyboardInterrupt, EOFError):
        Console(stderr=True).print("\n[dim]Aborted.[/dim]")
        return EXIT_INTERRUPTED


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
