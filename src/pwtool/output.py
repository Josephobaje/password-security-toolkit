"""Rendering of reports for the terminal (via :mod:`rich`) and as JSON."""

from __future__ import annotations

import json
from typing import Any

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from pwtool.breach import BreachResult
from pwtool.generator import GeneratedSecrets
from pwtool.strength import ATTACK_SCENARIOS, SCORE_LABELS, StrengthReport, format_duration

SCORE_STYLES: tuple[str, ...] = ("bold red", "red", "yellow", "green", "bold green")


def emit_json(console: Console, payload: dict[str, Any]) -> None:
    """Print ``payload`` as pretty JSON without any markup processing."""
    console.out(json.dumps(payload, indent=2), highlight=False)


def score_bar(score: int, width: int = 4) -> Text:
    """Return a coloured block bar such as ``███░`` for a 0-4 score."""
    style = SCORE_STYLES[score]
    bar = Text()
    bar.append("█" * score, style=style)
    bar.append("░" * (width - score), style="dim")
    return bar


def _tick(flag: bool) -> Text:
    return Text("✔", style="green") if flag else Text("✘", style="red")


def _bullets(items: tuple[str, ...], marker: str, style: str) -> Table:
    """Return a grid of bullet points with a hanging indent."""
    grid = Table.grid(padding=(0, 1))
    grid.add_column(style=style, no_wrap=True)
    grid.add_column()
    for item in items:
        grid.add_row(f" {marker}", Text(item, style=style if marker == "⚠" else ""))
    return grid


def render_strength(console: Console, report: StrengthReport) -> None:
    """Render a :class:`StrengthReport` as a rich panel."""
    style = SCORE_STYLES[report.score]
    headline = Text.assemble(
        ("Score  ", "bold"),
        score_bar(report.score),
        (f"  {report.score}/4  ", style),
        (SCORE_LABELS[report.score], style),
    )

    details = Table.grid(padding=(0, 2))
    details.add_column(style="cyan", no_wrap=True)
    details.add_column()
    details.add_row("Length", f"{report.length} characters")
    classes = Text()
    for name, flag in (
        ("lower", report.classes.lowercase),
        ("UPPER", report.classes.uppercase),
        ("digits", report.classes.digits),
        ("symbols", report.classes.symbols),
    ):
        classes.append_text(_tick(flag))
        classes.append(f" {name}   ")
    details.add_row("Character classes", classes)
    details.add_row(
        "Entropy (estimated)",
        f"{report.entropy:.1f} bits  [dim](charset max {report.charset_entropy:.1f} bits)[/dim]",
    )
    details.add_row(
        "Common password",
        f"[bold red]YES[/bold red] (rank #{report.common_rank} of 10,000)"
        if report.is_common
        else "[green]no[/green]",
    )
    if report.patterns:
        details.add_row(
            "Patterns found",
            "\n".join(
                f"• {p.description} [dim](chars {p.start + 1}-{p.end})[/dim]"
                for p in report.patterns
            ),
        )
    else:
        details.add_row("Patterns found", "[green]none[/green]")

    crack = Table(box=box.SIMPLE_HEAD, show_edge=False, pad_edge=False)
    crack.add_column("Attack scenario", style="dim")
    crack.add_column("Time to crack (avg)", justify="right")
    for key, (label, _rate) in ATTACK_SCENARIOS.items():
        crack.add_row(label, format_duration(report.crack_times[key]))

    parts: list[Any] = [headline, Text(), details, Text(), crack]
    if report.warnings:
        parts.append(Text("\nWarnings", style="bold yellow"))
        parts.append(_bullets(report.warnings, "⚠", "yellow"))
    if report.suggestions:
        parts.append(Text("\nSuggestions", style="bold cyan"))
        parts.append(_bullets(report.suggestions, "→", "cyan"))

    console.print(
        Panel(
            Group(*parts),
            title="[bold]Password Strength Report[/bold]",
            border_style=style,
            padding=(1, 2),
        )
    )


def render_breach(console: Console, result: BreachResult) -> None:
    """Render a :class:`BreachResult` as a rich panel."""
    if result.pwned:
        times = "time" if result.count == 1 else "times"
        body = Text.assemble(
            ("⚠  PWNED!\n", "bold red"),
            "This password has appeared ",
            (f"{result.count:,}", "bold red"),
            f" {times} in known data breaches.\n",
            ("Do not use it anywhere. If you already do, change it now.", "red"),
        )
        border = "red"
    else:
        body = Text.assemble(
            ("✔  Good news!\n", "bold green"),
            "This password was not found in the Pwned Passwords corpus.\n",
            ("Not being breached does not make it strong - run `pwtool check` too.", "dim"),
        )
        border = "green"
    note = Text(
        f"\nk-anonymity: only the SHA-1 prefix '{result.prefix}' was sent; "
        f"{result.suffixes_checked:,} candidate suffixes were compared locally.",
        style="dim",
    )
    console.print(
        Panel(
            Group(body, note),
            title="[bold]Have I Been Pwned - Breach Check[/bold]",
            border_style=border,
            padding=(1, 2),
        )
    )


def render_generated(console: Console, generated: GeneratedSecrets) -> None:
    """Render generated passwords / passphrases as a table."""
    table = Table(
        title=f"Generated {generated.mode}{'s' if len(generated.values) > 1 else ''}",
        box=box.ROUNDED,
        title_style="bold",
    )
    table.add_column("#", justify="right", style="dim")
    table.add_column(generated.mode.capitalize(), style="bold green")
    for index, value in enumerate(generated.values, start=1):
        table.add_row(str(index), Text(value))
    console.print(table)
    console.print(
        f"[dim]Entropy:[/dim] [bold]{generated.entropy_bits:.1f} bits[/bold] each "
        "[dim]· generated with Python's `secrets` (OS CSPRNG)[/dim]"
    )
