"""Rich terminal formatting helpers for CTF-GPT."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.markdown import Markdown
from rich.status import Status
from rich.theme import Theme
from contextlib import contextmanager
from typing import Optional, Generator

# Category color scheme
CATEGORY_COLORS: dict[str, str] = {
    "forensics": "cyan",
    "web": "red",
    "crypto": "yellow",
    "pwn": "magenta",
    "reversing": "green",
    "osint": "blue",
}

CATEGORY_ICONS: dict[str, str] = {
    "forensics": "[F]",
    "web": "[W]",
    "crypto": "[C]",
    "pwn": "[P]",
    "reversing": "[R]",
    "osint": "[O]",
}

LEVEL_LABELS: dict[int, str] = {
    1: "Nudge",
    2: "Technique",
    3: "Full Approach",
}

import os
import sys

# Force UTF-8 output on Windows to avoid cp1252 encoding errors
if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        sys.stderr.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        pass

console = Console(force_terminal=True)


# ---------------------------------------------------------------------------
# Gradient helpers
# ---------------------------------------------------------------------------

def _lerp_color(c1: tuple[int, int, int], c2: tuple[int, int, int], t: float) -> str:
    """Linearly interpolate between two RGB colours and return a hex string."""
    r = int(c1[0] + (c2[0] - c1[0]) * t)
    g = int(c1[1] + (c2[1] - c1[1]) * t)
    b = int(c1[2] + (c2[2] - c1[2]) * t)
    return f"#{r:02x}{g:02x}{b:02x}"


def _gradient_text(text: str, start_rgb: tuple[int, int, int],
                   end_rgb: tuple[int, int, int]) -> Text:
    """Create a Rich Text object with a character-level colour gradient."""
    rich_text = Text()
    length = max(len(text) - 1, 1)
    for i, ch in enumerate(text):
        colour = _lerp_color(start_rgb, end_rgb, i / length)
        rich_text.append(ch, style=colour)
    return rich_text


# ---------------------------------------------------------------------------
# 1. Banner
# ---------------------------------------------------------------------------

def print_banner() -> None:
    """Print a styled ASCII-art CTF-GPT banner with a cyan->magenta gradient."""
    banner_lines = [
        r"   _____ _______ ______        _____ _____ _______",
        r"  / ____|__   __|  ____|      / ____|  __ \__   __|",
        r" | |       | |  | |__ ______ | |  __| |__) | | |",
        r" | |       | |  |  __|______|| | |_ |  ___/  | |",
        r" | |____   | |  | |          | |__| | |      | |",
        r"  \_____|  |_|  |_|           \_____|_|      |_|",
    ]

    # Cyan (0, 255, 255) → Magenta (255, 0, 255)
    cyan = (0, 255, 255)
    magenta = (255, 0, 255)

    for idx, line in enumerate(banner_lines):
        t = idx / max(len(banner_lines) - 1, 1)
        coloured_line = _gradient_text(line, cyan, magenta)
        console.print(coloured_line)

    subtitle = Text()
    subtitle.append("  AI-powered CTF assistant", style="bold bright_white")
    subtitle.append(" · ", style="dim")
    subtitle.append("RAG + Kali MCP", style="bold cyan")
    console.print(subtitle)
    console.print()


# ---------------------------------------------------------------------------
# 2. Hint panel
# ---------------------------------------------------------------------------

def print_hint(
    response: str,
    category: str,
    level: int,
    sources: list[str] | None = None,
) -> None:
    """Render a Rich Panel containing the hint response.

    Parameters
    ----------
    response:
        The hint text (Markdown-compatible).
    category:
        CTF category (forensics, web, …).
    level:
        Hint depth level (1-3).
    sources:
        Optional list of source URLs / references.
    """
    colour = CATEGORY_COLORS.get(category, "white")
    icon = CATEGORY_ICONS.get(category, "🏴")
    label = LEVEL_LABELS.get(level, "Hint")

    title = f"{icon} [{category}] CTF-GPT · Level {level} ({label})"

    panel = Panel(
        Markdown(response),
        title=title,
        title_align="left",
        border_style=colour,
        padding=(1, 2),
    )
    console.print(panel)

    # Sources
    if sources:
        for src in sources:
            console.print(f"  [dim italic]> {src}[/dim italic]")
        console.print()

    # Footer hint for deeper levels
    if level < 3:
        next_level = level + 1
        console.print(
            f"  [dim]> Use --level {next_level} for more detail[/dim]"
        )
        console.print()


# ---------------------------------------------------------------------------
# 3. Agent iteration
# ---------------------------------------------------------------------------

def print_agent_iteration(
    iteration: int,
    tool: str,
    command: str,
    output: str,
    category: str,
) -> None:
    """Display one iteration of the Kali agent loop.

    Parameters
    ----------
    iteration:
        1-based iteration counter.
    tool:
        Tool / binary name that was invoked.
    command:
        Full command string executed.
    output:
        Raw stdout/stderr captured from the command.
    category:
        CTF category for colour theming.
    """
    colour = CATEGORY_COLORS.get(category, "white")

    # Header bar
    header = Text()
    header.append(f"━━━ [kali] Iteration {iteration} ", style=f"bold {colour}")
    header.append("━" * 40, style=f"dim {colour}")
    console.print(header)

    # Command panel
    console.print(Panel(
        Text(command, style="bold white on grey23"),
        title=f">> {tool}",
        title_align="left",
        border_style="bright_black",
        padding=(0, 1),
    ))

    # Output panel (truncated if needed)
    max_chars = 500
    display_output = output
    if len(output) > max_chars:
        display_output = output[:max_chars] + f"\n\n… [dim](truncated — {len(output)} chars total)[/dim]"

    console.print(Panel(
        display_output,
        title=">> Output",
        title_align="left",
        border_style=colour,
        padding=(0, 1),
    ))
    console.print()


# ---------------------------------------------------------------------------
# 4. Status table
# ---------------------------------------------------------------------------

def print_status(
    db_ok: bool,
    db_stats: dict[str, int],
    llm_ok: bool,
    llm_mode: str,
    mcp_ok: bool,
) -> None:
    """Print a status overview table.

    Parameters
    ----------
    db_ok:
        Whether ChromaDB is reachable.
    db_stats:
        Mapping of collection name → document count.
    llm_ok:
        Whether the LLM endpoint is responsive.
    llm_mode:
        Human-readable LLM description (e.g. model name).
    mcp_ok:
        Whether the MCP server is reachable.
    """
    table = Table(title="CTF-GPT Status", title_style="bold bright_white")
    table.add_column("Component", style="bold", min_width=14)
    table.add_column("Status", min_width=18)
    table.add_column("Details", style="dim")

    # ChromaDB row
    if db_ok:
        total = sum(db_stats.values())
        collection_details = ", ".join(
            f"{name}: {count}" for name, count in db_stats.items()
        )
        details = f"{total} docs total ({collection_details})"
        table.add_row("ChromaDB", "[green][+] Connected[/green]", details)
    else:
        table.add_row("ChromaDB", "[red][-] Not available[/red]", "Database not found or inaccessible")

    # LLM row
    if llm_ok:
        table.add_row("LLM", "[green][+] Connected[/green]", llm_mode)
    else:
        table.add_row("LLM", "[red][-] Not available[/red]", llm_mode)

    # MCP row
    if mcp_ok:
        table.add_row("MCP Server", "[green][+] Connected[/green]", "Kali tools available")
    else:
        table.add_row("MCP Server", "[red][-] Not available[/red]", "Run kali-mcp to start")

    console.print()
    console.print(table)
    console.print()


# ---------------------------------------------------------------------------
# 5. Error panel
# ---------------------------------------------------------------------------

def print_error(title: str, message: str) -> None:
    """Display a red-bordered error panel."""
    console.print(Panel(
        f"[bold red][!] {message}[/bold red]",
        title=f"[bold red]{title}[/bold red]",
        title_align="left",
        border_style="red",
        padding=(1, 2),
    ))


# ---------------------------------------------------------------------------
# 6. Spinner context manager
# ---------------------------------------------------------------------------

@contextmanager
def create_spinner(message: str) -> Generator[Status, None, None]:
    """Yield a Rich Status spinner for long-running operations.

    Usage::

        with create_spinner("Thinking...") as status:
            do_work()
            status.update("Still working...")
    """
    with console.status(message, spinner="dots") as status:
        yield status


# ---------------------------------------------------------------------------
# 7. Ingestion stats table
# ---------------------------------------------------------------------------

def print_ingestion_stats(stats: dict[str, int]) -> None:
    """Print a table summarising document counts per collection after ingestion."""
    table = Table(title="Ingestion Results", title_style="bold bright_white")
    table.add_column("Collection", style="bold", min_width=22)
    table.add_column("Documents", justify="right", min_width=10)

    total = 0
    for collection, count in stats.items():
        # Derive category name from collection (ctfgpt_forensics → forensics)
        category = collection.replace("ctfgpt_", "")
        colour = CATEGORY_COLORS.get(category, "white")
        icon = CATEGORY_ICONS.get(category, "[?]")
        table.add_row(f"{icon} {collection}", f"[{colour}]{count}[/{colour}]")
        total += count

    table.add_section()
    table.add_row("[bold]Total[/bold]", f"[bold]{total}[/bold]")

    console.print()
    console.print(table)
    console.print()
