"""Safety utilities for CTF-GPT agent mode.

Provides confirmation prompts, command validation, and scope
enforcement for automated tool execution on Kali.
"""

import re
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm

console = Console()

# ---------------------------------------------------------------------------
# Dangerous command patterns
# ---------------------------------------------------------------------------
# Each regex is checked against the full command string.  A match means the
# command is potentially destructive and should be blocked in automated mode.

DANGEROUS_PATTERNS: list[str] = [
    r"\brm\s+-rf\s+/",          # rm -rf /
    r"\bmkfs\b",                 # filesystem formatting
    r"\bdd\s+if=.*of=/dev/",     # dd to raw device
    r"\b:(){ :\|:& };:",        # fork bomb
    r"\bshutdown\b",             # system shutdown
    r"\breboot\b",               # system reboot
    r"\bwget.*\|.*sh\b",         # pipe URL to shell
    r"\bcurl.*\|.*bash\b",       # pipe URL to bash
]

_COMPILED_DANGEROUS: list[re.Pattern[str]] = [
    re.compile(pat) for pat in DANGEROUS_PATTERNS
]


# ---------------------------------------------------------------------------
# 1. Agent-mode confirmation
# ---------------------------------------------------------------------------

def confirm_agent_mode(challenge_desc: str) -> bool:
    """Display a Rich warning panel and ask the user to confirm agent mode.

    The panel explains that agent mode will autonomously execute commands
    on the user's Kali VM and shows the challenge description that will
    be worked on.

    Parameters
    ----------
    challenge_desc:
        The CTF challenge description the agent will work on.

    Returns
    -------
    bool
        ``True`` if the user confirmed, ``False`` otherwise.
    """
    warning_body = (
        "[bold yellow]⚠  Agent mode will execute commands on your Kali VM.[/bold yellow]\n\n"
        "The AI agent will autonomously run security tools (nmap, gobuster, etc.) "
        "to gather evidence for this challenge.  All commands are validated before "
        "execution, but you should review the challenge scope.\n\n"
        f"[bold]Challenge:[/bold]\n{challenge_desc[:500]}"
    )

    console.print()
    console.print(Panel(
        warning_body,
        title="[bold yellow]🤖 Agent Mode[/bold yellow]",
        title_align="left",
        border_style="yellow",
        padding=(1, 2),
    ))
    console.print()

    return Confirm.ask("[yellow]Continue with agent mode?[/yellow]", default=False)


# ---------------------------------------------------------------------------
# 2. Command safety validation
# ---------------------------------------------------------------------------

def validate_command(command: str) -> tuple[bool, str]:
    """Check a command against known dangerous patterns.

    Parameters
    ----------
    command:
        The shell command string to validate.

    Returns
    -------
    tuple[bool, str]
        ``(True, "")`` if the command appears safe.
        ``(False, reason)`` if a dangerous pattern was matched.
    """
    if not command or not command.strip():
        return False, "Empty command"

    for pattern in _COMPILED_DANGEROUS:
        match = pattern.search(command)
        if match:
            return False, f"Blocked dangerous pattern: {match.group()!r}"

    return True, ""


# ---------------------------------------------------------------------------
# 3. Scope enforcement
# ---------------------------------------------------------------------------

def validate_scope(command: str, scope: Optional[str] = None) -> tuple[bool, str]:
    """Verify that file paths referenced in a command stay within scope.

    When *scope* is set (e.g. ``"/home/kali/ctf"``), any absolute paths
    found in the command are checked to ensure they are children of the
    scope directory.  Relative paths and commands without file arguments
    are allowed.

    Parameters
    ----------
    command:
        The shell command string to check.
    scope:
        Optional absolute directory path that limits file access.
        If ``None``, all paths are allowed.

    Returns
    -------
    tuple[bool, str]
        ``(True, "")`` if within scope or no scope set.
        ``(False, reason)`` if an out-of-scope path was found.
    """
    if scope is None:
        return True, ""

    scope_path = Path(scope).resolve()

    # Extract tokens that look like absolute file paths
    # Match Unix-style absolute paths (/foo/bar) and common patterns
    path_pattern = re.compile(r"(?<!\w)(/[a-zA-Z0-9_./-]+)")
    matches = path_pattern.findall(command)

    for raw_path in matches:
        # Skip common system paths used by tools themselves (not user data)
        system_prefixes = ("/dev/null", "/usr/bin", "/usr/sbin", "/bin", "/sbin", "/tmp")
        if any(raw_path.startswith(prefix) for prefix in system_prefixes):
            continue

        candidate = Path(raw_path).resolve()
        try:
            candidate.relative_to(scope_path)
        except ValueError:
            return False, (
                f"Path {raw_path!r} is outside the allowed scope {str(scope_path)!r}"
            )

    return True, ""


# ---------------------------------------------------------------------------
# 4. Command sanitization
# ---------------------------------------------------------------------------

def sanitize_command(command: str) -> str:
    """Perform basic cleanup on a command string.

    This intentionally does **not** strip shell operators like ``|``,
    ``&&``, or ``||`` because the LLM needs to construct legitimate
    pipelines (e.g. ``nmap ... | grep open``).

    What it does:
    - Strip leading/trailing whitespace
    - Remove null bytes (potential injection vector)

    Parameters
    ----------
    command:
        Raw command string from the LLM.

    Returns
    -------
    str
        The cleaned command string.
    """
    # Strip whitespace
    cleaned = command.strip()

    # Remove null bytes
    cleaned = cleaned.replace("\x00", "")

    return cleaned
