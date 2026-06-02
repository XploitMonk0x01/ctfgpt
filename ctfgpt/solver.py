"""CTF-GPT Solve Engine — category-aware, structured attack orchestrator.

Unlike ``agent.py`` (which is open-ended), ``solver.py`` runs a
*pre-defined playbook* for each CTF category, executing the right tools
in the right order, then generates a grounded solution summary.

Playbook phases per category
─────────────────────────────
web      → recon (gobuster/nikto) → vuln_scan → exploit → summarise
pwn      → checksec → file → strings → ltrace → gdb_info → summarise
forensics→ file → strings → binwalk → exiftool → steg → summarise
crypto   → identify_cipher → decode_attempts → summarise
reversing→ file → strings → objdump → ghidra_headless → summarise
osint    → whois → nslookup → curl_headers → wayback → summarise
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Optional

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.rule import Rule
from rich.table import Table

console = Console(force_terminal=True)

# ---------------------------------------------------------------------------
# Tool Step definition
# ---------------------------------------------------------------------------

@dataclass
class ToolStep:
    """A single step in a solve playbook."""
    name: str                          # human label, e.g. "Port Scan"
    command_template: str              # may contain {target}, {file}, {url}
    description: str                   # what we expect to learn
    required: bool = True              # if False, skip on failure silently
    timeout: int = 60                  # seconds
    phase: str = "recon"               # recon | enum | exploit | analysis


# ---------------------------------------------------------------------------
# Category Playbooks
# ---------------------------------------------------------------------------

PLAYBOOKS: dict[str, list[ToolStep]] = {

    "web": [
        ToolStep("HTTP Headers",      "curl -sI {target}",                          "Check server, tech stack, cookies",    phase="recon"),
        ToolStep("Nikto Scan",        "nikto -h {target} -nossl -timeout 10",       "Find common vulns & misconfigs",       phase="recon"),
        ToolStep("Dir Bust",          "gobuster dir -u {target} -w /usr/share/wordlists/dirb/common.txt -q -t 20 --timeout 10s", "Discover hidden paths", phase="enum"),
        ToolStep("robots.txt",        "curl -s {target}/robots.txt",                "Check disallowed paths",               phase="enum",  required=False),
        ToolStep("Cookies & Auth",    "curl -sv {target} 2>&1 | grep -iE 'set-cookie|authorization|location'", "Check auth flow", phase="enum", required=False),
        ToolStep("Source Hints",      "curl -s {target} | grep -iE 'flag|ctf|secret|pass|token|admin|TODO|FIXME'", "Look for flags/hints in HTML", phase="exploit", required=False),
    ],

    "forensics": [
        ToolStep("File Type",         "file {file}",                                "Identify true file type",              phase="recon"),
        ToolStep("Strings",           "strings {file} | head -100",                 "Extract readable strings",             phase="recon"),
        ToolStep("Hex Header",        "xxd {file} | head -20",                      "Check magic bytes / file header",      phase="recon"),
        ToolStep("Binwalk",           "binwalk {file}",                             "Find embedded files / archives",       phase="analysis"),
        ToolStep("Exiftool",          "exiftool {file}",                            "Extract metadata",                     phase="analysis", required=False),
        ToolStep("Steg Check",        "steghide info {file} -p ''",                 "Check for steganography",              phase="analysis", required=False),
        ToolStep("Flag Pattern",      "strings {file} | grep -iE 'flag{{|ctf{{|HTB{{|THM{{'", "Search for flag format", phase="exploit", required=False),
    ],

    "crypto": [
        ToolStep("Identify Encoding", "echo '{target}' | base64 -d 2>/dev/null || echo 'not base64'", "Try base64 decode", phase="recon"),
        ToolStep("Hex Decode",        "echo '{target}' | xxd -r -p 2>/dev/null | strings",            "Try hex decode",    phase="recon"),
        ToolStep("ROT13",             "echo '{target}' | tr 'A-Za-z' 'N-ZA-Mn-za-m'",               "Try ROT-13",        phase="recon"),
        ToolStep("Caesar Brute",      "python3 -c \"s='{target}'; [print(i,''.join(chr((ord(c)-65+i)%26+65) if c.isupper() else chr((ord(c)-97+i)%26+97) if c.islower() else c for c in s)) for i in range(26)]\"", "Caesar brute force", phase="analysis"),
        ToolStep("Hash Identify",     "hashid '{target}'",                                            "Identify hash type", phase="analysis", required=False),
    ],

    "pwn": [
        ToolStep("File Info",         "file {file}",                                "Architecture, bits, PIE/NX",           phase="recon"),
        ToolStep("Security Checks",   "checksec --file={file}",                     "ASLR/NX/PIE/canary status",            phase="recon"),
        ToolStep("Strings",           "strings {file} | head -80",                  "Useful strings, hints, addresses",     phase="recon"),
        ToolStep("Symbols",           "nm -D {file} 2>/dev/null | head -40",        "Exported symbols (dangerous funcs?)",  phase="analysis"),
        ToolStep("Disassemble Main",  "objdump -d {file} | grep -A 40 '<main>'",    "Disassemble main function",            phase="analysis"),
        ToolStep("Ltrace",            "ltrace -f ./{file} 2>&1 | head -40",         "Library call trace",                   phase="analysis", required=False),
    ],

    "reversing": [
        ToolStep("File Info",         "file {file}",                                "Binary format & architecture",         phase="recon"),
        ToolStep("Strings",           "strings {file} | head -100",                 "Hardcoded keys, flags, paths",         phase="recon"),
        ToolStep("Imports",           "readelf -d {file} 2>/dev/null | grep NEEDED","Linked libraries",                     phase="recon"),
        ToolStep("Symbols",           "nm {file} 2>/dev/null | head -50",           "Symbol table",                         phase="analysis"),
        ToolStep("Disassemble",       "objdump -d -M intel {file} 2>/dev/null | head -100", "Full disassembly preview",     phase="analysis"),
        ToolStep("Anti-debug Check",  "strings {file} | grep -iE 'ptrace|debug|vm|sandbox'", "Anti-analysis tricks",        phase="analysis", required=False),
    ],

    "osint": [
        ToolStep("WHOIS",             "whois {target}",                             "Domain registration info",             phase="recon"),
        ToolStep("DNS Lookup",        "nslookup {target}",                          "DNS records",                          phase="recon"),
        ToolStep("HTTP Headers",      "curl -sI {target}",                          "Server tech stack",                    phase="recon"),
        ToolStep("Subdomain Enum",    "gobuster dns -d {target} -w /usr/share/wordlists/dirb/common.txt -q", "Find subdomains", phase="enum", required=False),
        ToolStep("Certificate Info",  "echo | openssl s_client -connect {target}:443 2>/dev/null | openssl x509 -noout -text | head -30", "TLS cert details", phase="enum", required=False),
    ],
}

# Fallback for unknown category
PLAYBOOKS["general"] = PLAYBOOKS["forensics"]


# ---------------------------------------------------------------------------
# Solver
# ---------------------------------------------------------------------------

def _render_phase_header(phase: str, category: str) -> None:
    phase_colors = {
        "recon": "cyan",
        "enum": "blue",
        "analysis": "yellow",
        "exploit": "red",
    }
    color = phase_colors.get(phase, "white")
    console.print()
    console.print(Rule(f"[bold {color}]Phase: {phase.upper()}[/bold {color}]"))


def _render_step_output(step: ToolStep, output: str, success: bool) -> None:
    color = "green" if success and output.strip() else "yellow" if success else "red"
    status = "✓" if success else "✗"
    preview = output[:800] if output else "(no output)"

    console.print(Panel(
        f"[dim]{preview}[/dim]",
        title=f"[{color}]{status}  {step.name}[/{color}]",
        title_align="left",
        subtitle=f"[dim]{step.command_template[:60]}…[/dim]" if len(step.command_template) > 60 else f"[dim]{step.command_template}[/dim]",
        subtitle_align="right",
        border_style=color,
        padding=(0, 1),
    ))


def run_solver(
    target: str,
    category: Optional[str],
    file_path: Optional[str],
    max_steps: int,
    dry_run: bool,
    scope: Optional[str],
    session_id: str,
) -> tuple[str, str]:
    """Run the structured solve playbook and return (summary_hint, session_id).

    Parameters
    ----------
    target:
        IP, URL, or cipher text / puzzle description.
    category:
        CTF category. Auto-detected if ``None``.
    file_path:
        Path to challenge file on Kali (e.g. ``/home/kali/ctf/challenge.exe``).
    max_steps:
        Maximum number of playbook steps to execute.
    dry_run:
        If ``True``, print commands but do not execute.
    scope:
        Optional filesystem scope restriction.
    session_id:
        Unique session identifier for the blackboard.
    """
    from ctfgpt.classifier import classify
    from ctfgpt.blackboard import Blackboard
    from ctfgpt.rag import ask as rag_ask

    # --- Auto-detect category -----------------------------------------------
    if not category:
        query_for_classify = f"{target} {file_path or ''}"
        category = classify(query_for_classify)
        console.print(f"  [dim]Auto-detected category:[/dim] [bold cyan]{category}[/bold cyan]")

    # --- Select playbook -----------------------------------------------------
    steps = PLAYBOOKS.get(category, PLAYBOOKS["general"])[:max_steps]
    console.print(f"  [dim]Playbook:[/dim] [bold]{len(steps)} steps[/bold] for [bold cyan]{category}[/bold cyan]\n")

    # --- Blackboard ---------------------------------------------------------
    bb = Blackboard(session_id=session_id, category=category, challenge_desc=target)

    # --- Print dry-run table ------------------------------------------------
    if dry_run:
        table = Table(title="Planned Steps (Dry Run)", show_lines=True)
        table.add_column("Phase", style="cyan")
        table.add_column("Step", style="bold")
        table.add_column("Command")
        for step in steps:
            cmd = _render_command(step.command_template, target, file_path)
            table.add_row(step.phase, step.name, cmd)
        console.print(table)
        return f"[Dry run] {len(steps)} steps planned for category '{category}'", session_id

    # --- MCP Client ----------------------------------------------------------
    try:
        from ctfgpt.mcp_client import get_mcp_client
        mcp = get_mcp_client()
    except Exception as exc:
        console.print(f"[red]❌ MCP client unavailable: {exc}[/red]")
        return f"Solve failed: MCP unavailable — {exc}", session_id

    # --- Execute playbook ----------------------------------------------------
    last_phase = ""
    step_count = 0

    for step in steps:
        step_count += 1
        cmd = _render_command(step.command_template, target, file_path)

        # Phase header
        if step.phase != last_phase:
            _render_phase_header(step.phase, category)
            last_phase = step.phase

        console.print(f"\n  [bold]{step_count}. {step.name}[/bold]  [dim]— {step.description}[/dim]")
        console.print(f"  [dim]$ {cmd}[/dim]")

        # User approval
        import typer
        approved = typer.confirm("     Run?", default=True)
        if not approved:
            console.print("  [yellow]Skipped.[/yellow]")
            continue

        # Execute
        try:
            result = mcp.execute(cmd, timeout=step.timeout)
            stdout = result.get("stdout", "")
            stderr = result.get("stderr", "")
            success = result.get("success", True)

            output = stdout or stderr or "(no output)"
            _render_step_output(step, output, success)

            weight = 0.8 if stdout.strip() else 0.3
            bb.write_finding(step.name, cmd, output, weight=weight)

        except Exception as exc:
            msg = str(exc)
            _render_step_output(step, f"Error: {msg}", False)
            if step.required:
                bb.write_finding(step.name, cmd, f"ERROR: {msg}", weight=0.1)

        time.sleep(0.3)  # small breathing room between steps

    # --- Generate grounded summary ------------------------------------------
    console.print()
    console.print(Rule("[bold green]Generating Solution Summary[/bold green]"))
    console.print("  [dim]Combining evidence with RAG writeup context…[/dim]\n")

    evidence_text = bb.summary()
    query = f"Solve this {category} CTF challenge: {target}\n\nEvidence collected:\n{evidence_text}"

    try:
        hint, _sources = rag_ask(
            query=query,
            category=category,
            level=3,
            blackboard_summary=evidence_text,
        )
    except Exception as exc:
        hint = (
            f"Evidence collected but RAG summary failed ({exc}).\n\n"
            f"Raw findings:\n{evidence_text}"
        )

    return hint, session_id


def _render_command(template: str, target: str, file_path: Optional[str]) -> str:
    """Substitute ``{target}`` and ``{file}`` into a command template."""
    cmd = template
    if "{target}" in cmd:
        cmd = cmd.replace("{target}", target)
    if "{file}" in cmd:
        cmd = cmd.replace("{file}", file_path or "CHALLENGE_FILE")
    if "{url}" in cmd:
        url = target if target.startswith("http") else f"http://{target}"
        cmd = cmd.replace("{url}", url)
    return cmd
