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

import time
import re
from urllib.parse import urlparse
from dataclasses import dataclass, field
from datetime import datetime
import shlex
from typing import Callable, Optional

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.rule import Rule
from rich.table import Table

console = Console(force_terminal=True)


# ---------------------------------------------------------------------------
# Smart Target Extraction
# ---------------------------------------------------------------------------

def extract_target(raw_input: str) -> tuple[str, str]:
    """Extract the actionable target (IP/URL/domain) from free-text input.

    Returns ``(target, challenge_description)`` where *target* is the
    clean IP, URL, or domain to plug into commands, and
    *challenge_description* is the full original text for RAG context.

    Detection priority:
    1. Full URL  (http://..., https://...)
    2. IPv4 address  (10.10.11.230)
    3. Domain / hostname  (smol.thm, target.htb)
    4. Fallback: use the raw input as-is
    """
    desc = raw_input.strip()

    # 1. Full URL
    url_match = re.search(r'(https?://[^\s,;"\')]+)', desc)
    if url_match:
        return url_match.group(1).rstrip('.,;'), desc

    # 2. IPv4 address
    ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', desc)
    if ip_match:
        return ip_match.group(1), desc

    # 3. Domain / hostname  (word.tld pattern, especially .thm .htb .com etc)
    domain_match = re.search(
        r'\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
        r'\.[a-zA-Z]{2,})\b',
        desc,
    )
    if domain_match:
        candidate = domain_match.group(1).lower()
        # Skip common false positives that are not actual targets
        skip = {'wordpress.com', 'github.com', 'example.com', 'google.com'}
        if candidate not in skip:
            return candidate, desc

    # 4. Fallback: if the input is short enough, treat it as the target
    if len(desc) < 120:
        return desc, desc

    # 5. Long text with no detectable target — return empty and warn
    return '', desc

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
        ToolStep("Port Scan",         "nmap -sCV -T4 --top-ports 1000 {target}",    "Discover open ports & services",       phase="recon", timeout=120),
        ToolStep("HTTP Headers",      "curl -sSI {host_header} {connect_url}",      "Check server, tech stack, cookies",    phase="recon"),
        ToolStep("Nikto Scan",        "nikto -h {connect_url} {nikto_vhost} -nossl -timeout 10", "Find common vulns & misconfigs", phase="recon", timeout=120),
        ToolStep("Dir Bust",          "wordlist=$(for f in /usr/share/wordlists/dirb/common.txt /usr/share/seclists/Discovery/Web-Content/common.txt /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt; do [ -f \"$f\" ] && echo \"$f\" && break; done); if [ -z \"$wordlist\" ]; then echo 'ERROR: no common web wordlist found' >&2; exit 2; fi; gobuster dir -u {connect_url} {host_header} -w \"$wordlist\" -q -t 20 --timeout 10s", "Discover hidden paths", phase="enum", timeout=120),
        ToolStep("robots.txt",        "curl -sS {host_header} {connect_url}/robots.txt", "Check disallowed paths",          phase="enum",  required=False),
        ToolStep("WPScan",            "wpscan --url {connect_url} {wpscan_headers} --enumerate vp,vt,u --no-banner", "WordPress vuln scan (plugins, themes, users)", phase="enum", timeout=180, required=False),
        ToolStep("Cookies & Auth",    "curl -sv {host_header} {connect_url} 2>&1 | grep -iE 'set-cookie|authorization|location'", "Check auth flow", phase="enum", required=False),
        ToolStep("Source Hints",      "curl -sS {host_header} {connect_url} | grep -iE 'flag|ctf|secret|pass|token|admin|TODO|FIXME'", "Look for flags/hints in HTML", phase="exploit", required=False),
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
        IP, URL, domain, cipher text, or full challenge description.
        IPs/URLs/domains are extracted automatically.
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

    # --- Extract actionable target from input --------------------------------
    clean_target, challenge_desc = extract_target(target)
    original_clean_target = clean_target
    active_url = _target_to_url(clean_target)
    virtual_host: Optional[str] = None

    if not clean_target:
        console.print("[red]❌ Could not detect an IP, URL, or domain in your input.[/red]")
        console.print("[yellow]   Tip: pass the target directly, e.g. ctfgpt solve 10.10.11.230[/yellow]")
        return "No actionable target found in input.", session_id

    console.print(f"  [dim]Extracted target:[/dim] [bold green]{clean_target}[/bold green]")
    if challenge_desc != clean_target:
        console.print(f"  [dim]Challenge context:[/dim] {challenge_desc[:120]}…")

    # --- Auto-detect category -----------------------------------------------
    if not category:
        query_for_classify = f"{challenge_desc} {file_path or ''}"
        category = classify(query_for_classify)
        console.print(f"  [dim]Auto-detected category:[/dim] [bold cyan]{category}[/bold cyan]")

    # --- Select playbook -----------------------------------------------------
    steps = PLAYBOOKS.get(category, PLAYBOOKS["general"])[:max_steps]
    console.print(f"  [dim]Playbook:[/dim] [bold]{len(steps)} steps[/bold] for [bold cyan]{category}[/bold cyan]\n")

    # --- Blackboard ---------------------------------------------------------
    bb = Blackboard(session_id=session_id, category=category, challenge_desc=challenge_desc)

    # --- Print dry-run table ------------------------------------------------
    if dry_run:
        table = Table(title="Planned Steps (Dry Run)", show_lines=True)
        table.add_column("Phase", style="cyan")
        table.add_column("Step", style="bold")
        table.add_column("Command")
        for step in steps:
            cmd = _render_command(
                step.command_template,
                clean_target,
                file_path,
                active_url,
                connect_target=original_clean_target,
                virtual_host=virtual_host,
            )
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
        cmd = _render_command(
            step.command_template,
            clean_target,
            file_path,
            active_url,
            connect_target=original_clean_target,
            virtual_host=virtual_host,
        )

        # Phase header
        if step.phase != last_phase:
            _render_phase_header(step.phase, category)
            last_phase = step.phase

        console.print(f"\n  [bold]{step_count}. {step.name}[/bold]  [dim]— {step.description}[/dim]")
        console.print(f"  [dim]$ {cmd}[/dim]")

        # User approval
        import typer
        console.print("     [dim]Run? [Y/n/q (quit to summary)][/dim]", end=" ")
        choice = input().strip().lower()
        if choice in ['q', 'quit']:
            console.print("  [yellow]Playbook aborted early. Jumping to summary...[/yellow]")
            break
        elif choice in ['n', 'no']:
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

            if category == "web":
                updated_url = _adapt_web_target_from_output(
                    current_url=active_url,
                    original_target=original_clean_target,
                    output=output,
                    blackboard=bb,
                )
                if updated_url != active_url:
                    active_url = updated_url
                    clean_target = _url_to_target(active_url)
                    if _looks_like_ipv4(original_clean_target) and not _looks_like_ipv4(clean_target):
                        virtual_host = clean_target
                    console.print(
                        f"  [cyan]↪ Following discovered web target:[/cyan] "
                        f"[bold]{active_url}[/bold]"
                    )
                    if virtual_host:
                        console.print(
                            f"  [cyan]↪ Using direct IP connection with Host header:[/cyan] "
                            f"[bold]{original_clean_target}[/bold] → [bold]{virtual_host}[/bold]"
                        )
                    _offer_hosts_mapping(
                        mcp=mcp,
                        hostname=clean_target,
                        ip_address=original_clean_target,
                        challenge_desc=challenge_desc,
                        blackboard=bb,
                    )

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

    evidence_text = _summarize_evidence_for_rag(bb)
    query = (
        f"Solve this {category} CTF challenge.\n"
        f"Target: {clean_target}\n"
        f"Description: {challenge_desc[:500]}\n\n"
        f"Evidence collected:\n{evidence_text}"
    )

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


def _render_command(
    template: str,
    target: str,
    file_path: Optional[str],
    url: Optional[str] = None,
    connect_target: Optional[str] = None,
    virtual_host: Optional[str] = None,
) -> str:
    """Substitute ``{target}`` and ``{file}`` into a command template."""
    cmd = template
    rendered_url = url or _target_to_url(target)
    connect_url = _connect_url(rendered_url, connect_target, virtual_host)
    host_header = f"-H {shlex.quote(f'Host: {virtual_host}')}" if virtual_host else ""
    nikto_vhost = f"-vhost {shlex.quote(virtual_host)}" if virtual_host else ""
    wpscan_headers = f"--headers {shlex.quote(f'Host: {virtual_host}')}" if virtual_host else ""

    if "{target}" in cmd:
        cmd = cmd.replace("{target}", target)
    if "{file}" in cmd:
        cmd = cmd.replace("{file}", file_path or "CHALLENGE_FILE")
    if "{url}" in cmd:
        cmd = cmd.replace("{url}", rendered_url)
    replacements = {
        "{connect_url}": connect_url,
        "{host_header}": host_header,
        "{nikto_vhost}": nikto_vhost,
        "{wpscan_headers}": wpscan_headers,
    }
    for placeholder, value in replacements.items():
        cmd = cmd.replace(placeholder, value)
    return re.sub(r" {2,}", " ", cmd).strip()


def _connect_url(url: str, connect_target: Optional[str], virtual_host: Optional[str]) -> str:
    """Return the URL tools should connect to, preserving vhost in Host header."""
    if not connect_target or not virtual_host or not _looks_like_ipv4(connect_target):
        return url

    parsed = urlparse(url)
    if not parsed.scheme:
        return _target_to_url(connect_target)

    port = f":{parsed.port}" if parsed.port else ""
    return f"{parsed.scheme}://{connect_target}{port}"


def _target_to_url(target: str) -> str:
    """Return a web URL for an IP, hostname, or already-qualified URL."""
    if target.startswith(("http://", "https://")):
        return target.rstrip("/")
    return f"http://{target.rstrip('/')}"


def _url_to_target(url: str) -> str:
    """Return the host component from a URL, falling back to the input."""
    parsed = urlparse(url)
    return parsed.netloc or url


def _adapt_web_target_from_output(
    current_url: str,
    original_target: str,
    output: str,
    blackboard: object,
) -> str:
    """Follow obvious redirects discovered during web reconnaissance."""
    match = re.search(r"(?i)(?:location:\s*|redirect(?:s|ed)?\s+to\s+)(https?://[^\s'\"<>]+)", output)
    if not match:
        return current_url

    redirected_url = match.group(1).rstrip(".,;")
    old_host = urlparse(current_url).netloc
    new_host = urlparse(redirected_url).netloc
    if not new_host or new_host == old_host:
        return current_url

    if _looks_like_ipv4(original_target) and not _looks_like_ipv4(new_host):
        try:
            blackboard.add_unexplored(
                f"Redirect target {new_host} may need /etc/hosts mapping to {original_target}."
            )
        except AttributeError:
            pass
        console.print(f"  [yellow]Redirect uses virtual host {new_host}.[/yellow]")

    return redirected_url.rstrip("/")


def _offer_hosts_mapping(
    mcp: object,
    hostname: str,
    ip_address: str,
    challenge_desc: str,
    blackboard: object,
) -> None:
    """Ask whether to add a discovered virtual host to Kali's /etc/hosts."""
    if not _looks_like_ipv4(ip_address) or _looks_like_ipv4(hostname):
        return

    hostnames = _hostnames_for_mapping(hostname, challenge_desc)
    host_display = " ".join(hostnames)
    hosts_cmd = _hosts_mapping_command(ip_address, hostnames)
    console.print(
        f"  [dim]Add Kali /etc/hosts mapping?[/dim] "
        f"[bold]{ip_address} {host_display}[/bold] [dim][Y/n][/dim]",
        end=" ",
    )
    choice = input().strip().lower()
    if choice in {"n", "no"}:
        console.print("  [yellow]Skipped /etc/hosts update; DNS-dependent tools may fail.[/yellow]")
        return

    try:
        result = mcp.execute(hosts_cmd, timeout=15)
        output = result.get("stdout", "") or result.get("stderr", "") or "(no output)"
        success = result.get("success", True)
        weight = 0.7 if success else 0.2
        blackboard.write_finding("Hosts Mapping", hosts_cmd, output, weight=weight)
        if success:
            console.print(f"  [green]Added/verified /etc/hosts mapping for {host_display}.[/green]")
        else:
            console.print(f"  [red]Failed to add /etc/hosts mapping:[/red] {output[:200]}")
    except Exception as exc:
        blackboard.write_finding("Hosts Mapping", hosts_cmd, f"ERROR: {exc}", weight=0.1)
        console.print(f"  [red]Failed to add /etc/hosts mapping:[/red] {exc}")


def _hostnames_for_mapping(hostname: str, challenge_desc: str) -> list[str]:
    """Return hostnames that should resolve to the same CTF target IP."""
    hostnames = [hostname]
    if hostname.startswith("www."):
        apex = hostname.removeprefix("www.")
        if apex and apex in challenge_desc:
            hostnames.append(apex)
    elif f"www.{hostname}" in challenge_desc:
        hostnames.append(f"www.{hostname}")
    return list(dict.fromkeys(hostnames))


def _hosts_mapping_command(ip_address: str, hostnames: list[str]) -> str:
    """Return an idempotent shell command that maps hostnames to *ip_address*."""
    quoted_hosts = " ".join(shlex.quote(hostname) for hostname in hostnames)
    ip_arg = shlex.quote(ip_address)
    return (
        f"for host in {quoted_hosts}; do "
        f"awk -v h=\"$host\" '{{for (i=2; i<=NF; i++) if ($i == h) found=1}} "
        f"END {{exit !found}}' /etc/hosts "
        f"|| printf '%s\\t%s\\n' {ip_arg} \"$host\" | sudo tee -a /etc/hosts; "
        f"done; "
        f"getent hosts {quoted_hosts}"
    )


def _looks_like_ipv4(value: str) -> bool:
    """Return True when *value* is an IPv4 address-like string."""
    return re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", value) is not None


def _summarize_evidence_for_rag(blackboard: object, max_chars: int = 6000) -> str:
    """Build a bounded, signal-focused evidence digest for the final RAG call."""
    base_summary = blackboard.summary()
    findings = getattr(blackboard, "findings", [])
    interesting = re.compile(
        r"flag|ctf|secret|token|password|admin|login|location:|set-cookie|"
        r"wordpress|wp-|vulnerab|cve|open|service|http|robots|disallow|"
        r"error|forbidden|unauthorized|redirect",
        re.IGNORECASE,
    )

    blocks: list[str] = [base_summary, "", "Relevant Evidence Snippets:"]
    for finding in sorted(findings, key=lambda item: item.get("weight", 0), reverse=True):
        result = str(finding.get("result", ""))
        lines = [line.strip() for line in result.splitlines() if interesting.search(line)]
        if not lines:
            lines = [line.strip() for line in result.splitlines()[:5] if line.strip()]

        snippet = "\n".join(lines[:12])[:900]
        if snippet:
            blocks.append(
                f"\n## {finding.get('tool', 'tool')}\n"
                f"$ {finding.get('command', '')}\n"
                f"{snippet}"
            )

    digest = "\n".join(blocks)
    if len(digest) <= max_chars:
        return digest
    return digest[:max_chars] + "\n\n[Evidence truncated to fit the final summary prompt.]"
