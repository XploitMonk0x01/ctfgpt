"""CTF-GPT Dynamic Planning Agent — adaptive, LLM-driven attack planner.

Unlike ``solver.py`` (static playbooks) or ``agent.py`` (open-ended ReAct),
the planner generates a concrete multi-step attack plan *before* executing,
then adapts the plan after each step based on tool output.

Flow:
    generate_plan → show_plan → [execute_step → observe → replan] (loop) → summarise
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table

console = Console(force_terminal=True)


# ---------------------------------------------------------------------------
# Plan Step
# ---------------------------------------------------------------------------

@dataclass
class PlanStep:
    """A single step in the dynamic attack plan."""
    step_num: int
    command: str
    rationale: str
    status: str = "pending"        # pending | running | done | skipped | failed
    output: str = ""               # tool output after execution
    phase: str = "recon"           # recon | enum | exploit | privesc

    def to_display(self) -> str:
        status_icons = {
            "pending": "⏳",
            "running": "🔄",
            "done": "✅",
            "skipped": "⏭️",
            "failed": "❌",
        }
        icon = status_icons.get(self.status, "❓")
        return f"{icon} Step {self.step_num}: {self.command}"


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

_PLAN_GENERATION_PROMPT = """\
You are an expert CTF penetration tester generating a concrete attack plan.
Think like a human hacker: start broad (what's open?), then enumerate,
then exploit, then escalate. Every command must be concrete and immediately
executable — no pseudo-code, no placeholders.

Target: {target}
Category: {category}
Challenge context: {challenge_desc}
{file_context}
{evidence_context}

METHODOLOGY (follow this order):
1. RECON   — nmap full-service scan to discover every open port and service
2. RECON   — grab HTTP headers / page title; follow any redirect
3. ENUM    — based on WHAT IS OPEN: gobuster/ffuf for web dirs, wpscan for WordPress,
             enum4linux for SMB, finger/rustscan for misc services
4. EXPLOIT — run targeted exploits for discovered vulnerabilities (searchsploit, sqlmap,
             wpscan --enumerate vp/u, hydra for SSH/FTP with weak creds)
5. PRIVESC — once inside: linpeas, sudo -l, find SUID, cron jobs, writable paths

PORTS HINT (if already known from evidence):
{ports_hint}

RULES:
1. Generate exactly {max_steps} steps ordered by the methodology above
2. Each step MUST be a CONCRETE shell command using the actual target "{target}"
3. Do NOT use {{target}}, <target>, or any placeholder — only the literal string
4. Do NOT include /etc/hosts manipulation — that is handled automatically
5. Do NOT repeat any already-completed step from evidence
6. If category is 'web': always start nmap, then curl -sI, then gobuster/ffuf, then wpscan if WordPress detected
7. If category is 'pwn': nmap → file, strings, checksec, gdb/pwndbg
8. If category is 'crypto': cat / identify cipher → decode → crack
9. Include WPScan with API token placeholder only if WordPress evidence exists
10. Each step must have a clear one-line rationale

OUTPUT FORMAT (strict — one step per line, no extra text):
STEP 1: <shell command> | RATIONALE: <one sentence why>
STEP 2: <shell command> | RATIONALE: <one sentence why>
...

EXAMPLE for a web target with SSH and HTTP open:
STEP 1: nmap -sCV -T4 10.10.11.230 | RATIONALE: Discover all open ports and service versions
STEP 2: curl -sIL http://10.10.11.230 | RATIONALE: Follow redirects and fingerprint HTTP tech stack
STEP 3: gobuster dir -u http://10.10.11.230 -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,html,txt | RATIONALE: Brute-force common web directories
STEP 4: wpscan --url http://10.10.11.230 --enumerate u,vp --plugins-detection aggressive | RATIONALE: Enumerate WordPress users and vulnerable plugins
"""

_REPLAN_PROMPT = """\
You are a CTF penetration tester adapting your attack plan based on new evidence.
Think like a human hacker — read the tool output carefully and decide the smartest next move.

Category: {category}
Target: {target} (use this hostname/IP in ALL commands)
Challenge: {challenge_desc}

Just completed Step {step_num}: {command}
Output (read carefully for open ports, services, hostnames, flags, errors):
{output}

Remaining planned steps:
{remaining_plan}

Already executed commands (DO NOT repeat these):
{completed_commands}

Evidence so far:
{evidence}

Based on the output, decide EXACTLY ONE of:
1. CONTINUE — the current plan is still correct, proceed to next step as-is
2. INSERT: <shell command> | RATIONALE: <why this is urgent next> — add one step immediately next
3. REPLAN — rewrite the remaining plan from scratch (same STEP N: cmd | RATIONALE: why format)
4. DONE — enough evidence to generate a final summary (flag found, or all angles exhausted)

SMART DECISION RULES:
- If nmap output shows open ports → always REPLAN with port-specific commands:
  * 22/tcp → add ssh bruteforce or banner grab if creds aren't known
  * 80/tcp or 443/tcp → gobuster, nikto, curl title, wpscan if WordPress detected
  * 21/tcp → ftp anonymous login check
  * 445/tcp → enum4linux, smbclient -L
  * 3306/tcp → mysql connection check
  * Include the hostname (not IP) in all web commands if redirect already detected
- If gobuster/ffuf finds new routes (e.g. /admin, /config.php, Status: 200/301) → REPLAN to investigate those specific paths with curl or a targeted dir scan.
- If curl shows "301 Moved Permanently" to a hostname → INSERT /etc/hosts mapping ONLY if
  that hostname is NOT already in the completed commands list
- If /etc/hosts was already mapped → NEVER insert another mapping, go straight to CONTINUE or REPLAN
- After /etc/hosts mapping → REPLAN remaining web steps to use the hostname instead of IP
- If WordPress is detected (wp-login, wp-content, X-Pingback) → REPLAN to insert wpscan --enumerate u,vp
- If a flag pattern is found (flag{{...}}, HTB{{...}}, THM{{...}}) → respond DONE
- If a step failed → INSERT an alternative command or REPLAN around the failure
- NEVER emit INSERT for /etc/hosts if it already appears in completed commands

Respond with EXACTLY one decision.
"""


# ---------------------------------------------------------------------------
# Hosts Redirect Detection
# ---------------------------------------------------------------------------

def _extract_hosts_redirect(command: str) -> tuple[str, str] | None:
    """If *command* adds an /etc/hosts entry, return (ip, hostname).

    Handles common patterns produced by the LLM or _replan:
      echo "10.10.11.1 box.htb" >> /etc/hosts
      echo "10.10.11.1 box.htb" | sudo tee -a /etc/hosts
      printf '%s\t%s\n' 10.10.11.1 box.htb | sudo tee -a /etc/hosts
    """
    # Match 'echo "IP HOSTNAME" >> /etc/hosts' style
    m = re.search(
        r'(?:echo|printf)\s+["\']?([\d.]+)\s+([a-zA-Z0-9._-]+\.(?:htb|thm|com|local|net|org|ctf))["\']?.*?/etc/hosts',
        command,
        re.IGNORECASE,
    )
    if m:
        return m.group(1), m.group(2)

    # Match 'printf '%s\t%s\n' IP HOSTNAME | tee …' style
    m = re.search(
        r"printf.*?'([\d.]+)'\s*'([a-zA-Z0-9._-]+\.(?:htb|thm|com|local|net|org|ctf))'",
        command,
        re.IGNORECASE,
    )
    if m:
        return m.group(1), m.group(2)

    # Match any command that writes IP HOSTNAME to /etc/hosts
    m = re.search(
        r'([\d.]+)\s+([a-zA-Z0-9._-]+\.(?:htb|thm|com|local|net|org|ctf)).*?/etc/hosts',
        command,
        re.IGNORECASE,
    )
    if m:
        return m.group(1), m.group(2)

    return None


def _idempotent_hosts_cmd(ip: str, hostname: str) -> str:
    """Return a one-liner that adds IP→hostname to /etc/hosts ONLY if not already present.

    Uses 'grep -qF' to check before appending, so it is safe to run multiple times.
    """
    import shlex
    ip_q = shlex.quote(ip)
    host_q = shlex.quote(hostname)
    entry_q = shlex.quote(f"{ip} {hostname}")
    return (
        f"grep -qF {entry_q} /etc/hosts || "
        f"echo {entry_q} | sudo tee -a /etc/hosts"
    )


# ---------------------------------------------------------------------------
# Plan Parser
# ---------------------------------------------------------------------------

def _parse_plan(raw: str, target: str) -> list[PlanStep]:
    """Parse LLM output into a list of PlanStep objects."""
    steps = []
    for line in raw.strip().split("\n"):
        line = line.strip()
        if not line:
            continue

        # Match: STEP N: <command> | RATIONALE: <text>
        match = re.match(
            r"STEP\s+(\d+)\s*:\s*(.+?)\s*\|\s*RATIONALE\s*:\s*(.+)",
            line,
            re.IGNORECASE,
        )
        if match:
            step_num = int(match.group(1))
            command = match.group(2).strip()
            rationale = match.group(3).strip()

            # Detect phase from command
            phase = _detect_phase(command)

            steps.append(PlanStep(
                step_num=step_num,
                command=command,
                rationale=rationale,
                phase=phase,
            ))

    # Renumber steps sequentially
    for i, step in enumerate(steps):
        step.step_num = i + 1

    return steps


def _detect_phase(command: str) -> str:
    """Heuristically detect the phase of a command."""
    cmd_lower = command.lower()
    if any(t in cmd_lower for t in ["nmap", "ping", "whois", "curl -si", "curl -s http"]):
        return "recon"
    if any(t in cmd_lower for t in ["gobuster", "wpscan", "nikto", "dirb", "ffuf", "enum"]):
        return "enum"
    if any(t in cmd_lower for t in ["sqlmap", "searchsploit", "msfconsole", "exploit", "reverse"]):
        return "exploit"
    if any(t in cmd_lower for t in ["linpeas", "pspy", "sudo", "suid", "cron", "privesc"]):
        return "privesc"
    return "recon"


# ---------------------------------------------------------------------------
# Plan Display
# ---------------------------------------------------------------------------

def _display_plan(steps: list[PlanStep], title: str = "Attack Plan") -> None:
    """Render the plan as a Rich table."""
    table = Table(
        title=f"[bold cyan]🗺️  {title}[/bold cyan]",
        show_lines=True,
        title_style="bold",
        padding=(0, 1),
    )
    table.add_column("#", style="bold", width=3, justify="center")
    table.add_column("Phase", style="cyan", width=8)
    table.add_column("Command", style="bold white", min_width=40)
    table.add_column("Rationale", style="dim", min_width=30)
    table.add_column("Status", width=8, justify="center")

    status_colors = {
        "pending": "[dim]⏳[/dim]",
        "running": "[yellow]🔄[/yellow]",
        "done": "[green]✅[/green]",
        "skipped": "[dim]⏭️[/dim]",
        "failed": "[red]❌[/red]",
    }

    for step in steps:
        table.add_row(
            str(step.step_num),
            step.phase,
            step.command,
            step.rationale,
            status_colors.get(step.status, "❓"),
        )

    console.print()
    console.print(table)
    console.print()


def _render_step_output(step: PlanStep, output: str, success: bool) -> None:
    """Render a step's execution output in a Rich panel."""
    color = "green" if success and output.strip() else "yellow" if success else "red"
    status = "✓" if success else "✗"
    preview = output[:800] if output else "(no output)"

    console.print(Panel(
        f"[dim]{preview}[/dim]",
        title=f"[{color}]{status}  Step {step.step_num}: {step.command.split()[0]}[/{color}]",
        title_align="left",
        subtitle=f"[dim]{step.rationale}[/dim]",
        subtitle_align="right",
        border_style=color,
        padding=(0, 1),
    ))


# ---------------------------------------------------------------------------
# Planner Engine
# ---------------------------------------------------------------------------

def run_planner(
    target: str,
    category: Optional[str],
    file_path: Optional[str],
    max_steps: int,
    session_id: str,
) -> tuple[str, str]:
    """Run the dynamic planning agent.

    Parameters
    ----------
    target : str
        Raw user input (IP, URL, domain, or full challenge description).
    category : str | None
        Forced category, or None for auto-detect.
    file_path : str | None
        Path to challenge file on Kali.
    max_steps : int
        Maximum number of plan steps.
    session_id : str
        Unique session identifier.

    Returns
    -------
    tuple[str, str]
        (final_hint, session_id)
    """
    from ctfgpt.solver import extract_target
    from ctfgpt.classifier import classify
    from ctfgpt.blackboard import Blackboard
    from ctfgpt.config import get_llm
    from ctfgpt.rag import ask as rag_ask

    # --- Extract target -----------------------------------------------------
    clean_target, challenge_desc = extract_target(target)

    if not clean_target:
        console.print("[red]❌ Could not detect an IP, URL, or domain in your input.[/red]")
        console.print("[yellow]   Tip: pass the target directly, e.g. ctfgpt plan 10.10.11.230[/yellow]")
        return "No actionable target found in input.", session_id

    console.print(f"  [dim]Extracted target:[/dim] [bold green]{clean_target}[/bold green]")
    if challenge_desc != clean_target:
        console.print(f"  [dim]Challenge context:[/dim] {challenge_desc[:120]}…")

    # --- Auto-detect category -----------------------------------------------
    if not category:
        category = classify(f"{challenge_desc} {file_path or ''}")
        console.print(f"  [dim]Auto-detected category:[/dim] [bold cyan]{category}[/bold cyan]")

    # --- Blackboard ---------------------------------------------------------
    bb = Blackboard(session_id=session_id, category=category, challenge_desc=challenge_desc)

    # --- Generate Plan via LLM ----------------------------------------------
    console.print()
    console.print(Rule("[bold cyan]Generating Attack Plan[/bold cyan]"))

    file_context = f"Challenge file: {file_path}" if file_path else "No challenge file provided."
    evidence_context = f"Existing evidence:\n{bb.summary()}" if bb.findings else "No prior evidence."
    ports_hint = _extract_open_ports_from_evidence(bb) or "(not yet scanned — run nmap first)"

    plan_prompt = _PLAN_GENERATION_PROMPT.format(
        challenge_desc=challenge_desc[:500],
        category=category,
        target=clean_target,
        file_context=file_context,
        evidence_context=evidence_context,
        ports_hint=ports_hint,
        max_steps=max_steps,
    )

    try:
        llm = get_llm(role="planner")
        raw_plan = llm.invoke(plan_prompt)
        if hasattr(raw_plan, "content"):
            raw_plan = raw_plan.content
        raw_plan = raw_plan.strip()
    except Exception as exc:
        console.print(f"[red]❌ Plan generation failed: {exc}[/red]")
        return f"Plan generation failed: {exc}", session_id

    steps = _parse_plan(raw_plan, clean_target)

    if not steps:
        console.print("[red]❌ LLM returned no parseable steps.[/red]")
        console.print(f"[dim]Raw output:\n{raw_plan[:500]}[/dim]")
        return "Plan generation returned no steps.", session_id

    # --- Show plan and get approval -----------------------------------------
    _display_plan(steps, title=f"Attack Plan for {clean_target} ({category})")

    console.print("  [dim]Review the plan above. You can approve, skip steps during execution, or quit.[/dim]")
    console.print("  [dim]Run? [Y/n/q] at each step. Type 'q' anytime to jump to summary.[/dim]\n")

    choice = input("  Approve and start execution? [Y/n]: ").strip().lower()
    if choice in ['n', 'no']:
        console.print("[dim]Plan rejected.[/dim]")
        return "Plan rejected by user.", session_id

    # --- MCP Client ---------------------------------------------------------
    try:
        from ctfgpt.mcp_client import get_mcp_client
        mcp = get_mcp_client()
    except Exception as exc:
        console.print(f"[red]❌ MCP client unavailable: {exc}[/red]")
        return f"Plan failed: MCP unavailable — {exc}", session_id

    # --- Execute plan adaptively --------------------------------------------
    current_idx = 0
    original_target = clean_target          # keep for retargeting logic
    hosts_mapped: set[str] = set()         # IPs that have already been mapped to /etc/hosts
    completed_commands: list[str] = []     # track all executed commands for /etc/hosts dedup
    # Cache observer LLM once — avoids re-instantiation on every step
    observer_llm = get_llm(role="observer")

    while current_idx < len(steps):
        step = steps[current_idx]
        step.status = "running"

        # Phase header
        if current_idx == 0 or steps[current_idx].phase != steps[current_idx - 1].phase:
            phase_colors = {"recon": "cyan", "enum": "blue", "exploit": "red", "privesc": "magenta"}
            color = phase_colors.get(step.phase, "white")
            console.print()
            console.print(Rule(f"[bold {color}]Phase: {step.phase.upper()}[/bold {color}]"))

        console.print(f"\n  [bold]Step {step.step_num}/{len(steps)}. {step.command.split()[0]}[/bold]  [dim]— {step.rationale}[/dim]")
        console.print(f"  [dim]$ {step.command}[/dim]")

        # User approval
        console.print("     [dim]Run? [Y/n/q (quit to summary)][/dim]", end=" ")
        try:
            user_choice = input().strip().lower()
        except EOFError:
            user_choice = ""  # non-interactive: auto-approve
        if user_choice in ['q', 'quit']:
            console.print("  [yellow]Plan aborted early. Jumping to summary...[/yellow]")
            step.status = "skipped"
            for remaining in steps[current_idx + 1:]:
                remaining.status = "skipped"
            break
        elif user_choice in ['n', 'no']:
            console.print("  [yellow]Skipped.[/yellow]")
            step.status = "skipped"
            current_idx += 1
            continue

        # Execute
        try:
            result = mcp.execute(step.command, timeout=120)
            stdout = result.get("stdout", "")
            stderr = result.get("stderr", "")
            success = result.get("success", True)

            output = stdout or stderr or "(no output)"
            step.output = output
            step.status = "done" if success else "failed"

            _render_step_output(step, output, success)

            weight = 0.8 if stdout.strip() else 0.3
            bb.write_finding(step.command.split()[0], step.command, output, weight=weight)
            completed_commands.append(step.command)

            # --- /etc/hosts redirect → retarget remaining steps --------------
            redirect = _extract_hosts_redirect(step.command)
            if redirect:
                old_ip, new_hostname = redirect
                hosts_mapped.add(old_ip)   # mark as already done
                if new_hostname != clean_target:
                    console.print()
                    console.print(
                        f"  [bold cyan]🔀 Redirect detected:[/bold cyan] "
                        f"[dim]{old_ip}[/dim] → [bold green]{new_hostname}[/bold green]"
                    )
                    console.print(
                        f"  [dim]Retargeting all remaining steps from "
                        f"{old_ip!r} to {new_hostname!r}…[/dim]"
                    )
                    clean_target = new_hostname
                    # Rewrite future step commands in-place
                    for future_step in steps[current_idx + 1:]:
                        future_step.command = future_step.command.replace(old_ip, new_hostname)
                    console.print()

        except Exception as exc:
            msg = str(exc)
            step.output = f"Error: {msg}"
            step.status = "failed"
            _render_step_output(step, f"Error: {msg}", False)
            bb.write_finding(step.command.split()[0], step.command, f"ERROR: {msg}", weight=0.1)
            completed_commands.append(step.command)

        # --- Re-plan after each step ----------------------------------------
        if current_idx < len(steps) - 1 and step.status in ("done", "failed"):

            # === Nmap-driven smart REPLAN ===
            # After any nmap step, extract actual open ports and replan
            is_nmap_step = step.command.strip().startswith("nmap")
            if is_nmap_step and step.status == "done" and step.output:
                open_ports = _extract_open_ports(step.output)
                if open_ports:
                    console.print()
                    console.print(
                        f"  [bold cyan]🔍 Nmap complete: found open ports:[/bold cyan] "
                        + ", ".join(open_ports)
                    )
                    # Force a REPLAN with port-aware context injected
                    port_context = _build_port_context(open_ports, clean_target)
                    nmap_replan = _replan(
                        llm=observer_llm,
                        category=category,
                        target=clean_target,
                        challenge_desc=challenge_desc,
                        step=step,
                        remaining_steps=steps[current_idx + 1:],
                        evidence=bb.summary(),
                        completed_commands=completed_commands,
                        force_context=port_context,
                    )
                    if nmap_replan["action"] in ("REPLAN", "INSERT"):
                        if nmap_replan["action"] == "REPLAN" and nmap_replan.get("steps"):
                            new_steps = nmap_replan["steps"]
                            console.print(f"  [bold yellow]🔄 Port-aware replan: {len(new_steps)} steps[/bold yellow]")
                            steps = steps[:current_idx + 1] + new_steps
                            for i, s in enumerate(steps):
                                s.step_num = i + 1
                            _display_plan(steps, title="Port-Aware Attack Plan")
                        # If INSERT, fall through to normal replan below
                        current_idx += 1
                        if step.status in ("done", "failed"):
                            time.sleep(0.3)
                        continue

            # === /etc/hosts dedup guard ===
            # If LLM wants to INSERT another /etc/hosts for an already-mapped IP, block it
            replan_decision = _replan(
                llm=observer_llm,
                category=category,
                target=clean_target,
                challenge_desc=challenge_desc,
                step=step,
                remaining_steps=steps[current_idx + 1:],
                evidence=bb.summary(),
                completed_commands=completed_commands,
            )

            # Guard: if LLM tries to INSERT another /etc/hosts for already-mapped IP → skip
            # Also: rewrite any /etc/hosts insert to use the idempotent grep-check form
            if replan_decision["action"] == "INSERT":
                proposed_cmd = replan_decision.get("step", {})
                if hasattr(proposed_cmd, "command"):
                    redirect_info = _extract_hosts_redirect(proposed_cmd.command)
                    if redirect_info:
                        ip, hostname = redirect_info
                        if ip in hosts_mapped:
                            console.print(
                                f"  [dim]🛡 /etc/hosts for {ip} already mapped — skipping duplicate INSERT.[/dim]"
                            )
                            replan_decision = {"action": "CONTINUE"}
                        else:
                            # Rewrite to be idempotent: grep before append
                            proposed_cmd.command = f"grep -q '{hostname}' /etc/hosts || echo '{ip} {hostname}' | sudo tee -a /etc/hosts"

            if replan_decision["action"] == "DONE":
                console.print("  [bold green]🎯 Planner decided: enough evidence collected![/bold green]")
                for remaining in steps[current_idx + 1:]:
                    remaining.status = "skipped"
                break

            elif replan_decision["action"] == "INSERT":
                new_step = replan_decision["step"]
                console.print(f"  [bold yellow]📌 Planner inserting new step:[/bold yellow] {new_step.command}")
                console.print(f"     [dim]Rationale: {new_step.rationale}[/dim]")
                steps.insert(current_idx + 1, new_step)
                for i, s in enumerate(steps):
                    s.step_num = i + 1

            elif replan_decision["action"] == "REPLAN":
                new_steps = replan_decision.get("steps", [])
                if new_steps:
                    console.print(f"  [bold yellow]🔄 Planner revised remaining plan ({len(new_steps)} steps)[/bold yellow]")
                    steps = steps[:current_idx + 1] + new_steps
                    for i, s in enumerate(steps):
                        s.step_num = i + 1
                    _display_plan(steps, title="Revised Attack Plan")

            # CONTINUE: do nothing special

        current_idx += 1
        # Only sleep when we actually ran a command (not when skipped)
        if step.status in ("done", "failed"):
            time.sleep(0.3)

    # --- Show final plan status ---------------------------------------------
    _display_plan(steps, title="Plan Execution Summary")

    # --- Generate grounded summary ------------------------------------------
    console.print()
    console.print(Rule("[bold green]Generating Solution Summary[/bold green]"))
    console.print("  [dim]Combining evidence with RAG writeup context…[/dim]\n")

    evidence_text = bb.summary()
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


# ---------------------------------------------------------------------------
# Port-Aware Helpers
# ---------------------------------------------------------------------------

def _extract_open_ports(nmap_output: str) -> list[str]:
    """Parse nmap output and return a list of open port description strings.

    Example return: ['22/tcp open ssh OpenSSH 7.4', '80/tcp open http Apache 2.4.6']
    """
    ports: list[str] = []
    for line in nmap_output.splitlines():
        # Match lines like: 22/tcp   open  ssh      OpenSSH 7.4
        m = re.match(r"^(\d+/tcp)\s+open\s+(\S+)(?:\s+(.+))?", line.strip())
        if m:
            port_proto = m.group(1)
            service = m.group(2)
            version = (m.group(3) or "").strip()
            ports.append(f"{port_proto} {service} {version}".strip())
    return ports


def _build_port_context(open_ports: list[str], target: str) -> str:
    """Build a human-readable port context block to inject into the replan prompt."""
    lines = [
        "=== NMAP SCAN COMPLETE ===",
        f"Target: {target}",
        "Open ports discovered:",
    ]
    for p in open_ports:
        lines.append(f"  {p}")
    lines.append("")
    lines.append("INSTRUCTION: REPLAN the remaining steps based on the above open ports.")
    lines.append("Use the TARGET hostname (not IP) in all web tool commands.")
    lines.append("Port-specific guidance:")
    lines.append("  22/tcp (SSH)  -> hydra SSH brute if creds unknown, or ssh-audit")
    lines.append("  80/tcp (HTTP) -> gobuster/ffuf dir scan, nikto, curl -sIL, wpscan if WordPress")
    lines.append("  443/tcp (HTTPS) -> same as HTTP but with https:// and -k flag")
    lines.append("  21/tcp (FTP)  -> ftp <target> with anonymous:anonymous")
    lines.append("  445/tcp (SMB) -> enum4linux -a, smbclient -L")
    lines.append("  3306/tcp (MySQL) -> mysql -h <target> -u root")
    return "\n".join(lines)


def _extract_open_ports_from_evidence(bb) -> str:
    """Search the blackboard for any previous nmap finding and return port summary."""
    for finding in reversed(getattr(bb, "findings", [])):
        tool = str(finding.get("tool", "")).lower()
        result = str(finding.get("result", ""))
        if tool == "nmap" and "open" in result:
            ports = _extract_open_ports(result)
            if ports:
                return "Known open ports: " + "; ".join(ports[:10])
    return ""


def _replan(
    llm,
    category: str,
    target: str,
    challenge_desc: str,
    step: PlanStep,
    remaining_steps: list[PlanStep],
    evidence: str,
    completed_commands: list[str] | None = None,
    force_context: str = "",
) -> dict:
    """Ask the LLM to adapt the plan based on the latest tool output.

    Returns a dict with 'action' key: CONTINUE | INSERT | REPLAN | DONE
    """
    remaining_plan = "\n".join(
        f"STEP {s.step_num}: {s.command} | RATIONALE: {s.rationale}"
        for s in remaining_steps
    )
    done_cmds = "\n".join(completed_commands or []) or "(none yet)"

    # If port context is injected, prepend it to the output for maximum LLM visibility
    enriched_output = step.output[:1500]
    if force_context:
        enriched_output = force_context + "\n\n" + enriched_output

    prompt = _REPLAN_PROMPT.format(
        category=category,
        target=target,
        challenge_desc=challenge_desc[:300],
        step_num=step.step_num,
        command=step.command,
        output=enriched_output,
        remaining_plan=remaining_plan or "(no remaining steps)",
        completed_commands=done_cmds,
        evidence=evidence[:1000],
    )

    try:
        raw = llm.invoke(prompt)
        if hasattr(raw, "content"):
            raw = raw.content
        raw = raw.strip()
    except Exception:
        return {"action": "CONTINUE"}

    raw_upper = raw.upper()

    # Parse decision — check INSERT first (most specific), then REPLAN, then DONE
    # Checking DONE last prevents false triggers when rationale contains the word "DONE"

    # Check for INSERT
    insert_match = re.search(
        r"INSERT\s*:\s*(.+?)\s*\|\s*RATIONALE\s*:\s*(.+)",
        raw,
        re.IGNORECASE,
    )
    if insert_match:
        cmd = insert_match.group(1).strip()
        rationale = insert_match.group(2).strip()
        return {
            "action": "INSERT",
            "step": PlanStep(
                step_num=0,  # will be renumbered
                command=cmd,
                rationale=rationale,
                phase=_detect_phase(cmd),
            ),
        }

    # Check for REPLAN
    if "REPLAN" in raw_upper:
        # Try to parse new steps from the response
        new_steps = _parse_plan(raw, target)
        if new_steps:
            return {"action": "REPLAN", "steps": new_steps}
        return {"action": "CONTINUE"}  # couldn't parse, just continue

    # Check for DONE (last, to avoid false positives in INSERT rationale)
    if re.search(r'(?m)^DONE\b', raw):
        return {"action": "DONE"}

    return {"action": "CONTINUE"}
