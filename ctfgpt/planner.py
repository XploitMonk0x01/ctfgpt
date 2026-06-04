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
You are an expert CTF attack planner. Given a challenge description, category,
and target information, generate a concrete numbered attack plan.

Challenge: {challenge_desc}
Category: {category}
Target: {target}
{file_context}
{evidence_context}

RULES:
1. Generate exactly {max_steps} steps, ordered by dependency (recon first, exploit last)
2. Each step MUST be a concrete shell command — no placeholders except the literal target
3. Use the actual target "{target}" in commands, not {{target}} or <target>
4. For web: always start with nmap, then include technology-specific tools
5. If evidence suggests WordPress, include wpscan
6. If evidence suggests a redirect to a hostname, include an /etc/hosts update step
7. Each step must have a clear rationale

OUTPUT FORMAT (strict — one step per line):
STEP 1: <shell command> | RATIONALE: <one sentence why>
STEP 2: <shell command> | RATIONALE: <one sentence why>
...

EXAMPLE:
STEP 1: nmap -sCV -T4 10.10.11.230 | RATIONALE: Discover open ports and services
STEP 2: curl -sI http://10.10.11.230 | RATIONALE: Check HTTP headers and tech stack
"""

_REPLAN_PROMPT = """\
You are a CTF attack planner adapting your plan based on new evidence.

Category: {category}
Target: {target}
Challenge: {challenge_desc}

Just completed Step {step_num}: {command}
Output:
{output}

Remaining plan:
{remaining_plan}

Evidence so far:
{evidence}

Based on the tool output, decide ONE of:
1. CONTINUE — the current plan is still good, proceed to the next step
2. INSERT: <shell command> | RATIONALE: <why> — add an urgent new step next
3. REPLAN — generate a completely new remaining plan (same format as original)
4. DONE — we have enough evidence to generate a final summary

IMPORTANT OBSERVATIONS:
- If the output shows a redirect to a hostname (e.g. "Location: http://www.smol.thm"),
  INSERT a step to add it to /etc/hosts and re-target remaining commands
- If nmap shows a specific service, adapt remaining steps to target that service
- If a flag pattern is found (flag{{...}}, HTB{{...}}, THM{{...}}), respond DONE
- If a step failed, suggest an alternative approach

Respond with EXACTLY one decision.
"""


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

    plan_prompt = _PLAN_GENERATION_PROMPT.format(
        challenge_desc=challenge_desc[:500],
        category=category,
        target=clean_target,
        file_context=file_context,
        evidence_context=evidence_context,
        max_steps=max_steps,
    )

    try:
        llm = get_llm()
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
        user_choice = input().strip().lower()
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

        except Exception as exc:
            msg = str(exc)
            step.output = f"Error: {msg}"
            step.status = "failed"
            _render_step_output(step, f"Error: {msg}", False)
            bb.write_finding(step.command.split()[0], step.command, f"ERROR: {msg}", weight=0.1)

        # --- Re-plan after each step ----------------------------------------
        if current_idx < len(steps) - 1:
            replan_decision = _replan(
                llm=get_llm(),
                category=category,
                target=clean_target,
                challenge_desc=challenge_desc,
                step=step,
                remaining_steps=steps[current_idx + 1:],
                evidence=bb.summary(),
            )

            if replan_decision["action"] == "DONE":
                console.print("  [bold green]🎯 Planner decided: enough evidence collected![/bold green]")
                for remaining in steps[current_idx + 1:]:
                    remaining.status = "skipped"
                break

            elif replan_decision["action"] == "INSERT":
                new_step = replan_decision["step"]
                console.print(f"  [bold yellow]📌 Planner inserting new step:[/bold yellow] {new_step.command}")
                console.print(f"     [dim]Rationale: {new_step.rationale}[/dim]")
                # Insert after current step
                steps.insert(current_idx + 1, new_step)
                # Renumber
                for i, s in enumerate(steps):
                    s.step_num = i + 1

            elif replan_decision["action"] == "REPLAN":
                new_steps = replan_decision["steps"]
                if new_steps:
                    console.print(f"  [bold yellow]🔄 Planner revised remaining plan ({len(new_steps)} steps)[/bold yellow]")
                    # Replace remaining steps
                    steps = steps[:current_idx + 1] + new_steps
                    # Renumber
                    for i, s in enumerate(steps):
                        s.step_num = i + 1
                    _display_plan(steps, title="Revised Attack Plan")

            # CONTINUE: do nothing special

        current_idx += 1
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


def _replan(
    llm,
    category: str,
    target: str,
    challenge_desc: str,
    step: PlanStep,
    remaining_steps: list[PlanStep],
    evidence: str,
) -> dict:
    """Ask the LLM to adapt the plan based on the latest tool output.

    Returns a dict with 'action' key: CONTINUE | INSERT | REPLAN | DONE
    """
    remaining_plan = "\n".join(
        f"STEP {s.step_num}: {s.command} | RATIONALE: {s.rationale}"
        for s in remaining_steps
    )

    prompt = _REPLAN_PROMPT.format(
        category=category,
        target=target,
        challenge_desc=challenge_desc[:300],
        step_num=step.step_num,
        command=step.command,
        output=step.output[:1500],
        remaining_plan=remaining_plan or "(no remaining steps)",
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

    # Parse decision
    if "DONE" in raw_upper:
        return {"action": "DONE"}

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

    return {"action": "CONTINUE"}
