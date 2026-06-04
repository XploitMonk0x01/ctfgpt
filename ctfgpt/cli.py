"""CTF-GPT CLI — AI-powered CTF assistant with RAG + Kali MCP integration.

Entry point: `ctfgpt` command, registered via pyproject.toml [project.scripts].
"""

import os
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel

from ctfgpt import __version__

# Force UTF-8 on Windows
if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except (AttributeError, OSError):
        pass

console = Console(force_terminal=True)
app = typer.Typer(
    name="ctfgpt",
    help="AI-powered CTF assistant with RAG pipeline and Kali MCP integration.",
    no_args_is_help=True,
    rich_markup_mode="rich",
    add_completion=False,
)


# ---------------------------------------------------------------------------
# ask — main command (hint mode in Phase 1, agent mode in Phase 3)
# ---------------------------------------------------------------------------
@app.command()
def ask(
    query: str = typer.Argument(..., help="Challenge description or question"),
    level: int = typer.Option(
        None, "--level", "-l", min=1, max=3,
        help="Hint level: 1=nudge, 2=technique, 3=full approach",
    ),
    category: Optional[str] = typer.Option(
        None, "--category", "-c",
        help="Override category detection (forensics|web|crypto|pwn|reversing|osint)",
    ),
    file: Optional[Path] = typer.Option(
        None, "--file", "-f", exists=True, readable=True,
        help="Upload a challenge file to workspace",
    ),
    agent: bool = typer.Option(
        False, "--agent", "-a",
        help="Enable agentic mode with Kali MCP tool execution",
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run",
        help="Show planned tool calls without executing (agent mode)",
    ),
    scope: Optional[str] = typer.Option(
        None, "--scope",
        help="Restrict file operations to this path (agent mode)",
    ),
    max_iter: int = typer.Option(
        8, "--max-iter",
        help="Maximum agent iterations (agent mode)",
    ),
) -> None:
    """Ask CTF-GPT for hints on a challenge.

    In hint mode (default), provides progressive hints at levels 1-3.
    In agent mode (--agent), runs tools on Kali and builds evidence.
    """
    from ctfgpt.utils.rich_output import print_banner, print_hint, print_error, create_spinner
    from ctfgpt.classifier import classify, get_confidence
    from ctfgpt.config import load_config, CATEGORIES

    print_banner()

    # Load config for default hint level
    config = load_config()
    if level is None:
        level = config.get("hints", {}).get("default_level", 1)

    # Validate category override
    if category and category not in CATEGORIES:
        print_error(
            "Invalid Category",
            f"'{category}' is not a valid category. "
            f"Choose from: {', '.join(CATEGORIES)}",
        )
        raise typer.Exit(1)

    # ── Agent mode ─────────────────────────────────────────────────────
    if agent:
        from ctfgpt.utils.safety import confirm_agent_mode

        if not confirm_agent_mode(query):
            console.print("[dim]Agent mode cancelled.[/dim]")
            raise typer.Exit(0)

        try:
            from ctfgpt.agent import run_agent

            hint, session_id = run_agent(
                query=query,
                category=category,
                max_iterations=max_iter,
                scope=scope,
                dry_run=dry_run,
            )

            if hint:
                from ctfgpt.utils.rich_output import print_hint
                print_hint(hint, category or "forensics", 3)

            console.print(
                f"\n  [dim]Session saved: {session_id}[/dim]"
                f"\n  [dim]Run: ctfgpt report --session {session_id}[/dim]\n"
            )
        except Exception as e:
            print_error("Agent Error", str(e))
            raise typer.Exit(1)

        return

    # ── Hint mode ─────────────────────────────────────────────────────
    # Step 1: Classify category
    with create_spinner("Detecting challenge category..."):
        if category:
            detected = category
            confidence = 1.0
        else:
            detected, confidence = get_confidence(query)

    console.print(
        f"  [dim]Category:[/dim] [bold {_cat_color(detected)}]{detected}[/bold {_cat_color(detected)}]"
        f"  [dim](confidence: {confidence:.0%})[/dim]\n"
    )

    # Step 2: RAG retrieval + LLM hint
    with create_spinner(f"Generating level {level} hint..."):
        try:
            from ctfgpt.rag import ask as rag_ask
            response, sources = rag_ask(
                query=query,
                category=detected,
                level=level,
                blackboard_summary="",
            )
        except Exception as e:
            print_error("LLM Error", str(e))
            raise typer.Exit(1)

    # Step 3: Display hint
    print_hint(response, detected, level, sources)

    # Step 4: Offer to go deeper
    if level < 3:
        console.print(
            f"\n  [dim]> Want more detail? Run:[/dim] "
            f"[bold]ctfgpt ask \"{query[:40]}...\" --level {level + 1}[/bold]\n"
        )

    # Step 5: Save to history
    try:
        from ctfgpt.utils.history import save_session
        save_session(
            query=query,
            category=detected,
            mode="hint",
            level=level,
            response=response,
        )
    except Exception:
        pass  # history saving is best-effort



# ---------------------------------------------------------------------------
# solve — structured category-aware attack playbook
# ---------------------------------------------------------------------------
@app.command()
def solve(
    target: Optional[str] = typer.Argument(
        None,
        help="IP address, URL, hostname, or cipher text to solve",
    ),
    category: Optional[str] = typer.Option(
        None, "--category", "-c",
        help="Force category: web | pwn | forensics | crypto | reversing | osint",
    ),
    file: Optional[str] = typer.Option(
        None, "--file", "-f",
        help="Path to the challenge file on Kali (e.g. /home/kali/ctf/challenge.exe)",
    ),
    max_steps: int = typer.Option(
        10, "--max-steps", "-n",
        help="Maximum number of playbook steps to execute (default: 10)",
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run",
        help="Print the planned steps without executing them",
    ),
    scope: Optional[str] = typer.Option(
        None, "--scope",
        help="Restrict file operations to this Kali path",
    ),
) -> None:
    """Run a structured, category-aware attack playbook against a CTF target.

    Unlike --agent (open-ended), solve runs a predefined sequence of the
    right tools for the detected category in the right order:
    recon → enumeration → analysis → exploit → summary.

    Examples:

      ctfgpt solve 10.10.11.230              # auto-detect, run full playbook
      ctfgpt solve http://target.thm --category web
      ctfgpt solve /home/kali/ctf/flag.png --category forensics
      ctfgpt solve "KHOOR ZRUOG" --category crypto
      ctfgpt solve 10.10.11.230 --dry-run   # preview steps only
    """
    from ctfgpt.utils.rich_output import print_banner, print_hint, print_error
    from ctfgpt.utils.safety import confirm_agent_mode
    from ctfgpt.utils.history import save_session

    print_banner()

    if not target:
        target = typer.prompt("Enter target (IP, URL, domain, or challenge description)")
        if not target:
            console.print("[red]❌ Target is required to run solve mode.[/red]")
            raise typer.Exit(1)
            
        # QoL fix: if the user pastes "--category web" into the prompt, parse it
        import re
        cat_match = re.search(r'--category\s+([a-zA-Z0-9_-]+)', target)
        if cat_match:
            category = cat_match.group(1).lower()
            target = target.replace(cat_match.group(0), "").strip()

    # Confirmation panel
    if not dry_run:
        from ctfgpt.solver import extract_target
        clean_target, challenge_desc = extract_target(target)
        display_desc = (challenge_desc[:120] + "...") if len(challenge_desc) > 120 else challenge_desc
        
        body = (
            "[bold yellow]⚠  Solve mode will execute a security tool playbook on your Kali VM.[/bold yellow]\n\n"
            f"[bold]Target:[/bold] {clean_target or 'None detected'}\n"
        )
        if challenge_desc != clean_target:
             body += f"[bold]Input Context:[/bold] {display_desc}\n"
        
        body += f"[bold]Category:[/bold] {category or 'auto-detect'}\n"
        body += f"[bold]Max Steps:[/bold] {max_steps}\n"
        
        if file:
            body += f"[bold]File:[/bold] {file}\n"

        console.print()
        console.print(Panel(
            body,
            title="[bold yellow]🎯 CTF-GPT Solve Mode[/bold yellow]",
            title_align="left",
            border_style="yellow",
            padding=(1, 2),
        ))
        console.print()

        if not typer.confirm("[yellow]Continue with solve mode?[/yellow]", default=False):
            console.print("[dim]Solve mode cancelled.[/dim]")
            raise typer.Exit(0)

    # Generate session ID
    from datetime import datetime
    session_id = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    console.print(f"  [dim]Session:[/dim] {session_id}\n")

    # Run the solver
    try:
        from ctfgpt.solver import run_solver
        hint, session_id = run_solver(
            target=target,
            category=category,
            file_path=file,
            max_steps=max_steps,
            dry_run=dry_run,
            scope=scope,
            session_id=session_id,
        )
    except Exception as exc:
        print_error("Solver Error", str(exc))
        raise typer.Exit(1)

    # Display final hint
    if hint:
        print_hint(hint, category or "general", level=3)

    # Save session
    try:
        save_session(
            query=target,
            category=category or "general",
            mode="solve",
            level=3,
            response=hint,
            session_id=session_id,
        )
    except Exception:
        pass

    console.print(
        f"\n  [dim]Session saved: {session_id}[/dim]"
        f"\n  [dim]Run: ctfgpt report --session {session_id}[/dim]\n"
    )


# ---------------------------------------------------------------------------
# plan — dynamic LLM-driven attack planner
# ---------------------------------------------------------------------------
@app.command()
def plan(
    target: Optional[str] = typer.Argument(
        None,
        help="IP address, URL, domain, or challenge description",
    ),
    category: Optional[str] = typer.Option(
        None, "--category", "-c",
        help="Force category: web | pwn | forensics | crypto | reversing | osint",
    ),
    file: Optional[str] = typer.Option(
        None, "--file", "-f",
        help="Path to the challenge file on Kali",
    ),
    max_steps: int = typer.Option(
        8, "--max-steps", "-n",
        help="Maximum number of plan steps to generate (default: 8)",
    ),
) -> None:
    """Generate and execute an adaptive, LLM-driven attack plan.

    Unlike 'solve' (static playbook) or 'ask --agent' (open-ended),
    'plan' asks the LLM to generate a concrete attack plan FIRST,
    shows it to you for approval, then executes step by step with
    adaptive re-planning after each tool output.

    The planner can INSERT new steps, REPLAN remaining steps, or
    decide it's DONE early if it finds the flag.

    Examples:

      ctfgpt plan 10.10.11.230 --category web
      ctfgpt plan smol.thm --category web
      ctfgpt plan                                  # prompts for target
      ctfgpt plan "challenge description with IP"
    """
    from ctfgpt.utils.rich_output import print_banner, print_hint, print_error

    print_banner()

    if not target:
        target = typer.prompt("Enter target (IP, URL, domain, or challenge description)")
        if not target:
            console.print("[red]❌ Target is required.[/red]")
            raise typer.Exit(1)

        # Parse --category from prompt input if present
        import re as _re
        cat_match = _re.search(r'--category\s+([a-zA-Z0-9_-]+)', target)
        if cat_match:
            category = cat_match.group(1).lower()
            target = target.replace(cat_match.group(0), "").strip()

    # Confirmation panel
    from ctfgpt.solver import extract_target
    clean_target, challenge_desc = extract_target(target)
    display_desc = (challenge_desc[:120] + "...") if len(challenge_desc) > 120 else challenge_desc

    body = (
        "[bold cyan]🗺️  Plan mode will generate an LLM attack plan and execute it on your Kali VM.[/bold cyan]\n\n"
        f"[bold]Target:[/bold] {clean_target or 'None detected'}\n"
    )
    if challenge_desc != clean_target:
        body += f"[bold]Context:[/bold] {display_desc}\n"
    body += f"[bold]Category:[/bold] {category or 'auto-detect'}\n"
    body += f"[bold]Max Steps:[/bold] {max_steps}\n"
    if file:
        body += f"[bold]File:[/bold] {file}\n"

    console.print()
    console.print(Panel(
        body,
        title="[bold cyan]🗺️  CTF-GPT Plan Mode[/bold cyan]",
        title_align="left",
        border_style="cyan",
        padding=(1, 2),
    ))
    console.print()

    if not typer.confirm("[cyan]Continue with plan mode?[/cyan]", default=True):
        console.print("[dim]Plan mode cancelled.[/dim]")
        raise typer.Exit(0)

    # Generate session ID
    from datetime import datetime
    session_id = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    console.print(f"  [dim]Session:[/dim] {session_id}\n")

    # Run the planner
    try:
        from ctfgpt.planner import run_planner
        hint, session_id = run_planner(
            target=target,
            category=category,
            file_path=file,
            max_steps=max_steps,
            session_id=session_id,
        )
    except Exception as exc:
        print_error("Planner Error", str(exc))
        raise typer.Exit(1)

    # Display final hint
    if hint:
        print_hint(hint, category or "general", level=3)

    # Save session
    try:
        from ctfgpt.utils.history import save_session
        save_session(
            query=target,
            category=category or "general",
            mode="plan",
            level=3,
            response=hint,
            session_id=session_id,
        )
    except Exception:
        pass

    console.print(
        f"\n  [dim]Session saved: {session_id}[/dim]"
        f"\n  [dim]Run: ctfgpt report --session {session_id}[/dim]\n"
    )

# ---------------------------------------------------------------------------
# auto — multi-agent autonomous mode
# ---------------------------------------------------------------------------
@app.command()
def auto(
    target: Optional[str] = typer.Argument(
        None,
        help="IP address, URL, domain, or challenge description",
    ),
    category: Optional[str] = typer.Option(
        None, "--category", "-c",
        help="Force category: web | pwn | forensics | crypto | reversing | osint",
    ),
) -> None:
    """Run in fully autonomous multi-agent mode.
    
    A Router agent will analyze the target and delegate tasks to 
    specialized sub-agents (Recon, Exploit, PrivEsc).
    """
    from ctfgpt.utils.rich_output import print_banner, print_error

    print_banner()

    if not target:
        target = typer.prompt("Enter target (IP, URL, domain, or challenge description)")
        if not target:
            console.print("[red]❌ Target is required.[/red]")
            raise typer.Exit(1)
            
    # Extract target
    from ctfgpt.solver import extract_target
    clean_target, challenge_desc = extract_target(target)
    
    if not category:
        from ctfgpt.classifier import classify
        category = classify(challenge_desc)

    console.print(Panel(
        f"[bold]Target:[/bold] {clean_target or 'None'}\n"
        f"[bold]Category:[/bold] {category}",
        title="[bold cyan]🤖 CTF-GPT Auto Mode[/bold cyan]",
        border_style="cyan"
    ))

    if not typer.confirm("[cyan]Start multi-agent attack?[/cyan]", default=True):
        raise typer.Exit(0)

    from datetime import datetime
    session_id = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    
    try:
        from ctfgpt.agents.router import MultiAgentRouter
        router = MultiAgentRouter(
            target=clean_target or target,
            category=category,
            session_id=session_id
        )
        result = router.run()
        console.print(f"\n[bold green]Final Result:[/bold green]\n{result}")
    except Exception as exc:
        print_error("Multi-Agent Error", str(exc))
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# ingest — build/update the vector knowledge base
# ---------------------------------------------------------------------------
@app.command()
def ingest(
    source: str = typer.Option(
        "ctftime", "--source", "-s",
        help="Data source: ctftime | github | hacktricks | hackingarticles | pdf | all",
    ),
    limit: int = typer.Option(
        500, "--limit", "-n",
        help="Maximum writeups to scrape per source",
    ),
    pdf_dir: Optional[str] = typer.Option(
        None, "--pdf-dir", "-p",
        help="Directory containing PDF writeups to ingest",
    ),
    github_repos: Optional[str] = typer.Option(
        None, "--repos",
        help="Comma-separated GitHub repos (owner/name) to ingest",
    ),
    github_urls: Optional[str] = typer.Option(
        None, "--urls",
        help="Comma-separated raw GitHub URLs to ingest",
    ),
) -> None:
    """Scrape CTF writeups, chunk, embed, and store in ChromaDB."""
    from ctfgpt.utils.rich_output import print_banner, print_error, create_spinner

    print_banner()
    console.print(f"[bold]>> Ingesting data from:[/bold] {source}  (limit: {limit})\n")

    valid_sources = {"ctftime", "github", "hacktricks", "hackingarticles", "pdf", "all"}
    if source not in valid_sources:
        print_error("Invalid Source", f"Choose from: {', '.join(sorted(valid_sources))}")
        raise typer.Exit(1)

    sources_to_run = (
        [source] if source != "all"
        else ["ctftime", "github", "hacktricks", "hackingarticles"]
    )

    from ctfgpt.config import DATA_DIR
    active_dirs = []

    for src in sources_to_run:
        console.rule(f"[bold]{src.upper()}[/bold]")

        if src == "ctftime":
            try:
                from ingestion.scraper_ctftime import run_scraper
                run_scraper(limit=limit)
                active_dirs.append(DATA_DIR / "ctftime")
            except Exception as e:
                print_error(f"Scraper Error ({src})", str(e))
                continue

        elif src == "github":
            try:
                from ingestion.loader_github import run_github_loader
                repos = github_repos.split(",") if github_repos else None
                urls = github_urls.split(",") if github_urls else None
                run_github_loader(repos=repos, urls=urls, limit=limit)
                active_dirs.append(DATA_DIR / "github")
            except Exception as e:
                print_error(f"GitHub Loader Error ({src})", str(e))
                continue

        elif src == "hacktricks":
            try:
                from ingestion.scraper_hacktricks import run_hacktricks_loader
                run_hacktricks_loader(limit=limit)
                active_dirs.append(DATA_DIR / "hacktricks")
            except Exception as e:
                print_error(f"HackTricks Error ({src})", str(e))
                continue

        elif src == "hackingarticles":
            try:
                from ingestion.scraper_hackingarticles import run_hackingarticles_scraper
                run_hackingarticles_scraper(limit=limit)
                active_dirs.append(DATA_DIR / "hackingarticles")
            except Exception as e:
                print_error(f"HackingArticles Error ({src})", str(e))
                continue

        elif src == "pdf":
            if not pdf_dir:
                print_error("PDF Source", "Use --pdf-dir to specify the PDF directory")
                continue
            try:
                from ingestion.loader_pdf import run_pdf_loader
                run_pdf_loader(pdf_dir=pdf_dir)
                active_dirs.append(DATA_DIR / "pdf")
            except Exception as e:
                print_error(f"PDF Loader Error ({src})", str(e))
                continue

    # Chunk and embed
    console.print()
    console.rule("[bold]Chunking & Embedding[/bold]")

    try:
        from ingestion.embedder import run_full_ingestion
        run_full_ingestion(source_dirs=active_dirs)
    except Exception as e:
        print_error("Embedding Error", str(e))
        raise typer.Exit(1)

    console.print("\n[bold green][+] Ingestion complete![/bold green]\n")


# ---------------------------------------------------------------------------
# config — view/set configuration
# ---------------------------------------------------------------------------
@app.command(name="config")
def config_cmd(
    show: bool = typer.Option(
        False, "--show",
        help="Show current configuration",
    ),
    set_key: Optional[str] = typer.Option(
        None, "--set",
        help="Config key to set (dot notation, e.g. 'llm_mode' or 'agent.max_iterations')",
    ),
    set_val: Optional[str] = typer.Option(
        None, "--value",
        help="Value to set for the config key",
    ),
) -> None:
    """View or modify CTF-GPT configuration."""
    from ctfgpt.config import load_config, get_config_value, set_config_value
    from ctfgpt.utils.rich_output import print_error
    from rich.syntax import Syntax
    import yaml

    config = load_config()

    if show or (set_key is None):
        # Pretty-print the config
        config_str = yaml.dump(config, default_flow_style=False, sort_keys=False)
        syntax = Syntax(config_str, "yaml", theme="monokai", line_numbers=False)
        console.print()
        console.print("[bold]Current Configuration[/bold]\n")
        console.print(syntax)
        console.print()
        return

    if set_key and set_val is None:
        # Show specific key
        value = get_config_value(set_key)
        if value is not None:
            console.print(f"  {set_key} = {value}")
        else:
            print_error("Key Not Found", f"No config key '{set_key}'")
        return

    if set_key and set_val:
        try:
            set_config_value(set_key, set_val)
            console.print(f"  [green][+][/green] Set [bold]{set_key}[/bold] = {set_val}")
        except Exception as e:
            print_error("Config Error", str(e))


# ---------------------------------------------------------------------------
# status — system health check
# ---------------------------------------------------------------------------
@app.command()
def status() -> None:
    """Check ChromaDB, LLM, and MCP server connectivity."""
    from ctfgpt.utils.rich_output import print_banner, print_status, print_error
    from ctfgpt.config import load_config

    print_banner()

    config = load_config()
    llm_mode = os.getenv("LLM_MODE", config.get("llm_mode", "cloud"))

    # Check ChromaDB
    db_ok = False
    db_stats: dict[str, int] = {}
    try:
        from ctfgpt.rag import check_db_status
        db_ok, db_stats = check_db_status()
    except Exception:
        pass

    # Check LLM
    llm_ok = False
    llm_detail = llm_mode
    try:
        if llm_mode == "cloud":
            provider = config.get("cloud", {}).get("provider", "groq")
            if provider == "deepseek":
                llm_ok = bool(os.getenv("DEEPSEEK_API_KEY"))
                model = config.get("deepseek", {}).get("model", "deepseek-chat")
                llm_detail = f"deepseek ({model})"
            else:
                llm_ok = bool(os.getenv("GROQ_API_KEY"))
                model = config.get("cloud", {}).get("model", "llama-3.3-70b-versatile")
                llm_detail = f"groq ({model})"
        else:
            # Check if Ollama is reachable
            import requests
            base_url = config.get("local", {}).get("base_url", "http://localhost:11434")
            r = requests.get(f"{base_url}/api/tags", timeout=3)
            llm_ok = r.status_code == 200
            llm_detail = f"ollama ({config.get('local', {}).get('model', 'mistral')})"
    except Exception:
        pass

    # Check MCP
    mcp_ok = False
    mcp_enabled = config.get("mcp", {}).get("enabled", False)
    if mcp_enabled:
        try:
            mcp_host = config.get("mcp", {}).get("host", "localhost")
            mcp_port = config.get("mcp", {}).get("port", 5000)
            import requests
            r = requests.get(f"http://{mcp_host}:{mcp_port}/health", timeout=3)
            mcp_ok = r.status_code == 200
        except Exception:
            pass

    print_status(db_ok, db_stats, llm_ok, llm_detail, mcp_ok)


# ---------------------------------------------------------------------------
# history — session history (Phase 2 placeholder)
# ---------------------------------------------------------------------------
@app.command()
def history() -> None:
    """View past CTF-GPT sessions."""
    try:
        from ctfgpt.utils.history import list_sessions
        from rich.table import Table

        sessions = list_sessions()
        if not sessions:
            console.print("[dim]No sessions yet. Run [bold]ctfgpt ask[/bold] to start.[/dim]")
            return

        table = Table(title="Session History", show_lines=False)
        table.add_column("Date", style="dim")
        table.add_column("Category", style="bold")
        table.add_column("Mode")
        table.add_column("Level", justify="center")
        table.add_column("Query", max_width=50)

        for s in sessions[-20:]:  # show last 20
            cat_color = _cat_color(s.get("category", ""))
            table.add_row(
                s.get("timestamp", "")[:16],
                f"[{cat_color}]{s.get('category', '?')}[/{cat_color}]",
                s.get("mode", "hint"),
                str(s.get("level", 1)),
                s.get("query", "")[:50],
            )

        console.print()
        console.print(table)
        console.print()
    except Exception:
        console.print("[dim]Session history will be available in Phase 2.[/dim]")


# ---------------------------------------------------------------------------
# report — session report generator
# ---------------------------------------------------------------------------
@app.command()
def report(
    session: Optional[str] = typer.Option(
        None, "--session",
        help="Session ID (e.g. 2024-01-15_14-32-05)",
    ),
    open_editor: bool = typer.Option(
        False, "--open",
        help="Open report in default editor",
    ),
    list_all: bool = typer.Option(
        False, "--list",
        help="List all available reports",
    ),
) -> None:
    """Generate or view a session report."""
    from ctfgpt.report import (
        generate_report, print_report, list_reports, get_latest_session_id,
    )

    # List mode
    if list_all:
        reports = list_reports()
        if not reports:
            console.print("[dim]No reports found. Run agent mode first.[/dim]")
            return

        from rich.table import Table
        table = Table(title="Session Reports", title_style="bold bright_white")
        table.add_column("Session ID", style="bold")
        table.add_column("Category")
        table.add_column("Path", style="dim")

        for r in reports[:20]:
            cat_color = _cat_color(r.get("category", ""))
            table.add_row(
                r["session_id"],
                f"[{cat_color}]{r['category']}[/{cat_color}]",
                r["path"],
            )

        console.print()
        console.print(table)
        console.print()
        return

    # Determine session
    session_id = session or get_latest_session_id()
    if not session_id:
        console.print("[dim]No sessions found. Run agent mode first.[/dim]")
        return

    console.print(f"[dim]Generating report for session: {session_id}[/dim]\n")

    try:
        report_md = generate_report(session_id)
        print_report(report_md)

        from ctfgpt.config import SESSIONS_DIR
        report_path = SESSIONS_DIR / session_id / "report.md"
        console.print(f"[dim]Report saved: {report_path}[/dim]\n")

        if open_editor:
            import subprocess
            subprocess.Popen(["notepad.exe", str(report_path)])
    except Exception as e:
        from ctfgpt.utils.rich_output import print_error
        print_error("Report Error", str(e))


# ---------------------------------------------------------------------------
# tools — MCP tool list (Phase 4 placeholder)
# ---------------------------------------------------------------------------
@app.command()
def tools() -> None:
    """List available MCP tools and connection status."""
    from ctfgpt.config import load_config

    config = load_config()
    mcp_enabled = config.get("mcp", {}).get("enabled", False)

    if not mcp_enabled:
        console.print(
            "[yellow]MCP is disabled in config.[/yellow]\n"
            "[dim]Enable with: ctfgpt config --set mcp.enabled --value true[/dim]\n"
            "[dim]Then start kali-server-mcp on your Kali VM and SSH tunnel.[/dim]"
        )
        return

    try:
        from ctfgpt.mcp_client import get_mcp_client
        from rich.table import Table

        with get_mcp_client() as client:
            connected = client.check_connection()
            if not connected:
                console.print("[red][-] MCP server not reachable.[/red]")
                console.print("[dim]Ensure SSH tunnel is up and kali-server-mcp is running.[/dim]")
                return

            tool_list = client.list_tools()
            table = Table(title="MCP Kali Tools", title_style="bold bright_white")
            table.add_column("#", justify="right", style="dim")
            table.add_column("Tool", style="bold cyan")

            for i, tool in enumerate(tool_list, 1):
                table.add_row(str(i), tool)

            console.print()
            console.print(f"[green][+] Connected[/green] to MCP server")
            console.print(table)
            console.print(f"\n[dim]{len(tool_list)} tools available[/dim]")
    except Exception as e:
        console.print(f"[red][-] Error: {e}[/red]")


# ---------------------------------------------------------------------------
# version callback
# ---------------------------------------------------------------------------
def _version_callback(value: bool) -> None:
    if value:
        console.print(f"[bold]CTF-GPT[/bold] v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", "-v",
        help="Show version and exit",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    """CTF-GPT: AI-powered CTF assistant with RAG + Kali MCP."""
    pass


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _cat_color(category: str) -> str:
    """Get Rich color for a category."""
    colors = {
        "forensics": "cyan",
        "web": "red",
        "crypto": "yellow",
        "pwn": "magenta",
        "reversing": "green",
        "osint": "blue",
    }
    return colors.get(category, "white")
