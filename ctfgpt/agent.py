"""LangGraph agent for CTF-GPT agent mode.

Implements a 5-node state graph:
    classify → plan → execute → observe → respond

The agent iteratively runs tools on Kali via MCP, writes findings
to the session blackboard, and delivers grounded hints using RAG
context plus live evidence.
"""

from __future__ import annotations

from datetime import datetime
from typing import TypedDict, Optional

from rich.console import Console

console = Console()


# ---------------------------------------------------------------------------
# Agent state
# ---------------------------------------------------------------------------

class AgentState(TypedDict):
    """Typed state passed between LangGraph nodes."""

    session_id: str                     # unique session id for blackboard persistence
    query: str                          # original challenge description
    category: str                       # detected category
    blackboard_summary: str             # current blackboard state as text
    rag_context: str                    # retrieved writeup context
    tool_output: str                    # last tool execution result
    next_action: str                    # "run_tool" | "respond" | "end"
    command: str                        # next MCP command to execute
    hint: str                           # final hint response
    iteration: int                      # current iteration count
    max_iterations: int                 # max allowed iterations
    findings: list[dict]                # accumulated finding dicts from blackboard
    error: str                          # error message if any


# ---------------------------------------------------------------------------
# Planning prompt template
# ---------------------------------------------------------------------------

_PLAN_PROMPT = """\
You are a CTF security analyst. Based on the challenge and evidence so far,
decide the next action.

Challenge: {query}
Category: {category}
Current Evidence: {blackboard_summary}
RAG Context: {rag_context}
Iteration: {iteration}/{max_iterations}
Previously executed commands: {executed_commands}

RULES:
1. Do NOT repeat any command from the "Previously executed commands" list.
2. If a command already produced useful output that answers the challenge,
   respond with RESPOND — do not run the same command again.
3. If a command failed, try a completely DIFFERENT tool or approach.
4. Only use TOOL if you need NEW information not already in Current Evidence.

Respond with EXACTLY one of:
TOOL: <command> — to run a NEW tool on Kali (must differ from previous)
RESPOND — if you have enough evidence to answer the challenge

If using TOOL, provide the exact command (e.g., TOOL: nmap -sV target)
"""

_OBSERVE_PROMPT = """\
Analyze this tool output for a {category} CTF challenge.
Command: {command}
Output: {tool_output}

Summarize the key findings in 1-2 sentences.
Is this finding useful? Rate: HIGH / MEDIUM / LOW
"""


# ---------------------------------------------------------------------------
# 1. classify_node
# ---------------------------------------------------------------------------

def classify_node(state: AgentState) -> dict:
    """Detect the CTF category from the challenge description.

    Initialises the iteration counter and sets up the blackboard
    summary for the first planning step.

    Parameters
    ----------
    state:
        Current agent state.

    Returns
    -------
    dict
        Partial state update with ``category`` and ``iteration``.
    """
    from ctfgpt.classifier import classify
    from ctfgpt.blackboard import Blackboard

    query = state["query"]
    session_id = state["session_id"]
    detected = classify(query)

    console.print(f"  [dim]Category detected:[/dim] [bold cyan]{detected}[/bold cyan]")

    # Initialize Blackboard
    bb = Blackboard(session_id=session_id, category=detected, challenge_desc=query)

    return {
        "category": detected,
        "iteration": 0,
        "blackboard_summary": bb.summary(),
        "findings": bb.findings,
        "error": "",
    }


# ---------------------------------------------------------------------------
# 2. plan_node
# ---------------------------------------------------------------------------

def plan_node(state: AgentState) -> dict:
    """Ask the LLM what action to take next.

    Builds a planning prompt with current evidence and RAG context,
    then parses the LLM response to extract either a tool command
    or a decision to respond.

    Parameters
    ----------
    state:
        Current agent state.

    Returns
    -------
    dict
        Partial state with ``next_action`` and ``command``.
    """
    from ctfgpt.config import get_llm

    # If we've hit max iterations, force a response
    if state["iteration"] >= state["max_iterations"]:
        console.print("  [yellow]Max iterations reached — generating response.[/yellow]")
        return {"next_action": "respond", "command": ""}

    # Retrieve RAG context if not already populated
    rag_context = state.get("rag_context", "")
    if not rag_context:
        try:
            from ctfgpt.rag import get_retriever, format_docs

            retriever = get_retriever(state["category"])
            docs = retriever.invoke(state["query"])
            rag_context = format_docs(docs) if docs else "No writeup data available."
        except Exception:
            rag_context = "RAG unavailable — no writeup context."

    # Build list of previously executed commands to prevent repetition
    executed_cmds = []
    for f in state.get("findings", []):
        cmd = f.get("command", "") if isinstance(f, dict) else ""
        if cmd and cmd not in executed_cmds:
            executed_cmds.append(cmd)
    executed_commands_str = ", ".join(executed_cmds) if executed_cmds else "(none yet)"

    prompt_text = _PLAN_PROMPT.format(
        query=state["query"],
        category=state["category"],
        blackboard_summary=state["blackboard_summary"],
        rag_context=rag_context,
        iteration=state["iteration"],
        max_iterations=state["max_iterations"],
        executed_commands=executed_commands_str,
    )

    try:
        llm = get_llm()
        response: str = llm.invoke(prompt_text)

        # LangChain models may return AIMessage or str
        if hasattr(response, "content"):
            response = response.content  # type: ignore[union-attr]

        response = response.strip()
    except Exception as exc:
        console.print(f"  [red]LLM planning failed: {exc}[/red]")
        return {"next_action": "respond", "command": "", "error": str(exc)}

    # Parse the LLM decision
    if response.upper().startswith("TOOL:"):
        command = response[5:].strip()
        # Prevent repeating the same command
        if command in executed_cmds:
            console.print(f"  [yellow]⚠  Agent tried to repeat: {command} — forcing response.[/yellow]")
            return {
                "next_action": "respond",
                "command": "",
                "rag_context": rag_context,
            }
        console.print(f"  [dim]Planned command:[/dim] [bold]{command}[/bold]")
        return {
            "next_action": "run_tool",
            "command": command,
            "rag_context": rag_context,
        }
    else:
        console.print("  [dim]Agent decided: respond with findings.[/dim]")
        return {
            "next_action": "respond",
            "command": "",
            "rag_context": rag_context,
        }


# ---------------------------------------------------------------------------
# 3. execute_node
# ---------------------------------------------------------------------------

def execute_node(state: AgentState) -> dict:
    """Execute the planned command on Kali via MCP.

    Validates the command for safety and scope before execution.
    If the command is blocked or MCP is unavailable, an error is
    recorded instead.

    Parameters
    ----------
    state:
        Current agent state (must contain ``command``).

    Returns
    -------
    dict
        Partial state with ``tool_output`` (or ``error``).
    """
    from ctfgpt.utils.safety import validate_command, validate_scope, sanitize_command

    command = state["command"]

    # Sanitize
    command = sanitize_command(command)

    # Safety check
    is_safe, reason = validate_command(command)
    if not is_safe:
        console.print(f"  [bold red]⛔ Command blocked: {reason}[/bold red]")
        return {
            "tool_output": "",
            "error": f"Command blocked: {reason}",
        }

    # Scope check (scope comes from config)
    try:
        from ctfgpt.config import load_config

        cfg = load_config()
        scope = cfg.get("mcp", {}).get("scope")
    except Exception:
        scope = None

    is_scoped, scope_reason = validate_scope(command, scope)
    if not is_scoped:
        console.print(f"  [bold red]⛔ Scope violation: {scope_reason}[/bold red]")
        return {
            "tool_output": "",
            "error": f"Scope violation: {scope_reason}",
        }

    # Execute via MCP
    try:
        from ctfgpt.mcp_client import get_mcp_client

        client = get_mcp_client()
        result_dict = client.execute(command)

        # extract output from the response dict
        # kali-server-mcp returns: stdout, stderr, return_code, success
        output = result_dict.get("stdout", "")
        err = result_dict.get("stderr", "")
        if err and not output:
            console.print(f"  [red]⚠  Remote error: {err}[/red]")
            return {"tool_output": "", "error": f"Remote: {err}"}

        result = output if output else err

        # Extract tool name for display
        tool_name = command.split()[0] if command.split() else "unknown"

        from ctfgpt.utils.rich_output import print_agent_iteration

        print_agent_iteration(
            iteration=state["iteration"] + 1,
            tool=tool_name,
            command=command,
            output=result,
            category=state["category"],
        )

        return {"tool_output": result, "error": ""}

    except ImportError:
        console.print("  [yellow]⚠  MCP client not available — skipping execution.[/yellow]")
        return {
            "tool_output": "",
            "error": "MCP client module not available.",
        }
    except ConnectionError as exc:
        console.print(f"  [red]⚠  MCP connection failed: {exc}[/red]")
        return {
            "tool_output": "",
            "error": f"MCP connection failed: {exc}",
        }
    except Exception as exc:
        console.print(f"  [red]⚠  Command execution failed: {exc}[/red]")
        return {
            "tool_output": "",
            "error": f"Execution failed: {exc}",
        }


# ---------------------------------------------------------------------------
# 4. observe_node
# ---------------------------------------------------------------------------

def observe_node(state: AgentState) -> dict:
    """Analyse tool output and update the blackboard.

    Sends the raw tool output to the LLM for summarisation and
    relevance rating, then updates the accumulated findings and
    blackboard summary.

    Parameters
    ----------
    state:
        Current agent state with ``tool_output`` populated.

    Returns
    -------
    dict
        Partial state with updated ``findings``, ``blackboard_summary``,
        ``iteration``, and ``next_action``.
    """
    from ctfgpt.config import get_llm
    from ctfgpt.blackboard import Blackboard

    bb = Blackboard(state["session_id"])
    iteration = state["iteration"] + 1

    tool_name = state["command"].split()[0] if state["command"] else "unknown"

    # If execution errored, record it so LLM knows to try something else
    if state.get("error"):
        console.print(f"  [dim yellow]Recording error on blackboard: {state['error']}[/dim yellow]")
        bb.write_finding(tool_name, state["command"], f"ERROR: {state['error']}", weight=0.1)
        return {
            "iteration": iteration,
            "next_action": "respond" if iteration >= state["max_iterations"] else "plan",
            "findings": bb.findings,
            "blackboard_summary": bb.summary(),
        }

    tool_output = state.get("tool_output", "")
    if not tool_output.strip():
        console.print("  [dim]Empty tool output — continuing.[/dim]")
        bb.write_finding(tool_name, state["command"], "No output.", weight=0.2)
        return {
            "iteration": iteration,
            "next_action": "plan" if iteration < state["max_iterations"] else "respond",
            "findings": bb.findings,
            "blackboard_summary": bb.summary(),
        }

    # Ask LLM to analyse the output
    prompt_text = _OBSERVE_PROMPT.format(
        category=state["category"],
        command=state["command"],
        tool_output=tool_output[:2000],  # truncate very long outputs
    )

    try:
        llm = get_llm()
        analysis: str = llm.invoke(prompt_text)

        if hasattr(analysis, "content"):
            analysis = analysis.content  # type: ignore[union-attr]

        analysis = analysis.strip()
    except Exception as exc:
        console.print(f"  [red]Observation LLM call failed: {exc}[/red]")
        analysis = f"Analysis unavailable ({exc})"

    # Parse rating from analysis
    rating_weight = 0.5  # MEDIUM default
    if "HIGH" in analysis.upper():
        rating_weight = 0.9
    elif "LOW" in analysis.upper():
        rating_weight = 0.2

    console.print(f"  [dim]Finding relevance:[/dim] [bold]{'HIGH' if rating_weight > 0.8 else 'MEDIUM' if rating_weight > 0.4 else 'LOW'}[/bold]")

    # Write to Blackboard
    bb.write_finding(tool_name, state["command"], analysis, weight=rating_weight)

    # Decide whether to continue or respond
    if rating_weight > 0.8:
        # HIGH relevance finding — we likely have the answer
        next_action = "respond"
        console.print("  [green]High-value evidence found — preparing response.[/green]")
    elif bb.has_sufficient_evidence(threshold=0.7) and iteration >= 2:
        next_action = "respond"
        console.print("  [green]Sufficient evidence gathered — preparing response.[/green]")
    elif iteration >= state["max_iterations"]:
        next_action = "respond"
    else:
        next_action = "plan"

    return {
        "iteration": iteration,
        "findings": bb.findings,
        "blackboard_summary": bb.summary(),
        "next_action": next_action,
    }


# ---------------------------------------------------------------------------
# 5. respond_node
# ---------------------------------------------------------------------------

def respond_node(state: AgentState) -> dict:
    """Generate the final grounded hint using RAG + blackboard evidence.

    Uses the full RAG pipeline at level 3 (detailed) since agent mode
    is inherently a "full approach" workflow.

    Parameters
    ----------
    state:
        Current agent state with accumulated evidence.

    Returns
    -------
    dict
        Partial state with ``hint`` and ``next_action`` set to ``"end"``.
    """
    from ctfgpt.rag import ask as rag_ask

    console.print("  [dim]Generating grounded hint from evidence…[/dim]")

    try:
        hint, _sources = rag_ask(
            query=state["query"],
            category=state["category"],
            level=3,  # agent mode = full approach
            blackboard_summary=state.get("blackboard_summary", ""),
        )
    except Exception as exc:
        console.print(f"  [red]RAG hint generation failed: {exc}[/red]")
        hint = (
            "I gathered some evidence but couldn't generate a complete hint. "
            f"Here's what I found:\n\n{state.get('blackboard_summary', 'No findings.')}"
        )

    return {"hint": hint, "next_action": "end"}


# ---------------------------------------------------------------------------
# Router functions
# ---------------------------------------------------------------------------

def route_after_plan(state: AgentState) -> str:
    """Route after the plan node based on the chosen action.

    Returns
    -------
    str
        ``"execute"`` if a tool should be run, ``"respond"`` otherwise.
    """
    if state["next_action"] == "run_tool":
        return "execute"
    return "respond"


def route_after_observe(state: AgentState) -> str:
    """Route after the observe node based on evidence sufficiency.

    Returns
    -------
    str
        ``"respond"`` if enough evidence is gathered, ``"plan"`` to
        continue the investigation loop.
    """
    if state["next_action"] == "respond":
        return "respond"
    return "plan"


# ---------------------------------------------------------------------------
# Graph builder
# ---------------------------------------------------------------------------

def build_agent_graph():
    """Construct and compile the 5-node LangGraph state graph.

    Graph topology::

        classify ─→ plan ─→ [execute ─→ observe ─→ plan] (loop)
                      │                           │
                      └─→ respond ←───────────────┘
                              │
                             END

    Returns
    -------
    CompiledGraph
        A compiled LangGraph ``StateGraph`` ready for invocation.
    """
    from langgraph.graph import StateGraph, END

    graph = StateGraph(AgentState)

    # Add nodes
    graph.add_node("classify", classify_node)
    graph.add_node("plan", plan_node)
    graph.add_node("execute", execute_node)
    graph.add_node("observe", observe_node)
    graph.add_node("respond", respond_node)

    # Static edges
    graph.add_edge("classify", "plan")
    graph.add_edge("execute", "observe")
    graph.add_edge("respond", END)

    # Conditional edges
    graph.add_conditional_edges("plan", route_after_plan, {
        "execute": "execute",
        "respond": "respond",
    })
    graph.add_conditional_edges("observe", route_after_observe, {
        "respond": "respond",
        "plan": "plan",
    })

    # Entry point
    graph.set_entry_point("classify")

    return graph.compile()


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_agent(
    query: str,
    category: Optional[str] = None,
    max_iterations: int = 8,
    scope: Optional[str] = None,
    dry_run: bool = False,
) -> tuple[str, str]:
    """Run the CTF agent against a challenge description.

    This is the main entry point for agent mode.  It builds the
    LangGraph state graph, initialises the agent state, and invokes
    the graph to iteratively gather evidence and produce a grounded
    hint.

    Parameters
    ----------
    query:
        The CTF challenge description or question.
    category:
        Optional category override.  If ``None``, auto-detected.
    max_iterations:
        Maximum number of tool execution iterations (default 8).
    scope:
        Optional scope directory to restrict file access.
    dry_run:
        If ``True``, only run classify + plan and show what would
        be executed without actually running any tools.

    Returns
    -------
    tuple[str, str]
        ``(hint_text, session_id)`` — the generated hint and the
        session identifier for history tracking.
    """
    from ctfgpt.utils.rich_output import print_hint
    from ctfgpt.utils.history import save_session

    session_id = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    console.print()
    console.print("[bold bright_white]🤖 CTF-GPT Agent Mode[/bold bright_white]")
    console.print(f"  [dim]Session:[/dim] {session_id}")
    console.print(f"  [dim]Max iterations:[/dim] {max_iterations}")
    if scope:
        console.print(f"  [dim]Scope:[/dim] {scope}")
    console.print()

    # Build initial state
    initial_state: AgentState = {
        "session_id": session_id,
        "query": query,
        "category": category or "",
        "blackboard_summary": "",
        "rag_context": "",
        "tool_output": "",
        "next_action": "",
        "command": "",
        "hint": "",
        "iteration": 0,
        "max_iterations": max_iterations,
        "findings": [],
        "error": "",
    }

    if dry_run:
        # Dry run: only classify and plan
        console.print("[yellow]🔍 Dry run — showing planned actions only.[/yellow]\n")

        classify_result = classify_node(initial_state)
        state_after_classify = {**initial_state, **classify_result}

        plan_result = plan_node(state_after_classify)
        state_after_plan = {**state_after_classify, **plan_result}

        if state_after_plan["command"]:
            console.print(f"\n  [bold]Would execute:[/bold] {state_after_plan['command']}")
        else:
            console.print("\n  [dim]Agent would respond without running tools.[/dim]")

        hint = f"[Dry run] Category: {state_after_classify['category']}, Planned: {state_after_plan.get('command', 'respond')}"

        save_session(
            query=query,
            category=state_after_classify["category"],
            mode="agent-dry",
            level=3,
            response=hint,
            session_id=session_id,
            iterations=0,
        )

        return hint, session_id

    # Full run: compile and invoke the graph
    try:
        compiled_graph = build_agent_graph()
    except ImportError as exc:
        console.print(f"[bold red]❌ LangGraph not installed: {exc}[/bold red]")
        console.print("[dim]Install with: pip install langgraph[/dim]")
        return "Agent mode requires langgraph. Install with: pip install langgraph", session_id

    try:
        final_state = compiled_graph.invoke(initial_state)
    except Exception as exc:
        console.print(f"[bold red]❌ Agent execution failed: {exc}[/bold red]")
        return f"Agent failed: {exc}", session_id

    hint = final_state.get("hint", "No hint generated.")
    category_result = final_state.get("category", "unknown")
    findings = final_state.get("findings", [])

    # Display the final hint
    print_hint(
        response=hint,
        category=category_result,
        level=3,
        sources=[],
    )

    # Collect tool commands that were run
    tools_run = [f.get("command", "") for f in findings if isinstance(f, dict)]

    # Save to history
    save_session(
        query=query,
        category=category_result,
        mode="agent",
        level=3,
        response=hint,
        session_id=session_id,
        tools_run=tools_run,
        iterations=final_state.get("iteration", 0),
    )

    console.print(f"\n  [dim]Session saved: {session_id}[/dim]")

    return hint, session_id
