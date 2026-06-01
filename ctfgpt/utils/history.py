"""Session history persistence for CTF-GPT.

Stores session metadata in a JSON file at ~/.ctfgpt/history.json.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from ctfgpt.config import HISTORY_PATH


def _load_history() -> list[dict]:
    """Load history from disk."""
    if HISTORY_PATH.exists():
        try:
            with open(HISTORY_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("sessions", [])
        except (json.JSONDecodeError, KeyError):
            return []
    return []


def _save_history(sessions: list[dict]) -> None:
    """Save history to disk."""
    HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(HISTORY_PATH, "w", encoding="utf-8") as f:
        json.dump({"sessions": sessions}, f, indent=2, default=str)


def save_session(
    query: str,
    category: str,
    mode: str = "hint",
    level: int = 1,
    response: str = "",
    session_id: Optional[str] = None,
    tools_run: Optional[list[str]] = None,
    iterations: int = 0,
    report_path: Optional[str] = None,
) -> str:
    """Save a session to history.

    Args:
        query: The challenge description or question.
        category: Detected/overridden category.
        mode: 'hint' or 'agent'.
        level: Hint level given (1-3).
        response: The hint/response text (truncated to 500 chars).
        session_id: Optional session ID. Auto-generated if None.
        tools_run: List of MCP tools executed (agent mode).
        iterations: Number of agent iterations.
        report_path: Path to session report (agent mode).

    Returns:
        The session ID.
    """
    if session_id is None:
        session_id = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    sessions = _load_history()
    sessions.append({
        "session_id": session_id,
        "timestamp": datetime.now().isoformat(),
        "query": query[:200],
        "category": category,
        "mode": mode,
        "level": level,
        "response": response[:500],
        "tools_run": tools_run or [],
        "iterations": iterations,
        "report": report_path,
    })

    _save_history(sessions)
    return session_id


def list_sessions() -> list[dict]:
    """Return all sessions, sorted by timestamp (newest last)."""
    sessions = _load_history()
    return sorted(sessions, key=lambda s: s.get("timestamp", ""))


def get_session(session_id: str) -> Optional[dict]:
    """Get a specific session by ID."""
    sessions = _load_history()
    for s in sessions:
        if s.get("session_id") == session_id:
            return s
    return None


def clear_history() -> None:
    """Clear all session history."""
    _save_history([])
