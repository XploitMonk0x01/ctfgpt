"""Session blackboard with pheromone-weighted evidence.

The blackboard tracks tool outputs during an agent session, weighting
findings by their relevance.  High-weight findings bubble up to inform
subsequent LLM calls; low-weight findings decay and eventually move
to ``dead_ends``.

Persisted as JSON at ``~/.ctfgpt/sessions/{session_id}/blackboard.json``.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from ctfgpt.config import SESSIONS_DIR

# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------

_MAX_RESULT_LEN: int = 1000


@dataclass
class Finding:
    """A single piece of evidence produced by a tool."""

    agent: str          # e.g. "recon", "exploit", "default"
    tool: str           # e.g. "nmap", "gobuster"
    command: str        # full command string
    result: str         # truncated output (max 1000 chars)
    weight: float       # 0.0–1.0, starts at 0.8
    timestamp: str      # ISO format
    iteration: int      # which iteration produced this

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        return cls(**data)


# ---------------------------------------------------------------------------
# Blackboard
# ---------------------------------------------------------------------------


class Blackboard:
    """Central evidence store for a single agent session."""

    _FILENAME: str = "blackboard.json"

    def __init__(
        self,
        session_id: str,
        category: str = "",
        challenge_desc: str = "",
    ) -> None:
        self.session_id = session_id
        self.category = category
        self.challenge_desc = challenge_desc
        self.findings: list[dict[str, Any]] = []
        self.unexplored: list[str] = []
        self.dead_ends: list[dict[str, Any]] = []
        self.iteration: int = 0

        self._session_dir: Path = SESSIONS_DIR / session_id
        self._session_dir.mkdir(parents=True, exist_ok=True)
        self._dirty: bool = False

        # Hydrate from disk if a previous state exists
        self._load()

    # -- mutations ----------------------------------------------------------

    def write_finding(
        self,
        tool: str,
        command: str,
        result: str,
        weight: float = 0.8,
        agent: str = "default",
    ) -> None:
        """Append a new finding, increment iteration, and auto-save."""
        self.iteration += 1
        finding = Finding(
            agent=agent,
            tool=tool,
            command=command,
            result=result[:_MAX_RESULT_LEN],
            weight=max(0.0, min(weight, 1.0)),
            timestamp=datetime.now(timezone.utc).isoformat(),
            iteration=self.iteration,
        )
        self.findings.append(finding.to_dict())
        self._dirty = True
        self.save()

    def boost(self, tool: str, factor: float = 1.2) -> None:
        """Multiply the weight of the latest finding for *tool* by *factor*.

        Weight is capped at ``1.0``.
        """
        for f in reversed(self.findings):
            if f["tool"] == tool:
                f["weight"] = min(f["weight"] * factor, 1.0)
                self._dirty = True
                self.save()
                return

    def decay(self, tool: str, factor: float = 0.5) -> None:
        """Decay the weight of the latest finding for *tool*.

        If weight drops below ``0.1`` the finding is moved to
        :pyattr:`dead_ends`.
        """
        for i, f in enumerate(reversed(self.findings)):
            if f["tool"] == tool:
                f["weight"] *= factor
                if f["weight"] < 0.1:
                    real_idx = len(self.findings) - 1 - i
                    self.dead_ends.append(self.findings.pop(real_idx))
                self._dirty = True
                self.save()
                return

    # -- unexplored hints ---------------------------------------------------

    def add_unexplored(self, hint: str) -> None:
        """Queue a hint for future exploration."""
        self.unexplored.append(hint)
        self._dirty = True
        self.save()

    def pop_unexplored(self) -> Optional[str]:
        """Pop and return the first unexplored hint, or ``None``."""
        if not self.unexplored:
            return None
        hint = self.unexplored.pop(0)
        self._dirty = True
        self.save()
        return hint

    # -- queries ------------------------------------------------------------

    def top_findings(self, n: int = 3) -> list[dict[str, Any]]:
        """Return the top *n* findings sorted by weight (descending)."""
        return sorted(self.findings, key=lambda f: f["weight"], reverse=True)[:n]

    def has_sufficient_evidence(self, threshold: float = 0.9) -> bool:
        """Return ``True`` if any finding has ``weight >= threshold``."""
        return any(f["weight"] >= threshold for f in self.findings)

    def summary(self) -> str:
        """Formatted string suitable for RAG prompt injection."""
        lines: list[str] = [
            f"== Session Evidence (iteration {self.iteration}) ==",
            f"Category: {self.category or 'unknown'}",
            "",
            "Top Findings:",
        ]
        for idx, f in enumerate(self.top_findings(), start=1):
            preview = f["result"].split("\n")[0][:80]
            lines.append(
                f"[{idx}] (weight: {f['weight']:.2f}) {f['tool']}: {preview}"
            )

        if not self.findings:
            lines.append("  (none yet)")

        lines.append("")
        lines.append(f"Unexplored leads: {len(self.unexplored)}")
        lines.append(f"Dead ends: {len(self.dead_ends)}")
        return "\n".join(lines)

    # -- serialization ------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Serialize the full blackboard state to a plain dict."""
        return {
            "session_id": self.session_id,
            "category": self.category,
            "challenge_desc": self.challenge_desc,
            "findings": self.findings,
            "unexplored": self.unexplored,
            "dead_ends": self.dead_ends,
            "iteration": self.iteration,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any], session_id: str) -> Blackboard:
        """Deserialize a blackboard from a dict (e.g. loaded from JSON)."""
        bb = cls.__new__(cls)
        bb.session_id = session_id
        bb.category = data.get("category", "")
        bb.challenge_desc = data.get("challenge_desc", "")
        bb.findings = data.get("findings", [])
        bb.unexplored = data.get("unexplored", [])
        bb.dead_ends = data.get("dead_ends", [])
        bb.iteration = data.get("iteration", 0)
        bb._session_dir = SESSIONS_DIR / session_id
        bb._session_dir.mkdir(parents=True, exist_ok=True)
        bb._dirty = False
        return bb

    # -- persistence --------------------------------------------------------

    def save(self) -> None:
        """Persist current state to ``blackboard.json`` and clear dirty flag."""
        path = self._session_dir / self._FILENAME
        path.write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        self._dirty = False

    def flush(self) -> None:
        """Persist only if there are unsaved changes (dirty flag is set)."""
        if self._dirty:
            self.save()

    def _load(self) -> None:
        """Load state from ``blackboard.json`` if it exists on disk."""
        path = self._session_dir / self._FILENAME
        if not path.is_file():
            return
        try:
            data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
            self.category = data.get("category", self.category) or self.category
            self.challenge_desc = (
                data.get("challenge_desc", self.challenge_desc) or self.challenge_desc
            )
            self.findings = data.get("findings", [])
            self.unexplored = data.get("unexplored", [])
            self.dead_ends = data.get("dead_ends", [])
            self.iteration = data.get("iteration", 0)
        except (json.JSONDecodeError, KeyError):
            # Corrupted file — start fresh
            pass
