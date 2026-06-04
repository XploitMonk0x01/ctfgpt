"""Configuration loader for CTF-GPT.

Loads settings from config.yaml with env-var overrides and provides
factory functions for LLM and embedding instances.

Search order for config.yaml:
    1. Current working directory
    2. CTFGPT_HOME (~/.ctfgpt/config.yaml)
    3. Package directory (project root, next to the ctfgpt/ package)
    4. Built-in DEFAULT_CONFIG dict
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

# ---------------------------------------------------------------------------
# Path constants
# ---------------------------------------------------------------------------
CTFGPT_HOME: Path = Path.home() / ".ctfgpt"
DB_PATH: Path = CTFGPT_HOME / "db"
SESSIONS_DIR: Path = CTFGPT_HOME / "sessions"
WORKSPACE_DIR: Path = Path.cwd() / "workspace"
HISTORY_PATH: Path = CTFGPT_HOME / "history.json"
DATA_DIR: Path = Path.cwd() / "data" / "writeups"

# ---------------------------------------------------------------------------
# Collection & category constants
# ---------------------------------------------------------------------------
COLLECTIONS: list[str] = [
    "ctfgpt_forensics",
    "ctfgpt_web",
    "ctfgpt_crypto",
    "ctfgpt_pwn",
    "ctfgpt_reversing",
    "ctfgpt_osint",
]

CATEGORIES: list[str] = [
    "forensics",
    "web",
    "crypto",
    "pwn",
    "reversing",
    "osint",
]

# ---------------------------------------------------------------------------
# Default configuration (fallback when no config.yaml is found)
# ---------------------------------------------------------------------------
DEFAULT_CONFIG: dict[str, Any] = {
    "llm_mode": "cloud",
    "cloud": {
        "provider": "groq",
        "model": "llama-3.3-70b-versatile",
    },
    "models": {
        "planner": None,       # None = use cloud.provider default
        "observer": None,
        "responder": None,
    },
    "local": {
        "model": "mistral",
        "embed_model": "nomic-embed-text",
        "base_url": "http://localhost:11434",
    },
    "embedding": {
        "model": "all-MiniLM-L6-v2",
    },
    "mcp": {
        "enabled": False,
        "host": "localhost",
        "port": 5000,
        "timeout": 30,
        "scope": None,
    },
    "agent": {
        "max_iterations": 8,
        "decay_threshold": 0.1,
        "auto_report": True,
    },
    "db": {
        "path": "~/.ctfgpt/db",
    },
    "hints": {
        "default_level": 1,
        "max_level": 3,
    },
}

# ---------------------------------------------------------------------------
# Module-level config cache
# ---------------------------------------------------------------------------
_config: dict[str, Any] | None = None


def _find_config_yaml() -> Path | None:
    """Locate config.yaml using the defined search order.

    Returns the first path found, or ``None`` if no file exists.
    """
    candidates: list[Path] = [
        # 1. Current working directory
        Path.cwd() / "config.yaml",
        # 2. CTFGPT_HOME
        CTFGPT_HOME / "config.yaml",
        # 3. Package / project root (parent of ctfgpt/ package dir)
        Path(__file__).resolve().parent.parent / "config.yaml",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def load_config(*, force_reload: bool = False) -> dict[str, Any]:
    """Load and cache the YAML configuration.

    Parameters
    ----------
    force_reload:
        When ``True``, ignore the cached config and re-read from disk.

    Returns
    -------
    dict
        The merged configuration dictionary.
    """
    global _config  # noqa: PLW0603

    if _config is not None and not force_reload:
        return _config

    config_path = _find_config_yaml()
    if config_path is not None:
        with config_path.open("r", encoding="utf-8") as fh:
            loaded: dict[str, Any] = yaml.safe_load(fh) or {}
        # Merge: loaded values override defaults
        merged = {**DEFAULT_CONFIG, **loaded}
    else:
        merged = dict(DEFAULT_CONFIG)

    _config = merged
    return _config





# ---------------------------------------------------------------------------
# Factory helpers
# ---------------------------------------------------------------------------

def get_llm(role: str = "default"):
    """Return a LangChain LLM instance based on the current mode.

    Parameters
    ----------
    role:
        The role requesting the LLM. Supported roles:
        ``"planner"`` — plan generation & re-planning (deep reasoning)
        ``"observer"`` — tool output observation (fast summaries)
        ``"responder"`` — final hint generation (quality output)
        ``"default"`` — uses the global ``cloud.provider`` setting

        When a role has a provider configured in ``config.models.<role>``,
        that provider is used. Otherwise falls back to ``cloud.provider``.

    The mode is resolved as:
        ``LLM_MODE`` env var  →  ``config["llm_mode"]``  →  ``"cloud"``

    Raises
    ------
    ValueError
        If the resolved mode is not ``"cloud"`` or ``"local"``.
    """
    cfg = load_config()
    mode = os.getenv("LLM_MODE", cfg.get("llm_mode", "cloud"))

    if mode == "cloud":
        # Resolve provider: role-specific override → global default
        default_provider = cfg.get("cloud", {}).get("provider", "groq")
        role_provider = None
        if role != "default":
            role_provider = cfg.get("models", {}).get(role)
        provider = role_provider or default_provider

        return _build_cloud_llm(cfg, provider)

    elif mode == "local":
        from langchain_ollama import OllamaLLM  # type: ignore[import-untyped]

        return OllamaLLM(
            model=cfg["local"]["model"],
            base_url=cfg["local"]["base_url"],
        )
    else:
        raise ValueError(f"Unknown LLM_MODE: {mode}")


def _build_cloud_llm(cfg: dict[str, Any], provider: str):
    """Instantiate a cloud LLM for the given provider name."""
    if provider == "deepseek":
        from langchain_openai import ChatOpenAI  # type: ignore[import-untyped]

        return ChatOpenAI(
            model=cfg.get("deepseek", {}).get("model", "deepseek-chat"),
            api_key=os.getenv("DEEPSEEK_API_KEY"),
            base_url="https://api.deepseek.com",
            temperature=0.3,
        )
    else:
        # Default: Groq
        from langchain_groq import ChatGroq  # type: ignore[import-untyped]

        return ChatGroq(
            model=cfg.get("cloud", {}).get("model", "llama-3.3-70b-versatile"),
            api_key=os.getenv("GROQ_API_KEY"),
            temperature=0.3,
        )


def get_embeddings():
    """Return a HuggingFace sentence-transformers embedding instance."""
    from langchain_huggingface import HuggingFaceEmbeddings  # type: ignore[import-untyped]

    cfg = load_config()
    model_name: str = cfg.get("embedding", {}).get("model", "all-MiniLM-L6-v2")
    return HuggingFaceEmbeddings(model_name=model_name)


# ---------------------------------------------------------------------------
# CLI helpers – dot-path config access
# ---------------------------------------------------------------------------

def get_config_value(key_path: str) -> Any:
    """Retrieve a nested config value using dot notation.

    Example::

        get_config_value("cloud.model")  # -> "llama-3.1-8b-instant"

    Raises
    ------
    KeyError
        If the key path does not exist in the configuration.
    """
    cfg = load_config()
    keys = key_path.split(".")
    current: Any = cfg
    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            raise KeyError(f"Config key not found: {key_path}")
    return current


def set_config_value(key_path: str, value: str) -> None:
    """Set a nested config value using dot notation and persist to disk.

    The value string is coerced to ``int``, ``float``, ``bool``, or
    ``None`` when appropriate; otherwise it is stored as a string.

    The updated config is written to ``CTFGPT_HOME / "config.yaml"``.
    """
    cfg = load_config()
    keys = key_path.split(".")
    current: Any = cfg
    for key in keys[:-1]:
        if isinstance(current, dict):
            current = current.setdefault(key, {})
        else:
            raise KeyError(f"Cannot traverse non-dict at: {key}")

    # Coerce value
    coerced: Any
    lower = value.lower()
    if lower == "true":
        coerced = True
    elif lower == "false":
        coerced = False
    elif lower in ("null", "none"):
        coerced = None
    else:
        try:
            coerced = int(value)
        except ValueError:
            try:
                coerced = float(value)
            except ValueError:
                coerced = value

    current[keys[-1]] = coerced

    # Persist to CTFGPT_HOME
    CTFGPT_HOME.mkdir(parents=True, exist_ok=True)
    out_path = CTFGPT_HOME / "config.yaml"
    with out_path.open("w", encoding="utf-8") as fh:
        yaml.dump(cfg, fh, default_flow_style=False, sort_keys=False)
