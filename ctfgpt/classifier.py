"""CTF challenge category auto-detection.

Provides a two-step classifier that first checks for an explicit user override,
then falls back to keyword-signal scoring across the six CTF categories.
"""

import re
from typing import Optional

from rich.console import Console

from ctfgpt.config import CATEGORIES

console = Console()

# Keyword signals for each category — multi-word entries are matched as phrases
CATEGORY_SIGNALS: dict[str, list[str]] = {
    "forensics": [
        "binwalk", "strings", "hexdump", "steganography", "memory dump",
        "volatility", "png", "pcap", "wireshark", "exiftool", "foremost",
        "autopsy", "disk image", "file carving", "metadata",
    ],
    "web": [
        "sql injection", "xss", "lfi", "rfi", "php", "cookies",
        "burpsuite", "jwt", "ssrf", "directory traversal", "gobuster",
        "web server", "http", "html", "javascript", "api",
        "config.php", "admin", "index.php", "curl", "robots.txt"
    ],
    "crypto": [
        "cipher", "rsa", "aes", "base64", "xor", "hash", "md5",
        "sha1", "sha256", "sha512", "encoding", "otp", "padding oracle", "frequency",
        "modular", "prime", "encrypt", "decrypt",
    ],
    "pwn": [
        "buffer overflow", "rop", "ret2libc", "shellcode", "got",
        "plt", "heap", "stack", "libc", "gdb", "pwntools",
        "format string", "canary", "nx", "aslr",
    ],
    "reversing": [
        "ghidra", "ida", "binary", "disassemble", "crackme",
        "anti-debug", "packed", "upx", "decompile", "elf", "pe",
        "assembly", "obfuscated", "malware",
    ],
    "osint": [
        "username", "email", "social media", "geolocation",
        "whois", "dns", "google dork", "wayback",
        "sherlock", "recon", "linkedin", "instagram", "maltego",
    ],
}

# Pre-compile patterns for each category (case-insensitive, word-boundary aware)
_COMPILED_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    category: [
        re.compile(rf"\b{re.escape(kw)}\b", re.IGNORECASE)
        for kw in keywords
    ]
    for category, keywords in CATEGORY_SIGNALS.items()
}

# Minimum keyword score to trust the classification
_CONFIDENCE_THRESHOLD: float = 0.15

# Fallback when there is no clear signal
_DEFAULT_CATEGORY: str = "web"


def keyword_score(query: str) -> dict[str, float]:
    """Score a query against every category's keyword list.

    Each keyword that appears in *query* contributes one point to its
    category.  Scores are normalised to the ``[0, 1]`` range by dividing
    by the number of keywords in that category.

    Multi-word keywords (e.g. ``"buffer overflow"``) are matched as exact
    phrases using word-boundary-aware regular expressions.

    Parameters
    ----------
    query:
        Free-form challenge description or question from the user.

    Returns
    -------
    dict[str, float]
        Mapping of ``{category: normalised_score}``.
    """
    scores: dict[str, float] = {}
    for category, patterns in _COMPILED_PATTERNS.items():
        hits = sum(1 for pat in patterns if pat.search(query))
        scores[category] = hits / len(patterns) if patterns else 0.0
    return scores


def classify(query: str, override: Optional[str] = None) -> str:
    """Return the most likely CTF category for *query*.

    Parameters
    ----------
    query:
        The user's challenge description or question.
    override:
        If provided **and** it is a valid category name, it is returned
        immediately — no scoring is performed.

    Returns
    -------
    str
        One of the six category strings defined in ``CATEGORIES``.
    """
    # Honour explicit override
    if override is not None:
        normalised = override.strip().lower()
        if normalised in CATEGORIES:
            return normalised

    # Score keywords
    scores = keyword_score(query)

    # Pick the category with the highest score
    best_category = max(scores, key=scores.get)  # type: ignore[arg-type]
    best_score = scores[best_category]

    if best_score >= _CONFIDENCE_THRESHOLD:
        return best_category

    if best_score == 0.0:
        console.print(
            f"  [dim]Classifier: no keywords matched — defaulting to '{_DEFAULT_CATEGORY}'[/dim]"
        )
        return _DEFAULT_CATEGORY

    # Not enough signal — return the best-scoring category anyway (never blindly default)
    # This avoids the wrong playbook running when there is some (weak) signal
    console.print(
        f"  [dim]Classifier: low confidence ({best_score:.2f}) — using best guess '{best_category}'[/dim]"
    )
    return best_category


def get_confidence(query: str) -> tuple[str, float]:
    """Return the best category and its confidence score for display.

    Parameters
    ----------
    query:
        The user's challenge description or question.

    Returns
    -------
    tuple[str, float]
        ``(category, confidence)`` where *confidence* is in ``[0, 1]``.
    """
    scores = keyword_score(query)
    best_category = max(scores, key=scores.get)  # type: ignore[arg-type]
    return best_category, scores[best_category]
