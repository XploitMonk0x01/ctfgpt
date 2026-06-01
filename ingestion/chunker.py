"""Text chunking and metadata tagging for CTF-GPT knowledge base."""

import json
import re
from pathlib import Path
from typing import Optional

try:
    from langchain_text_splitters import RecursiveCharacterTextSplitter
except ImportError:
    from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_core.documents import Document
from rich.console import Console

console = Console()

# ── Tool Detection ─────────────────────────────────────────────────────────

_KNOWN_TOOLS: list[str] = [
    "binwalk", "strings", "exiftool", "foremost", "volatility", "wireshark",
    "nmap", "gobuster", "burpsuite", "sqlmap", "nikto", "dirb",
    "john", "hashcat", "cyberchef", "base64",
    "ghidra", "ida", "radare2", "gdb", "pwntools", "ltrace", "strace",
    "whois", "dig", "subfinder",
    "python", "php", "curl", "wget",
]

TOOL_PATTERNS: dict[str, re.Pattern[str]] = {
    tool: re.compile(rf"\b{re.escape(tool)}\b", re.IGNORECASE)
    for tool in _KNOWN_TOOLS
}
"""Pre-compiled, case-insensitive word-boundary patterns for each known tool."""

# ── Technique Keywords ─────────────────────────────────────────────────────

TECHNIQUE_KEYWORDS: dict[str, list[str]] = {
    "sql-injection": ["sql injection", "sqli", "sqlmap", "' or 1=1"],
    "xss": ["cross-site scripting", "xss", "<script>"],
    "buffer-overflow": ["buffer overflow", "bof", "stack smashing"],
    "file-format-spoofing": ["magic bytes", "file header", "PK header"],
    "steganography": ["stego", "lsb", "hidden data", "steghide"],
    "password-cracking": ["john", "hashcat", "rockyou", "wordlist"],
    "directory-traversal": ["path traversal", "../", "lfi", "rfi"],
    "rsa-attack": ["rsa", "factorization", "small exponent"],
    "rop-chain": ["rop", "return oriented", "gadget"],
    "format-string": ["format string", "%p", "%x", "%n"],
}


# ── Detection Helpers ──────────────────────────────────────────────────────


def detect_tools(text: str) -> list[str]:
    """Find all known-tool mentions in *text*.

    Uses the pre-compiled :data:`TOOL_PATTERNS` for efficient, case-insensitive
    whole-word matching.

    Returns:
        Sorted, deduplicated list of tool names (lower-case).
    """
    if not text:
        return []
    return sorted(
        tool
        for tool, pattern in TOOL_PATTERNS.items()
        if pattern.search(text)
    )


def detect_techniques(text: str) -> list[str]:
    """Identify attack / analysis techniques mentioned in *text*.

    Scans for the keyword phrases listed in :data:`TECHNIQUE_KEYWORDS`.

    Returns:
        Sorted, deduplicated list of technique identifiers
        (e.g. ``"sql-injection"``).
    """
    if not text:
        return []

    text_lower = text.lower()
    found: list[str] = []
    for technique, keywords in TECHNIQUE_KEYWORDS.items():
        for kw in keywords:
            if kw.lower() in text_lower:
                found.append(technique)
                break  # one match per technique is enough
    return sorted(found)


def infer_difficulty(text: str, tools_count: int) -> str:
    """Heuristically estimate the difficulty of a challenge writeup.

    The heuristic considers the number of distinct tools and techniques
    referenced, plus the overall length of the text.

    Returns:
        ``"easy"``, ``"medium"``, or ``"hard"``.
    """
    techniques_count = len(detect_techniques(text))
    total_signals = tools_count + techniques_count

    # Long writeups with many tool / technique mentions ≈ hard
    word_count = len(text.split())
    if total_signals >= 5 or word_count > 2000:
        return "hard"
    if total_signals <= 1 and word_count < 500:
        return "easy"
    return "medium"


# ── Chunking ───────────────────────────────────────────────────────────────


def chunk_documents(
    writeups: list[dict],
    chunk_size: int = 512,
    chunk_overlap: int = 50,
) -> list[Document]:
    """Split writeup texts into LangChain :class:`Document` chunks.

    Each chunk inherits the writeup's metadata and is augmented with:

    * ``tools_used`` – tools detected inside that particular chunk.
    * ``techniques`` – techniques detected inside that chunk.
    * ``difficulty`` – heuristic difficulty estimate.
    * ``chunk_id`` – deterministic ID in the form
      ``{source}_{writeup_id}_chunk_{n}``.

    Args:
        writeups: List of writeup dicts as produced by the scraper (must
            contain at least ``id``, ``content``, ``source``, ``category``,
            ``title``, ``ctf_name``, ``url``).
        chunk_size: Target character count per chunk.
        chunk_overlap: Number of overlapping characters between consecutive
            chunks.

    Returns:
        Flat list of :class:`Document` objects ready for embedding.
    """
    splitter = RecursiveCharacterTextSplitter(
        chunk_size=chunk_size,
        chunk_overlap=chunk_overlap,
        length_function=len,
        separators=["\n\n", "\n", ". ", " ", ""],
    )

    documents: list[Document] = []

    for writeup in writeups:
        content: str = writeup.get("content", "")
        if not content:
            console.print(
                f"[yellow]⚠  Skipping writeup {writeup.get('id', '?')} — no content[/]"
            )
            continue

        writeup_id: str = str(writeup.get("id", "unknown"))
        source: str = writeup.get("source", "unknown")
        category: str = writeup.get("category", "forensics")
        ctf_name: str = writeup.get("ctf_name", "")
        title: str = writeup.get("title", "")
        url: str = writeup.get("url", "")

        # Split the full content into chunks
        chunks: list[str] = splitter.split_text(content)

        for idx, chunk_text in enumerate(chunks):
            tools_used = detect_tools(chunk_text)
            techniques = detect_techniques(chunk_text)
            difficulty = infer_difficulty(chunk_text, len(tools_used))

            chunk_id = f"{source}_{writeup_id}_chunk_{idx}"

            doc = Document(
                page_content=chunk_text,
                metadata={
                    "source": source,
                    "ctf_name": ctf_name,
                    "challenge_name": title,
                    "category": category,
                    "difficulty": difficulty,
                    "tools_used": tools_used,
                    "techniques": techniques,
                    "url": url,
                    "chunk_id": chunk_id,
                },
            )
            documents.append(doc)

    console.print(
        f"[green]✓  Chunked {len(writeups)} writeups → {len(documents)} documents[/]"
    )
    return documents


# ── I/O Helpers ────────────────────────────────────────────────────────────


def load_writeups_from_dir(directory: Path) -> list[dict]:
    """Load all JSON writeup files from *directory*.

    Each JSON file is expected to be a single writeup dict as produced by
    :func:`ctfgpt.ingestion.scraper_ctftime.scrape_ctftime`.

    Files that fail to parse are logged and skipped.

    Returns:
        List of writeup dicts.
    """
    if not directory.is_dir():
        console.print(f"[red]✗  Directory not found: {directory}[/]")
        return []

    writeups: list[dict] = []
    json_files = sorted(directory.glob("*.json"))

    if not json_files:
        console.print(f"[yellow]⚠  No JSON files found in {directory}[/]")
        return []

    for path in json_files:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            writeups.append(data)
        except (json.JSONDecodeError, OSError) as exc:
            console.print(f"[yellow]⚠  Skipping {path.name}: {exc}[/]")

    console.print(f"[green]✓  Loaded {len(writeups)} writeups from {directory}[/]")
    return writeups
