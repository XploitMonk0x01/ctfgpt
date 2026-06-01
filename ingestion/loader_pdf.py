"""PDF writeup loader for CTF-GPT knowledge base.

Loads PDF files from a directory, extracts text, detects category
and tools, and saves as JSON writeups compatible with the chunker.
"""

import json
import re
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()

# ── Lightweight Category Signals ──────────────────────────────────────────
# Mirrors the keyword lists from ctfgpt.classifier but kept self-contained
# so this module has no hard dependency on the classifier.

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
    ],
    "crypto": [
        "cipher", "rsa", "aes", "base64", "xor", "hash", "md5",
        "sha", "encoding", "otp", "padding oracle", "frequency",
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
        "metadata", "whois", "dns", "google dork", "wayback",
        "sherlock", "recon",
    ],
}

_COMPILED_SIGNALS: dict[str, list[re.Pattern[str]]] = {
    category: [
        re.compile(rf"\b{re.escape(kw)}\b", re.IGNORECASE)
        for kw in keywords
    ]
    for category, keywords in CATEGORY_SIGNALS.items()
}


# ── PDF Text Extraction ───────────────────────────────────────────────────


def extract_text_from_pdf(pdf_path: Path) -> str:
    """Extract all text from a PDF file.

    Attempts extraction with ``pdfplumber`` first (better results for
    tables and code blocks), then falls back to ``PyPDF2``.

    Parameters
    ----------
    pdf_path:
        Absolute or relative path to the PDF file.

    Returns
    -------
    str
        Concatenated text from all pages.

    Raises
    ------
    ImportError
        If neither ``pdfplumber`` nor ``PyPDF2`` is installed.
    FileNotFoundError
        If *pdf_path* does not exist.
    """
    if not pdf_path.is_file():
        raise FileNotFoundError(f"PDF file not found: {pdf_path}")

    # ── Try pdfplumber (preferred) ────────────────────────────────────
    try:
        import pdfplumber  # type: ignore[import-untyped]

        pages_text: list[str] = []
        with pdfplumber.open(pdf_path) as pdf:
            for page in pdf.pages:
                text = page.extract_text()
                if text:
                    pages_text.append(text)
        return "\n\n".join(pages_text)
    except ImportError:
        pass  # fall through to PyPDF2

    # ── Try PyPDF2 (fallback) ─────────────────────────────────────────
    try:
        from PyPDF2 import PdfReader  # type: ignore[import-untyped]

        reader = PdfReader(str(pdf_path))
        pages_text = []
        for page in reader.pages:
            text = page.extract_text()
            if text:
                pages_text.append(text)
        return "\n\n".join(pages_text)
    except ImportError:
        pass

    raise ImportError(
        "PDF extraction requires either 'pdfplumber' or 'PyPDF2'.\n"
        "Install one of them:\n"
        "  pip install pdfplumber   # recommended — better for tables/code\n"
        "  pip install PyPDF2       # lighter alternative"
    )


# ── Category Detection ─────────────────────────────────────────────────────


def detect_category(text: str) -> str:
    """Detect the most likely CTF category from *text* using keyword scoring.

    Scores each category by counting keyword matches and normalising
    against the keyword list length.  Returns the highest-scoring
    category, or ``'forensics'`` when no clear signal is found.

    Parameters
    ----------
    text:
        The full extracted writeup text.

    Returns
    -------
    str
        One of: ``forensics``, ``web``, ``crypto``, ``pwn``,
        ``reversing``, ``osint``.
    """
    if not text:
        return "forensics"

    scores: dict[str, float] = {}
    for category, patterns in _COMPILED_SIGNALS.items():
        hits = sum(1 for pat in patterns if pat.search(text))
        scores[category] = hits / len(patterns) if patterns else 0.0

    best = max(scores, key=scores.get)  # type: ignore[arg-type]
    return best if scores[best] > 0 else "forensics"


# ── Main Loader ────────────────────────────────────────────────────────────


def load_pdfs(
    pdf_dir: Path,
    output_dir: Optional[Path] = None,
) -> list[dict]:
    """Load all PDF files from *pdf_dir* and convert them to writeup dicts.

    For each PDF the loader:

    1. Extracts full text via :func:`extract_text_from_pdf`.
    2. Auto-detects the CTF category.
    3. Detects tool mentions (reuses :func:`ingestion.chunker.detect_tools`).
    4. Saves a JSON writeup file to *output_dir*.

    Broken or unreadable PDFs are logged and skipped.

    Parameters
    ----------
    pdf_dir:
        Directory containing ``*.pdf`` files to ingest.
    output_dir:
        Where to write the JSON writeups.  Defaults to
        ``DATA_DIR / 'pdf'``.

    Returns
    -------
    list[dict]
        List of writeup dicts (one per successfully processed PDF).
    """
    from ctfgpt.config import DATA_DIR  # noqa: WPS433
    from ingestion.chunker import detect_tools  # noqa: WPS433

    if output_dir is None:
        output_dir = DATA_DIR / "pdf"
    output_dir.mkdir(parents=True, exist_ok=True)

    pdf_dir = Path(pdf_dir)
    if not pdf_dir.is_dir():
        console.print(f"[red]✗  PDF directory not found: {pdf_dir}[/]")
        return []

    pdf_files = sorted(pdf_dir.glob("*.pdf"))
    if not pdf_files:
        console.print(f"[yellow]⚠  No PDF files found in {pdf_dir}[/]")
        return []

    writeups: list[dict] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
    ) as progress:
        task = progress.add_task("Loading PDFs…", total=len(pdf_files))

        for pdf_path in pdf_files:
            try:
                content = extract_text_from_pdf(pdf_path)
            except (ImportError, FileNotFoundError) as exc:
                console.print(f"[red]✗  {pdf_path.name}: {exc}[/]")
                progress.update(task, advance=1)
                continue
            except Exception as exc:  # noqa: BLE001
                console.print(f"[yellow]⚠  Skipping {pdf_path.name}: {exc}[/]")
                progress.update(task, advance=1)
                continue

            if not content or len(content.strip()) < 50:
                console.print(
                    f"[yellow]⚠  Skipping {pdf_path.name}: insufficient text[/]"
                )
                progress.update(task, advance=1)
                continue

            category = detect_category(content)
            tools_used = detect_tools(content)

            writeup: dict = {
                "id": pdf_path.stem,
                "title": pdf_path.stem.replace("_", " ").replace("-", " ").title(),
                "ctf_name": "local_pdf",
                "category": category,
                "content": content,
                "tools_used": tools_used,
                "url": str(pdf_path.resolve()),
                "source": "pdf",
            }

            # Persist to disk
            out_path = output_dir / f"{pdf_path.stem}.json"
            try:
                out_path.write_text(
                    json.dumps(writeup, indent=2, ensure_ascii=False),
                    encoding="utf-8",
                )
            except OSError as exc:
                console.print(f"[yellow]⚠  Could not save {out_path}: {exc}[/]")

            writeups.append(writeup)
            progress.update(task, advance=1)

    console.print(
        f"[green]✓  Loaded {len(writeups)}/{len(pdf_files)} PDFs → {output_dir}[/]"
    )
    return writeups


# ── Sync Entry-point ───────────────────────────────────────────────────────


def run_pdf_loader(pdf_dir: str) -> list[dict]:
    """Synchronous entry point for the PDF loader.

    Parameters
    ----------
    pdf_dir:
        String path to the directory containing PDF files.

    Returns
    -------
    list[dict]
        Writeup dicts produced by :func:`load_pdfs`.
    """
    return load_pdfs(Path(pdf_dir))


if __name__ == "__main__":
    import sys

    directory = sys.argv[1] if len(sys.argv) > 1 else "."
    results = run_pdf_loader(directory)
    console.print(f"Processed {len(results)} PDF writeups.")
