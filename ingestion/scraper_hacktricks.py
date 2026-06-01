"""HackTricks knowledge base loader for CTF-GPT.

Clones the HackTricks and HackTricks-Cloud repos and extracts
technique documentation as writeup-format JSON files.
"""

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()

HACKTRICKS_REPO: str = "https://github.com/HackTricks-wiki/hacktricks.git"

# Map HackTricks directory structure to our categories
DIR_CATEGORY_MAP: dict[str, str] = {
    "forensics": "forensics",
    "stego": "forensics",
    "crypto": "crypto",
    "cryptography": "crypto",
    "web": "web",
    "pentesting-web": "web",
    "exploiting": "pwn",
    "binary-exploitation": "pwn",
    "reversing": "reversing",
    "reverse-engineering": "reversing",
    "osint": "osint",
}

# Files to always skip (common non-writeup / boilerplate files)
_SKIP_FILENAMES: set[str] = {
    "readme.md",
    "summary.md",
    "changelog.md",
    "contributing.md",
    "license.md",
    "code_of_conduct.md",
}


# ── Git Cloning ────────────────────────────────────────────────────────────


def clone_hacktricks(target_dir: Path) -> bool:
    """Shallow-clone the HackTricks repository.

    Parameters
    ----------
    target_dir:
        Local directory to clone into.  Created if it does not exist.

    Returns
    -------
    bool
        ``True`` if the clone succeeded, ``False`` otherwise.
    """
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", HACKTRICKS_REPO, str(target_dir)],
            check=True,
            capture_output=True,
            text=True,
            timeout=180,
        )
        console.print(f"[green]✓  Cloned HackTricks → {target_dir}[/]")
        return True
    except FileNotFoundError:
        console.print("[red]✗  git is not installed or not on PATH[/]")
        return False
    except subprocess.CalledProcessError as exc:
        console.print(
            f"[yellow]⚠  Failed to clone HackTricks: {exc.stderr.strip()}[/]"
        )
        return False
    except subprocess.TimeoutExpired:
        console.print("[yellow]⚠  HackTricks clone timed out (180 s)[/]")
        return False


# ── Path-based Category Mapping ───────────────────────────────────────────


def categorize_by_path(file_path: Path) -> str:
    """Map a file path to a CTF category using directory name signals.

    Checks every component of *file_path* against :data:`DIR_CATEGORY_MAP`.
    The first match (scanning from the file towards the root) wins.

    Parameters
    ----------
    file_path:
        Absolute or relative path to a markdown file inside the
        HackTricks repository.

    Returns
    -------
    str
        One of: ``forensics``, ``web``, ``crypto``, ``pwn``,
        ``reversing``, ``osint``.  Defaults to ``'web'`` since
        HackTricks is predominantly web/pentesting focused.
    """
    # Walk path components from deepest to shallowest
    for part in reversed(file_path.parts):
        normalised = part.lower().strip()
        if normalised in DIR_CATEGORY_MAP:
            return DIR_CATEGORY_MAP[normalised]
    return "web"  # sensible default for HackTricks


# ── Main Loader ────────────────────────────────────────────────────────────


def load_hacktricks(
    target_dir: Optional[Path] = None,
    output_dir: Optional[Path] = None,
    limit: int = 500,
) -> list[dict]:
    """Clone the HackTricks repo and extract writeup-format dicts.

    If *target_dir* already exists and contains a ``.git`` directory the
    clone step is skipped, allowing incremental re-runs.

    Parameters
    ----------
    target_dir:
        Where to clone the HackTricks repo.  Defaults to
        ``DATA_DIR / 'hacktricks_repo'``.
    output_dir:
        Where to write JSON writeup files.  Defaults to
        ``DATA_DIR / 'hacktricks'``.
    limit:
        Maximum number of markdown files to process.

    Returns
    -------
    list[dict]
        Writeup dicts ready for chunking / embedding.
    """
    from ctfgpt.config import DATA_DIR  # noqa: WPS433
    from ingestion.chunker import detect_tools  # noqa: WPS433

    if target_dir is None:
        target_dir = DATA_DIR / "hacktricks_repo"
    if output_dir is None:
        output_dir = DATA_DIR / "hacktricks"
    output_dir.mkdir(parents=True, exist_ok=True)

    # ── Clone if needed ───────────────────────────────────────────────
    if target_dir.is_dir() and (target_dir / ".git").is_dir():
        console.print(
            f"[dim]  ↳ Using existing HackTricks clone at {target_dir}[/]"
        )
    else:
        target_dir.mkdir(parents=True, exist_ok=True)
        if not clone_hacktricks(target_dir):
            return []

    # ── Collect candidate markdown files ──────────────────────────────
    md_files = sorted(target_dir.rglob("*.md"))

    # Filter out skippable files
    candidates: list[Path] = []
    for md_path in md_files:
        if md_path.name.lower() in _SKIP_FILENAMES:
            continue
        # Skip hidden directories (e.g. .git, .github)
        if any(p.startswith(".") for p in md_path.relative_to(target_dir).parts):
            continue
        candidates.append(md_path)

    if not candidates:
        console.print("[yellow]⚠  No usable markdown files found in HackTricks repo[/]")
        return []

    # Apply limit to candidate list
    candidates = candidates[:limit]

    writeups: list[dict] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
    ) as progress:
        task = progress.add_task(
            "Processing HackTricks docs…", total=len(candidates)
        )

        for md_path in candidates:
            try:
                content = md_path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                console.print(f"[yellow]⚠  Skipping {md_path.name}: {exc}[/]")
                progress.update(task, advance=1)
                continue

            # Skip very short files (likely stubs or index pages)
            if len(content.strip()) < 200:
                progress.update(task, advance=1)
                continue

            rel_path = md_path.relative_to(target_dir)
            file_id = hashlib.md5(str(rel_path).encode()).hexdigest()[:12]

            category = categorize_by_path(rel_path)
            tools_used = detect_tools(content)

            # Construct the canonical GitHub URL for this file
            github_url = (
                f"https://github.com/HackTricks-wiki/hacktricks/blob/master/"
                f"{rel_path.as_posix()}"
            )

            writeup: dict = {
                "id": file_id,
                "title": md_path.stem.replace("-", " ").replace("_", " ").title(),
                "ctf_name": "hacktricks",
                "category": category,
                "content": content,
                "tools_used": tools_used,
                "url": github_url,
                "source": "hacktricks",
            }

            # Persist to disk
            out_path = output_dir / f"{file_id}.json"
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
        f"[green]✓  Processed {len(writeups)}/{len(candidates)} HackTricks docs "
        f"→ {output_dir}[/]"
    )
    return writeups


# ── Sync Entry-point ───────────────────────────────────────────────────────


def run_hacktricks_loader(limit: int = 500) -> list[dict]:
    """Synchronous entry point for the HackTricks loader.

    Parameters
    ----------
    limit:
        Maximum number of markdown files to process.

    Returns
    -------
    list[dict]
        Writeup dicts produced by :func:`load_hacktricks`.
    """
    return load_hacktricks(limit=limit)


if __name__ == "__main__":
    import sys

    max_files = int(sys.argv[1]) if len(sys.argv) > 1 else 500
    results = run_hacktricks_loader(limit=max_files)
    console.print(f"Processed {len(results)} HackTricks documents.")
