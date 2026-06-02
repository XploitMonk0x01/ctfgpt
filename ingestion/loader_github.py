"""GitHub CTF writeup loader for CTF-GPT knowledge base.

Supports:
- Cloning entire repos with CTF writeups
- Fetching individual markdown files via raw URLs
- GitHub API search for top CTF writeup repos
"""

import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

import httpx
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()

# Well-known CTF writeup repos (owner/repo format)
DEFAULT_REPOS: list[str] = [
    "ctf-wiki/ctf-wiki",
    "w181496/Web-CTF-Cheatsheet",
    "apsdehal/awesome-ctf",
]

# User-specified repos to always include when running ingest --source github
CTFGPT_REPOS: list[str] = [
    "https://github.com/edoardottt/tryhackme-ctf",
    "https://github.com/Esther7171/TryHackMe-Walkthroughs/tree/main/Room",
    "https://github.com/momenbasel/htb-writeups",
    "https://github.com/hackthebox/business-ctf-2025",
]

GITHUB_RAW_BASE: str = "https://raw.githubusercontent.com"
GITHUB_API_BASE: str = "https://api.github.com"

# ── Lightweight Category Detection ────────────────────────────────────────
# Kept self-contained to avoid hard dependency on the classifier module.

_CATEGORY_KEYWORDS: dict[str, list[str]] = {
    "forensics": [
        "binwalk", "strings", "hexdump", "steganography", "volatility",
        "wireshark", "pcap", "disk image", "file carving", "exiftool",
    ],
    "web": [
        "sql injection", "xss", "lfi", "rfi", "burpsuite", "jwt",
        "ssrf", "directory traversal", "gobuster", "http",
    ],
    "crypto": [
        "cipher", "rsa", "aes", "base64", "xor", "hash",
        "padding oracle", "encrypt", "decrypt", "prime",
    ],
    "pwn": [
        "buffer overflow", "rop", "ret2libc", "shellcode",
        "heap", "stack", "gdb", "pwntools", "format string",
    ],
    "reversing": [
        "ghidra", "ida", "disassemble", "crackme", "decompile",
        "elf", "assembly", "obfuscated", "malware",
    ],
    "osint": [
        "username", "email", "geolocation", "whois", "dns",
        "google dork", "wayback", "sherlock", "recon",
    ],
}


def _detect_category(text: str) -> str:
    """Score *text* against category keyword lists and return the best match.

    Falls back to ``'forensics'`` when no keywords are found.
    """
    if not text:
        return "forensics"

    text_lower = text.lower()
    best_cat = "forensics"
    best_score = 0.0

    for category, keywords in _CATEGORY_KEYWORDS.items():
        hits = sum(1 for kw in keywords if kw in text_lower)
        score = hits / len(keywords) if keywords else 0.0
        if score > best_score:
            best_score = score
            best_cat = category

    return best_cat


# ── GitHub URL Parser ────────────────────────────────────────────────────────


def parse_github_input(raw: str) -> tuple[str, Optional[str]]:
    """Parse a GitHub repo URL or ``owner/name`` string into (repo, subdir).

    Handles inputs like:
    - ``"owner/repo"`` → ``("owner/repo", None)``
    - ``"https://github.com/owner/repo"`` → ``("owner/repo", None)``
    - ``"https://github.com/owner/repo/tree/main/path/to/dir"``
      → ``("owner/repo", "path/to/dir")``

    Parameters
    ----------
    raw:
        A raw string from the user.

    Returns
    -------
    tuple[str, Optional[str]]
        ``("owner/repo", subdir_or_None)``
    """
    raw = raw.strip().rstrip("/")

    # Full GitHub URL
    match = re.match(
        r"https?://github\.com/([^/]+/[^/]+)(?:/tree/[^/]+/?(.*))?",
        raw,
    )
    if match:
        repo = match.group(1)
        subdir = match.group(2) or None
        if subdir:
            subdir = subdir.strip("/") or None
        return repo, subdir

    # Already owner/repo
    if re.match(r"^[\w.-]+/[\w.-]+$", raw):
        return raw, None

    # Unrecognised — return as-is and let git handle the error
    return raw, None


# ── Network Helpers ────────────────────────────────────────────────────────


def fetch_raw_file(url: str) -> Optional[str]:
    """Fetch a single file from a raw GitHub URL.

    Parameters
    ----------
    url:
        A raw-content URL, e.g.
        ``https://raw.githubusercontent.com/owner/repo/main/writeup.md``

    Returns
    -------
    str or None
        The file's text content, or ``None`` on any HTTP / network error.
    """
    try:
        resp = httpx.get(url, follow_redirects=True, timeout=30.0)
        resp.raise_for_status()
        return resp.text
    except httpx.HTTPError as exc:
        console.print(f"[yellow]⚠  Failed to fetch {url}: {exc}[/]")
        return None


# ── Git Helpers ────────────────────────────────────────────────────────────


def clone_repo(repo: str, target_dir: Path) -> bool:
    """Shallow-clone a GitHub repository.

    Parameters
    ----------
    repo:
        Repository in ``owner/name`` format (e.g. ``"apsdehal/awesome-ctf"``).
    target_dir:
        Local directory to clone into.

    Returns
    -------
    bool
        ``True`` if the clone succeeded, ``False`` otherwise.
    """
    url = f"https://github.com/{repo}.git"
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", url, str(target_dir)],
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
        )
        console.print(f"[green]✓  Cloned {repo}[/]")
        return True
    except FileNotFoundError:
        console.print("[red]✗  git is not installed or not on PATH[/]")
        return False
    except subprocess.CalledProcessError as exc:
        console.print(f"[yellow]⚠  Failed to clone {repo}: {exc.stderr.strip()}[/]")
        return False
    except subprocess.TimeoutExpired:
        console.print(f"[yellow]⚠  Clone timed out for {repo}[/]")
        return False


# ── Repo Scanning ──────────────────────────────────────────────────────────


def scan_repo_for_writeups(
    repo_dir: Path,
    subdir: Optional[str] = None,
) -> list[dict]:
    """Walk a cloned repository (or a subdirectory of it) and extract writeup dicts.

    Finds all ``.md`` and ``.txt`` files, skips those shorter than 200
    characters (unlikely to be full writeups), and builds a writeup dict
    for each qualifying file.

    Parameters
    ----------
    repo_dir:
        Root directory of the cloned repository.
    subdir:
        Optional subdirectory path relative to *repo_dir* to restrict
        scanning to (e.g. ``"Room"`` from a ``/tree/main/Room`` URL).

    Returns
    -------
    list[dict]
        Writeup dicts ready for chunking / embedding.
    """
    from ingestion.chunker import detect_tools  # noqa: WPS433

    scan_root = repo_dir
    if subdir:
        candidate = repo_dir / subdir
        if candidate.is_dir():
            scan_root = candidate
            console.print(f"[dim]  Scanning subdirectory: {subdir}[/]")
        else:
            console.print(f"[yellow]⚠  Subdir '{subdir}' not found in repo — scanning full repo.[/]")

    writeups: list[dict] = []

    for ext in ("*.md", "*.txt"):
        for file_path in scan_root.rglob(ext):
            # Skip hidden dirs / common non-writeup files
            parts_lower = [p.lower() for p in file_path.parts]
            if any(p.startswith(".") for p in file_path.parts):
                continue

            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            if len(content.strip()) < 200:
                continue

            # Derive a stable ID from the relative path
            rel_path = file_path.relative_to(repo_dir)
            file_id = hashlib.md5(str(rel_path).encode()).hexdigest()[:12]

            # Use the immediate parent directory as the CTF name hint
            ctf_name = file_path.parent.name if file_path.parent != repo_dir else repo_dir.name

            category = _detect_category(content)
            tools_used = detect_tools(content)

            # Construct a plausible GitHub URL
            # repo_dir name is typically 'owner-repo' after clone
            repo_name = repo_dir.name
            github_url = f"https://github.com/{repo_name}/blob/main/{rel_path.as_posix()}"

            writeups.append({
                "id": file_id,
                "title": file_path.stem.replace("_", " ").replace("-", " ").title(),
                "ctf_name": ctf_name,
                "category": category,
                "content": content,
                "tools_used": tools_used,
                "url": github_url,
                "source": "github",
            })

    return writeups


# ── Main Loaders ───────────────────────────────────────────────────────────


def load_from_repos(
    repos: list[str],
    output_dir: Optional[Path] = None,
    limit: int = 500,
) -> list[dict]:
    """Clone repos, scan for writeups, and save as JSON.

    Parameters
    ----------
    repos:
        List of GitHub repos in ``owner/name`` format.
    output_dir:
        Where to write JSON writeup files.  Defaults to
        ``DATA_DIR / 'github'``.
    limit:
        Maximum total writeups to collect across all repos.

    Returns
    -------
    list[dict]
        Combined list of writeup dicts from all repos.
    """
    from ctfgpt.config import DATA_DIR  # noqa: WPS433

    if output_dir is None:
        output_dir = DATA_DIR / "github"
    output_dir.mkdir(parents=True, exist_ok=True)

    all_writeups: list[dict] = []

    # Parse each repo entry: may be owner/repo or a full GitHub URL
    parsed_repos: list[tuple[str, Optional[str]]] = [
        parse_github_input(r) for r in repos
    ]

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
    ) as progress:
        task = progress.add_task("Loading GitHub repos…", total=len(parsed_repos))

        for repo, subdir in parsed_repos:
            if len(all_writeups) >= limit:
                break

            with tempfile.TemporaryDirectory(prefix="ctfgpt_") as tmp:
                clone_dir = Path(tmp) / repo.replace("/", "_")
                if not clone_repo(repo, clone_dir):
                    progress.update(task, advance=1)
                    continue

                repo_writeups = scan_repo_for_writeups(clone_dir, subdir=subdir)

                # Respect the global limit
                remaining = limit - len(all_writeups)
                repo_writeups = repo_writeups[:remaining]

                # Update the GitHub URLs now that we know the real repo name
                for wu in repo_writeups:
                    rel_part = wu["url"].split("/blob/main/", 1)
                    if len(rel_part) == 2:
                        wu["url"] = f"https://github.com/{repo}/blob/main/{rel_part[1]}"

                # Persist to disk
                for wu in repo_writeups:
                    out_path = output_dir / f"{wu['id']}.json"
                    try:
                        out_path.write_text(
                            json.dumps(wu, indent=2, ensure_ascii=False),
                            encoding="utf-8",
                        )
                    except OSError as exc:
                        console.print(
                            f"[yellow]⚠  Could not save {out_path}: {exc}[/]"
                        )

                all_writeups.extend(repo_writeups)
                console.print(
                    f"[dim]  ↳ {repo}{f'/{subdir}' if subdir else ''}: "
                    f"{len(repo_writeups)} writeups extracted[/]"
                )

            progress.update(task, advance=1)

    console.print(
        f"[green]✓  Loaded {len(all_writeups)} writeups from "
        f"{len(repos)} repos → {output_dir}[/]"
    )
    return all_writeups


def load_from_urls(
    urls: list[str],
    output_dir: Optional[Path] = None,
) -> list[dict]:
    """Fetch individual files from raw GitHub URLs and save as writeup JSON.

    Parameters
    ----------
    urls:
        List of raw GitHub URLs pointing to markdown / text files.
    output_dir:
        Where to write JSON writeup files.  Defaults to
        ``DATA_DIR / 'github'``.

    Returns
    -------
    list[dict]
        List of writeup dicts (one per successfully fetched URL).
    """
    from ctfgpt.config import DATA_DIR  # noqa: WPS433
    from ingestion.chunker import detect_tools  # noqa: WPS433

    if output_dir is None:
        output_dir = DATA_DIR / "github"
    output_dir.mkdir(parents=True, exist_ok=True)

    writeups: list[dict] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
    ) as progress:
        task = progress.add_task("Fetching GitHub URLs…", total=len(urls))

        for url in urls:
            content = fetch_raw_file(url)
            if content is None or len(content.strip()) < 200:
                console.print(f"[yellow]⚠  Skipping {url}: no usable content[/]")
                progress.update(task, advance=1)
                continue

            file_id = hashlib.md5(url.encode()).hexdigest()[:12]

            # Extract a title from the URL path
            url_path = url.split("/")
            filename = url_path[-1] if url_path else "unknown"
            title = (
                Path(filename)
                .stem.replace("_", " ")
                .replace("-", " ")
                .title()
            )

            category = _detect_category(content)
            tools_used = detect_tools(content)

            writeup: dict = {
                "id": file_id,
                "title": title,
                "ctf_name": url_path[-2] if len(url_path) >= 2 else "github",
                "category": category,
                "content": content,
                "tools_used": tools_used,
                "url": url,
                "source": "github",
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
        f"[green]✓  Fetched {len(writeups)}/{len(urls)} URLs → {output_dir}[/]"
    )
    return writeups


# ── Sync Entry-point ───────────────────────────────────────────────────────


def run_github_loader(
    repos: Optional[list[str]] = None,
    urls: Optional[list[str]] = None,
    limit: int = 500,
    include_default: bool = True,
) -> list[dict]:
    """Synchronous entry point combining repo cloning and URL fetching.

    Accepts both ``owner/repo`` shorthand and full GitHub URLs (including
    optional ``/tree/<branch>/<subdir>`` path components).

    Parameters
    ----------
    repos:
        GitHub repos or full GitHub URLs. When ``None`` and
        *include_default* is ``True``, the built-in :data:`CTFGPT_REPOS`
        list is used.
    urls:
        Optional list of raw GitHub file URLs to fetch individually
        (points to specific .md files, not repo pages).
    limit:
        Maximum total writeups from repo cloning.
    include_default:
        When ``True`` (default), always include :data:`CTFGPT_REPOS`
        in addition to any *repos* argument.

    Returns
    -------
    list[dict]
        Combined list of writeup dicts from both methods.
    """
    all_writeups: list[dict] = []

    # ── Build target repo list ─────────────────────────────────────────
    target_repos: list[str] = []
    if repos is not None:
        target_repos.extend(repos)
    if include_default:
        for r in CTFGPT_REPOS:
            if r not in target_repos:
                target_repos.append(r)
    if not target_repos:
        target_repos = DEFAULT_REPOS

    # ── Clone and scan repos ──────────────────────────────────────────
    if target_repos:
        all_writeups.extend(load_from_repos(target_repos, limit=limit))

    # ── Fetch individual raw file URLs ────────────────────────────────
    if urls:
        all_writeups.extend(load_from_urls(urls))

    console.print(
        f"[bold green]✓  GitHub loader complete: {len(all_writeups)} total writeups[/]"
    )
    return all_writeups


if __name__ == "__main__":
    run_github_loader()
