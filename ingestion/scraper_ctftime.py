"""CTFtime.org writeup scraper for CTF-GPT knowledge base."""

import asyncio
import json
import re
from pathlib import Path
from typing import Optional

import httpx
from bs4 import BeautifulSoup
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()

BASE_URL = "https://ctftime.org"
WRITEUPS_URL = f"{BASE_URL}/writeups"
HEADERS = {
    "User-Agent": "CTF-GPT/0.1 (educational CTF assistant; +https://github.com/XploitMonk0x01/ctfgpt)",
    "Accept": "text/html,application/xhtml+xml",
}
DELAY = 1.5  # seconds between requests (polite scraping)

# Category mapping from CTFtime labels
CATEGORY_MAP: dict[str, str] = {
    "forensics": "forensics",
    "forensic": "forensics",
    "stego": "forensics",
    "steganography": "forensics",
    "web": "web",
    "web exploitation": "web",
    "crypto": "crypto",
    "cryptography": "crypto",
    "pwn": "pwn",
    "binary exploitation": "pwn",
    "exploitation": "pwn",
    "reverse": "reversing",
    "reversing": "reversing",
    "reverse engineering": "reversing",
    "re": "reversing",
    "osint": "osint",
    "misc": "forensics",  # misc goes to forensics as default
    "miscellaneous": "forensics",
}

# Known CTF tool names for metadata tagging
KNOWN_TOOLS: list[str] = [
    "binwalk", "strings", "exiftool", "foremost", "volatility", "wireshark",
    "nmap", "gobuster", "burpsuite", "sqlmap", "nikto", "dirb",
    "john", "hashcat", "cyberchef", "base64",
    "ghidra", "ida", "radare2", "gdb", "pwntools", "ltrace", "strace",
    "whois", "dig", "subfinder",
    "python", "php", "curl", "wget",
]


# ── Helper Functions ───────────────────────────────────────────────────────


def detect_tools(text: str) -> list[str]:
    """Scan *text* for mentions of known CTF tool names.

    Performs case-insensitive whole-word matching so that, e.g., "ida"
    is not falsely detected inside "validate".

    Returns:
        Sorted, deduplicated list of matched tool names (lower-case).
    """
    if not text:
        return []

    text_lower = text.lower()
    found: set[str] = set()
    for tool in KNOWN_TOOLS:
        # Use word-boundary matching to avoid false positives
        pattern = rf"\b{re.escape(tool)}\b"
        if re.search(pattern, text_lower):
            found.add(tool)
    return sorted(found)


def normalize_category(raw: str) -> str:
    """Map a raw CTFtime category label to one of our 6 canonical categories.

    Matching is case-insensitive.  Falls back to ``"forensics"`` when the
    label is unrecognised.
    """
    if not raw:
        return "forensics"
    return CATEGORY_MAP.get(raw.strip().lower(), "forensics")


def _extract_writeup_id(url: str) -> str:
    """Pull a numeric writeup ID out of a CTFtime writeup URL.

    Example URL: ``/writeup/12345`` → ``"12345"``
    """
    match = re.search(r"/writeup/(\d+)", url)
    return match.group(1) if match else url.strip("/").split("/")[-1]


# ── Async Scraping ─────────────────────────────────────────────────────────


async def scrape_writeup_list(
    client: httpx.AsyncClient,
    page: int,
) -> list[dict]:
    """Scrape a single page of the CTFtime writeups listing.

    Each page on ``/writeups?page=<n>`` contains a table of writeup links
    together with their associated CTF name and category tag.

    Args:
        client: Reusable ``httpx.AsyncClient`` with pre-set headers/timeouts.
        page: 1-indexed page number to fetch.

    Returns:
        A list of dicts, each with keys ``url``, ``title``, ``ctf_name``,
        and ``category``.
    """
    params = {"page": page}
    try:
        resp = await client.get(WRITEUPS_URL, params=params)
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        console.print(f"[yellow]⚠  Failed to fetch writeup list page {page}: {exc}[/]")
        return []

    soup = BeautifulSoup(resp.text, "html.parser")
    results: list[dict] = []

    # CTFtime lists writeups in <table> rows or <div class="writeupslist"> entries
    # Try table rows first (most common layout)
    table = soup.find("table")
    if table:
        rows = table.find_all("tr")
        for row in rows:
            cols = row.find_all("td")
            if len(cols) < 3:
                continue

            # First column: writeup link (title + URL)
            link_tag = cols[0].find("a", href=True)
            if not link_tag:
                continue
            href = link_tag["href"]
            if not href.startswith("/writeup/"):
                continue

            title = link_tag.get_text(strip=True)
            url = f"{BASE_URL}{href}"

            # Second column: CTF event name
            ctf_tag = cols[1].find("a")
            ctf_name = ctf_tag.get_text(strip=True) if ctf_tag else "Unknown CTF"

            # Third column (or tags): category
            raw_category = cols[2].get_text(strip=True) if len(cols) > 2 else ""
            category = normalize_category(raw_category)

            results.append({
                "url": url,
                "title": title,
                "ctf_name": ctf_name,
                "category": category,
            })
    else:
        # Fallback: parse <div> based listing
        for entry in soup.select("div.writeup, div.writeupslist div"):
            link_tag = entry.find("a", href=re.compile(r"/writeup/\d+"))
            if not link_tag:
                continue

            href = link_tag["href"]
            title = link_tag.get_text(strip=True)
            url = f"{BASE_URL}{href}" if href.startswith("/") else href

            ctf_tag = entry.find("a", href=re.compile(r"/event/"))
            ctf_name = ctf_tag.get_text(strip=True) if ctf_tag else "Unknown CTF"

            cat_tag = entry.find("a", href=re.compile(r"/tasks/"))
            raw_category = cat_tag.get_text(strip=True) if cat_tag else ""
            category = normalize_category(raw_category)

            results.append({
                "url": url,
                "title": title,
                "ctf_name": ctf_name,
                "category": category,
            })

    return results


async def scrape_writeup_content(
    client: httpx.AsyncClient,
    url: str,
) -> Optional[str]:
    """Fetch a single writeup page and extract its main textual content.

    Args:
        client: Reusable ``httpx.AsyncClient``.
        url: Full URL to the writeup page.

    Returns:
        Extracted body text, or ``None`` if the request or parsing failed.
    """
    try:
        resp = await client.get(url)
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        console.print(f"[yellow]⚠  Failed to fetch writeup {url}: {exc}[/]")
        return None

    try:
        soup = BeautifulSoup(resp.text, "html.parser")

        # Remove boilerplate elements
        for tag in soup.find_all(["script", "style", "nav", "header", "footer"]):
            tag.decompose()

        # Try the main content container first
        content_div = (
            soup.find("div", class_="writeup-content")
            or soup.find("div", class_="page-content")
            or soup.find("div", id="content")
            or soup.find("article")
            or soup.find("main")
        )

        if content_div:
            text = content_div.get_text(separator="\n", strip=True)
        else:
            # Last resort: grab the whole body
            body = soup.find("body")
            text = body.get_text(separator="\n", strip=True) if body else ""

        # Collapse excessive blank lines
        text = re.sub(r"\n{3,}", "\n\n", text).strip()
        return text if len(text) > 50 else None  # skip near-empty pages

    except Exception as exc:  # noqa: BLE001
        console.print(f"[yellow]⚠  Failed to parse writeup {url}: {exc}[/]")
        return None


async def scrape_ctftime(
    limit: int = 500,
    output_dir: Optional[Path] = None,
) -> list[dict]:
    """Scrape up to *limit* writeups from CTFtime.org.

    For each writeup the scraper:
    1. Fetches and parses the full writeup page.
    2. Detects tool mentions in the content.
    3. Saves the result as a JSON file in *output_dir*.

    Args:
        limit: Maximum number of writeups to scrape.
        output_dir: Destination directory for JSON files.  Defaults to
            ``DATA_DIR / "ctftime"`` (imported from config).

    Returns:
        List of writeup dicts with keys: ``id``, ``title``, ``ctf_name``,
        ``category``, ``content``, ``tools_used``, ``url``, ``source``.
    """
    # Lazy import to avoid circular dependency at module level
    from ctfgpt.config import DATA_DIR  # noqa: WPS433

    if output_dir is None:
        output_dir = DATA_DIR / "ctftime"
    output_dir.mkdir(parents=True, exist_ok=True)

    collected: list[dict] = []
    page = 1
    seen_urls: set[str] = set()

    async with httpx.AsyncClient(
        headers=HEADERS,
        follow_redirects=True,
        timeout=httpx.Timeout(30.0),
    ) as client:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
        ) as progress:
            task = progress.add_task("Scraping CTFtime writeups…", total=limit)

            while len(collected) < limit:
                # ── Fetch listing page ────────────────────────────────
                entries = await scrape_writeup_list(client, page)
                if not entries:
                    console.print("[yellow]No more writeup entries found — stopping.[/]")
                    break

                for entry in entries:
                    if len(collected) >= limit:
                        break
                    if entry["url"] in seen_urls:
                        continue
                    seen_urls.add(entry["url"])

                    # Polite delay between requests
                    await asyncio.sleep(DELAY)

                    # ── Fetch writeup content ─────────────────────────
                    content = await scrape_writeup_content(client, entry["url"])
                    if content is None:
                        progress.update(task, advance=0)
                        continue

                    writeup_id = _extract_writeup_id(entry["url"])
                    tools_used = detect_tools(content)

                    writeup: dict = {
                        "id": writeup_id,
                        "title": entry["title"],
                        "ctf_name": entry["ctf_name"],
                        "category": entry["category"],
                        "content": content,
                        "tools_used": tools_used,
                        "url": entry["url"],
                        "source": "ctftime",
                    }

                    # Persist to disk
                    out_path = output_dir / f"{writeup_id}.json"
                    try:
                        out_path.write_text(
                            json.dumps(writeup, indent=2, ensure_ascii=False),
                            encoding="utf-8",
                        )
                    except OSError as exc:
                        console.print(
                            f"[yellow]⚠  Could not save {out_path}: {exc}[/]"
                        )

                    collected.append(writeup)
                    progress.update(task, advance=1)

                page += 1
                await asyncio.sleep(DELAY)

    console.print(
        f"[green]✓  Scraped {len(collected)} writeups → {output_dir}[/]"
    )
    return collected


# ── Sync Entry-point ───────────────────────────────────────────────────────


def run_scraper(limit: int = 500) -> list[dict]:
    """Synchronous wrapper around :func:`scrape_ctftime`.

    Suitable for calling from a CLI command without an existing event loop.
    """
    return asyncio.run(scrape_ctftime(limit=limit))


if __name__ == "__main__":
    run_scraper()
