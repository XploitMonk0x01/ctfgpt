"""HackingArticles.in CTF challenge scraper for CTF-GPT knowledge base.

Scrapes the CTF Challenges category from https://www.hackingarticles.in
and converts each article into a writeup dict for embedding.
"""

import hashlib
import json
import re
import time
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin

import httpx
from bs4 import BeautifulSoup
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()

BASE_URL = "https://www.hackingarticles.in"
CATEGORY_URL = f"{BASE_URL}/category/ctf-challenges/"

HEADERS = {
    "User-Agent": (
        "CTF-GPT/1.0 (educational CTF assistant; "
        "https://github.com/user/ctfgpt)"
    ),
    "Accept": "text/html,application/xhtml+xml",
    "Accept-Language": "en-US,en;q=0.9",
}

# ---------------------------------------------------------------------------
# Category detection (same as loader_github.py)
# ---------------------------------------------------------------------------
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
    if not text:
        return "forensics"
    text_lower = text.lower()
    best_cat, best_score = "forensics", 0.0
    for category, keywords in _CATEGORY_KEYWORDS.items():
        hits = sum(1 for kw in keywords if kw in text_lower)
        score = hits / len(keywords) if keywords else 0.0
        if score > best_score:
            best_score = score
            best_cat = category
    return best_cat


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _get(url: str, retries: int = 3) -> Optional[str]:
    """Fetch a URL with retry logic. Returns HTML text or None."""
    for attempt in range(retries):
        try:
            with httpx.Client(headers=HEADERS, follow_redirects=True, timeout=30.0) as client:
                resp = client.get(url)
                resp.raise_for_status()
                return resp.text
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 429:
                wait = 10 * (attempt + 1)
                console.print(f"[yellow]Rate limited — waiting {wait}s before retry…[/]")
                time.sleep(wait)
            else:
                console.print(f"[yellow]⚠  HTTP {exc.response.status_code} for {url}[/]")
                return None
        except httpx.HTTPError as exc:
            console.print(f"[yellow]⚠  Network error fetching {url}: {exc}[/]")
            if attempt < retries - 1:
                time.sleep(3)
    return None


# ---------------------------------------------------------------------------
# Page parsing
# ---------------------------------------------------------------------------

def _get_article_links(page_html: str) -> list[str]:
    """Extract individual article URLs from a category listing page."""
    soup = BeautifulSoup(page_html, "html.parser")
    links = []

    # HackingArticles uses standard WordPress structure
    for article in soup.select("article"):
        a_tag = (
            article.select_one("h2.entry-title a")
            or article.select_one("h1.entry-title a")
            or article.select_one("a.more-link")
        )
        if a_tag and a_tag.get("href"):
            href = a_tag["href"]
            if not href.startswith("http"):
                href = urljoin(BASE_URL, href)
            if href not in links:
                links.append(href)

    return links


def _get_next_page_url(page_html: str) -> Optional[str]:
    """Find the 'next page' pagination link, if any."""
    soup = BeautifulSoup(page_html, "html.parser")
    next_link = soup.select_one("a.next.page-numbers")
    if next_link:
        return next_link.get("href")
    return None


def _parse_article(url: str, html: str) -> Optional[dict]:
    """Parse an article page into a writeup dict."""
    soup = BeautifulSoup(html, "html.parser")

    # Extract title
    title_tag = soup.select_one("h1.entry-title") or soup.select_one("h1")
    title = title_tag.get_text(strip=True) if title_tag else "Unknown Title"

    # Extract main content — WordPress entry-content div
    content_div = soup.select_one("div.entry-content")
    if not content_div:
        return None  # Not a real article

    # Remove unwanted elements: ads, share buttons, comment forms
    for tag in content_div.select(
        "script, style, .sharedaddy, .jp-relatedposts, "
        ".wp-block-buttons, form, .comments-area, "
        ".mejs-container, noscript, iframe"
    ):
        tag.decompose()

    # Get clean text
    content = content_div.get_text(separator="\n", strip=True)

    if len(content.strip()) < 300:
        return None  # Too short, skip

    category = _detect_category(content)

    file_id = hashlib.md5(url.encode()).hexdigest()[:12]

    # Try to detect tools used
    try:
        from ingestion.chunker import detect_tools
        tools_used = detect_tools(content)
    except ImportError:
        tools_used = []

    return {
        "id": file_id,
        "title": title,
        "ctf_name": "hackingarticles",
        "category": category,
        "content": content,
        "tools_used": tools_used,
        "url": url,
        "source": "hackingarticles",
    }


# ---------------------------------------------------------------------------
# Main scraper
# ---------------------------------------------------------------------------

def run_hackingarticles_scraper(
    limit: int = 200,
    output_dir: Optional[Path] = None,
    delay: float = 1.5,
) -> list[dict]:
    """Scrape CTF challenge writeups from HackingArticles.in.

    Parameters
    ----------
    limit:
        Maximum number of articles to scrape.
    output_dir:
        Where to write JSON writeup files. Defaults to ``DATA_DIR / 'hackingarticles'``.
    delay:
        Seconds to wait between requests to be polite to the server.

    Returns
    -------
    list[dict]
        List of writeup dicts.
    """
    from ctfgpt.config import DATA_DIR

    if output_dir is None:
        output_dir = DATA_DIR / "hackingarticles"
    output_dir.mkdir(parents=True, exist_ok=True)

    all_links: list[str] = []
    current_url: Optional[str] = CATEGORY_URL

    console.print(f"[cyan]→ Discovering HackingArticles CTF pages (limit: {limit})…[/]")

    # Collect all article URLs from pagination
    while current_url and len(all_links) < limit:
        html = _get(current_url)
        if not html:
            break

        page_links = _get_article_links(html)
        for link in page_links:
            if link not in all_links:
                all_links.append(link)
                if len(all_links) >= limit:
                    break

        console.print(
            f"  [dim]Page: {current_url} → {len(page_links)} articles found "
            f"(total: {len(all_links)})[/]"
        )

        current_url = _get_next_page_url(html)
        time.sleep(delay)

    console.print(f"[green]✓  Discovered {len(all_links)} article URLs[/]")

    # Scrape each article
    writeups: list[dict] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
    ) as progress:
        task = progress.add_task(
            "Scraping HackingArticles…", total=len(all_links)
        )

        for url in all_links:
            time.sleep(delay)
            html = _get(url)
            if not html:
                progress.update(task, advance=1)
                continue

            writeup = _parse_article(url, html)
            if writeup is None:
                progress.update(task, advance=1)
                continue

            out_path = output_dir / f"{writeup['id']}.json"
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
        f"[bold green]✓  HackingArticles scraper complete: "
        f"{len(writeups)}/{len(all_links)} articles ingested → {output_dir}[/]"
    )
    return writeups


if __name__ == "__main__":
    run_hackingarticles_scraper(limit=50)
