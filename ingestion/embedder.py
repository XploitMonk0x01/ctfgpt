"""Embed chunked documents and store in ChromaDB collections."""

from pathlib import Path
from typing import Optional

import chromadb
from langchain_chroma import Chroma
from langchain_core.documents import Document
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table

from ctfgpt.config import get_embeddings, DB_PATH, COLLECTIONS, CATEGORIES

console = Console()

# ── Vectorstore Access ─────────────────────────────────────────────────────


def get_vectorstore(
    category: str,
    embeddings=None,
) -> Chroma:
    """Return a LangChain :class:`Chroma` vectorstore for the given category.

    The vectorstore is backed by a persistent ChromaDB directory at
    :data:`DB_PATH`.  The collection is named ``ctfgpt_{category}``.

    Args:
        category: One of the canonical categories defined in
            :data:`ctfgpt.config.CATEGORIES`.
        embeddings: Optional pre-built embeddings instance.  When *None*,
            :func:`ctfgpt.config.get_embeddings` is called to create one.

    Returns:
        A ready-to-use :class:`Chroma` vectorstore.
    """
    if embeddings is None:
        embeddings = get_embeddings()

    collection_name = f"ctfgpt_{category}"

    # Ensure the persistent directory exists
    DB_PATH.mkdir(parents=True, exist_ok=True)

    return Chroma(
        collection_name=collection_name,
        embedding_function=embeddings,
        persist_directory=str(DB_PATH),
    )


# ── Embedding & Storage ───────────────────────────────────────────────────


def embed_and_store(
    documents: list[Document],
    batch_size: int = 100,
) -> dict[str, int]:
    """Embed *documents* and insert them into the matching ChromaDB collections.

    Documents are grouped by their ``metadata["category"]`` value.  Each
    group is added to the corresponding ``ctfgpt_{category}`` collection.
    Duplicates are handled by using ``chunk_id`` as the document ID — if a
    chunk with the same ID already exists it will be overwritten.

    Args:
        documents: LangChain :class:`Document` objects (as produced by
            :func:`ctfgpt.ingestion.chunker.chunk_documents`).
        batch_size: Number of documents per insertion batch.

    Returns:
        Mapping of ``{category: num_docs_added}``.
    """
    # Group by category
    by_category: dict[str, list[Document]] = {}
    for doc in documents:
        cat = doc.metadata.get("category", "forensics")
        by_category.setdefault(cat, []).append(doc)

    embeddings = get_embeddings()
    stats: dict[str, int] = {}

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
    ) as progress:
        total_docs = sum(len(docs) for docs in by_category.values())
        task = progress.add_task("Embedding & storing…", total=total_docs)

        for category, docs in by_category.items():
            vectorstore = get_vectorstore(category, embeddings=embeddings)

            # Process in batches
            for i in range(0, len(docs), batch_size):
                batch = docs[i : i + batch_size]

                # Serialise list/dict metadata values to JSON strings so
                # ChromaDB can store them (it only accepts str/int/float/bool).
                for doc in batch:
                    for key, value in doc.metadata.items():
                        if isinstance(value, (list, dict)):
                            doc.metadata[key] = _serialise_meta(value)

                texts = [d.page_content for d in batch]
                metadatas = [d.metadata for d in batch]
                ids = [d.metadata.get("chunk_id", f"auto_{i + j}") for j, d in enumerate(batch)]

                vectorstore.add_texts(texts=texts, metadatas=metadatas, ids=ids)
                progress.update(task, advance=len(batch))

            stats[category] = len(docs)
            console.print(
                f"  [cyan]↳ {category}[/]: {len(docs)} chunks stored "
                f"in [bold]ctfgpt_{category}[/]"
            )

    console.print(f"[green]✓  Stored {total_docs} chunks across {len(stats)} collections[/]")
    return stats


def _serialise_meta(value) -> str:
    """Convert a list or dict metadata value to a JSON string."""
    import json

    return json.dumps(value, ensure_ascii=False)


# ── Collection Stats ──────────────────────────────────────────────────────


def get_collection_stats() -> dict[str, int]:
    """Return the document count for every CTF-GPT ChromaDB collection.

    Uses :class:`chromadb.PersistentClient` for direct, low-level access
    (no embeddings required).

    Returns:
        Mapping of ``{collection_name: document_count}``.  Missing
        collections are reported with a count of ``0``.
    """
    stats: dict[str, int] = {}
    db_path = str(DB_PATH)

    if not DB_PATH.exists():
        return {name: 0 for name in COLLECTIONS}

    try:
        client = chromadb.PersistentClient(path=db_path)
        existing_names = {col.name for col in client.list_collections()}
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]✗  Could not open ChromaDB at {db_path}: {exc}[/]")
        return {name: 0 for name in COLLECTIONS}

    for collection_name in COLLECTIONS:
        if collection_name in existing_names:
            try:
                col = client.get_collection(collection_name)
                stats[collection_name] = col.count()
            except Exception:  # noqa: BLE001
                stats[collection_name] = 0
        else:
            stats[collection_name] = 0

    return stats


# ── Full Pipeline ─────────────────────────────────────────────────────────


def run_full_ingestion(
    source_dirs: Optional[list[Path]] = None,
    limit: int = 500,
) -> None:
    """Orchestrate the complete ingestion pipeline.

    Steps:

    1. Load writeup JSON files from *source_dirs*.
    2. Chunk the writeups into LangChain Documents.
    3. Embed and store chunks in ChromaDB.
    4. Print a summary statistics table.

    Args:
        source_dirs: List of directories containing writeup JSON files.
        limit: Maximum number of writeups to scrape (used as fallback).
    """
    from ctfgpt.config import DATA_DIR  # noqa: WPS433
    from ingestion.chunker import chunk_documents, load_writeups_from_dir

    if not source_dirs:
        # Default to all subdirectories in DATA_DIR
        source_dirs = [d for d in DATA_DIR.iterdir() if d.is_dir()] if DATA_DIR.exists() else []

    # ── 1. Load writeups from all sources ─────────────────────────────
    writeups = []
    for s_dir in source_dirs:
        loaded = load_writeups_from_dir(s_dir)
        writeups.extend(loaded)

    if not writeups:
        console.print("[yellow]No writeups found in any source directory.[/]")
        console.print("[dim]Use specific source flags (e.g. --source ctftime, --source github) to scrape data.[/dim]")
        return

    # ── 2. Chunk ──────────────────────────────────────────────────────
    documents = chunk_documents(writeups)
    if not documents:
        console.print("[red]✗  Chunking produced no documents. Aborting.[/]")
        return

    # ── 3. Embed & store ──────────────────────────────────────────────
    embed_and_store(documents)

    # ── 4. Print stats ────────────────────────────────────────────────
    stats = get_collection_stats()

    table = Table(title="CTF-GPT Knowledge Base — Collection Stats")
    table.add_column("Collection", style="cyan", no_wrap=True)
    table.add_column("Documents", style="green", justify="right")

    total = 0
    for name, count in sorted(stats.items()):
        table.add_row(name, str(count))
        total += count
    table.add_row("[bold]Total[/]", f"[bold]{total}[/]")

    console.print(table)


if __name__ == "__main__":
    run_full_ingestion()
