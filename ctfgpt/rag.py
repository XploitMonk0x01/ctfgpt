"""RAG chain for CTF-GPT hint generation.

Retrieves relevant CTF writeup chunks from a per-category ChromaDB
collection, assembles a tiered prompt, and streams a response through
the configured LLM.  Falls back gracefully to a pure-LLM answer when
the knowledge base is empty or inaccessible.
"""

from functools import lru_cache
from typing import Optional

from langchain_chroma import Chroma
from langchain_core.documents import Document
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.output_parsers import StrOutputParser
from rich.console import Console

from ctfgpt.config import get_llm, get_embeddings, DB_PATH, COLLECTIONS

console = Console()

# ---------------------------------------------------------------------------
# Prompt constants
# ---------------------------------------------------------------------------

LEVEL_INSTRUCTIONS: dict[int, str] = {
    1: "One sentence only. Point to what deserves attention. No technique names, no tool names.",
    2: "Name the technique family. Explain briefly why it fits this challenge. No specific tool names or commands.",
    3: (
        "Name the exact tool, exact flags, exact approach. "
        "Provide a step-by-step methodology. Still NEVER reveal the flag value."
    ),
}

LEVEL_NAMES: dict[int, str] = {
    1: "Nudge",
    2: "Technique",
    3: "Full Approach",
}

SYSTEM_PROMPT = """\
You are a CTF mentor. Guide the solver — never solve for them.
Rules:
- NEVER reveal the flag or its value
- NEVER provide complete working exploit code
- Match hint depth to the requested level
- Reference specific writeups or techniques when relevant
- If session evidence is provided, use it to give grounded, specific hints

Category: {category}
Hint Level: {level} ({level_name})

Relevant Writeup Knowledge:
{rag_context}

Current Session Evidence (from live tool runs):
{blackboard_summary}

Challenge Description:
{query}

Respond at level {level}. {level_instruction}"""

_NO_DOCS_NOTICE = (
    "No writeup data available yet. "
    "Run 'ctfgpt ingest' to build the knowledge base."
)


# ---------------------------------------------------------------------------
# 1. Vectorstore access
# ---------------------------------------------------------------------------

@lru_cache(maxsize=8)
def get_vectorstore(category: str) -> Chroma:
    """Return a ChromaDB vectorstore for the given CTF category.

    Parameters
    ----------
    category:
        One of the six CTF categories (e.g. ``"forensics"``).

    Returns
    -------
    Chroma
        A LangChain ``Chroma`` wrapper pointing at the persisted
        collection ``ctfgpt_{category}``.
    """
    collection_name = f"ctfgpt_{category}"
    return Chroma(
        collection_name=collection_name,
        embedding_function=get_embeddings(),
        persist_directory=str(DB_PATH),
    )


# ---------------------------------------------------------------------------
# 2. Retriever
# ---------------------------------------------------------------------------

def get_retriever(category: str, k: int = 5):
    """Return an MMR retriever for the given category.

    Uses Maximal Marginal Relevance to balance relevance and diversity
    in retrieved documents.

    Parameters
    ----------
    category:
        CTF category name.
    k:
        Number of documents to return.

    Returns
    -------
    langchain_core.retrievers.BaseRetriever
        A retriever configured for MMR search.
    """
    vectorstore = get_vectorstore(category)
    return vectorstore.as_retriever(
        search_type="mmr",
        search_kwargs={"k": k, "fetch_k": 20, "lambda_mult": 0.5},
    )


# ---------------------------------------------------------------------------
# 3. Document formatting
# ---------------------------------------------------------------------------

def format_docs(docs: list[Document]) -> str:
    """Format retrieved documents into a context string for the prompt.

    Each document is rendered with its source and technique metadata
    (when available) followed by the page content.

    Parameters
    ----------
    docs:
        List of LangChain ``Document`` objects from the retriever.

    Returns
    -------
    str
        A newline-separated context block.
    """
    if not docs:
        return _NO_DOCS_NOTICE

    parts: list[str] = []
    for idx, doc in enumerate(docs, 1):
        meta = doc.metadata or {}
        source = meta.get("source", "unknown")
        technique = meta.get("technique", "")

        header_parts = [f"[{idx}] Source: {source}"]
        if technique:
            header_parts.append(f"Technique: {technique}")
        header = " | ".join(header_parts)

        parts.append(f"{header}\n{doc.page_content}")

    return "\n\n---\n\n".join(parts)


# ---------------------------------------------------------------------------
# 4. Prompt assembly
# ---------------------------------------------------------------------------

def build_prompt(
    query: str,
    category: str,
    level: int,
    rag_context: str,
    blackboard_summary: str = "",
) -> str:
    """Assemble the full system prompt from the template.

    Parameters
    ----------
    query:
        The user's challenge description or question.
    category:
        Detected / overridden CTF category.
    level:
        Hint depth (1-3).
    rag_context:
        Formatted retrieval context or a fallback notice.
    blackboard_summary:
        Optional evidence gathered from live tool runs.

    Returns
    -------
    str
        The fully interpolated prompt string.
    """
    level_name = LEVEL_NAMES.get(level, "Hint")
    level_instruction = LEVEL_INSTRUCTIONS.get(level, LEVEL_INSTRUCTIONS[1])

    return SYSTEM_PROMPT.format(
        category=category,
        level=level,
        level_name=level_name,
        rag_context=rag_context,
        blackboard_summary=blackboard_summary or "None yet.",
        query=query,
        level_instruction=level_instruction,
    )


# ---------------------------------------------------------------------------
# 5. Main RAG pipeline
# ---------------------------------------------------------------------------

def ask(
    query: str,
    category: str,
    level: int = 1,
    blackboard_summary: str = "",
) -> tuple[str, list[str]]:
    """Run the full RAG pipeline and return a hint.

    Attempts to retrieve relevant writeup chunks from ChromaDB.  If the
    vectorstore is empty or unavailable the function falls back to a
    pure-LLM response with a notice that the knowledge base should be
    populated.

    Parameters
    ----------
    query:
        The user's challenge description or question.
    category:
        CTF category (e.g. ``"web"``).
    level:
        Hint depth (1 = Nudge, 2 = Technique, 3 = Full Approach).
    blackboard_summary:
        Optional session evidence from Kali tool runs.

    Returns
    -------
    tuple[str, list[str]]
        ``(hint_text, source_urls)`` — the generated hint and a list of
        source references extracted from the retrieved documents.
    """
    llm = get_llm(role="responder")
    rag_context: str = _NO_DOCS_NOTICE
    sources: list[str] = []

    # --- Attempt retrieval ------------------------------------------------
    try:
        retriever = get_retriever(category)
        # Search query combines the user's intent with actual tool evidence
        search_query = query
        if blackboard_summary:
            search_query += "\n\nEvidence found:\n" + blackboard_summary
        docs: list[Document] = retriever.invoke(search_query)

        if docs:
            rag_context = format_docs(docs)
            sources = _extract_sources(docs)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[dim yellow]⚠  Retrieval failed ({exc}) — using LLM only.[/dim yellow]")
        rag_context = "Context retrieval temporarily unavailable — answer using general knowledge."

    # --- Build prompt & call LLM ------------------------------------------
    prompt_text = build_prompt(
        query=query,
        category=category,
        level=level,
        rag_context=rag_context,
        blackboard_summary=blackboard_summary,
    )

    try:
        # Use direct messages instead of ChatPromptTemplate to avoid
        # LangChain re-parsing { } characters in RAG content (code, JSON etc)
        messages = [
            SystemMessage(content=prompt_text),
        ]
        response_msg = llm.invoke(messages)
        # LangChain models return AIMessage; Groq returns str directly
        if hasattr(response_msg, "content"):
            response = str(response_msg.content)
        else:
            response = str(response_msg)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[bold red]❌ LLM call failed: {exc}[/bold red]")
        response = (
            "I couldn't generate a hint right now. "
            "Please check your LLM configuration with `ctfgpt status`."
        )

    return response, sources


def _extract_sources(docs: list[Document]) -> list[str]:
    """Pull unique source paths / URLs from document metadata."""
    seen: set[str] = set()
    sources: list[str] = []
    for doc in docs:
        src = (doc.metadata or {}).get("source", "")
        if src and src not in seen:
            seen.add(src)
            sources.append(src)
    return sources


# ---------------------------------------------------------------------------
# 6. DB health check
# ---------------------------------------------------------------------------

def check_db_status() -> tuple[bool, dict[str, int]]:
    """Check ChromaDB accessibility and return document counts.

    Uses ``chromadb.PersistentClient`` directly so that the embedding
    model is **not** loaded — keeping ``ctfgpt status`` fast.

    Returns
    -------
    tuple[bool, dict[str, int]]
        ``(is_healthy, {collection_name: doc_count})``.
    """
    import chromadb

    stats: dict[str, int] = {}
    db_path = str(DB_PATH)

    if not DB_PATH.exists():
        return False, {col: 0 for col in COLLECTIONS}

    try:
        client = chromadb.PersistentClient(path=db_path)
        existing = {c.name for c in client.list_collections()}

        for collection_name in COLLECTIONS:
            if collection_name in existing:
                try:
                    col = client.get_collection(collection_name)
                    stats[collection_name] = col.count()
                except Exception:
                    stats[collection_name] = 0
            else:
                stats[collection_name] = 0

        return True, stats
    except Exception:
        return False, {col: 0 for col in COLLECTIONS}

