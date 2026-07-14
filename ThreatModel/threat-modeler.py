#!/usr/bin/env python3
"""
AI Threat Modeler
=================
AI-powered threat modeling tool with built-in RAG pipeline.

Reads a product info document (.md) and an internal security best practices document (.txt), builds a FAISS vector index over the best practices, then runs a two-pass GPT-4o analysis:

  Pass 1 — Identify threats from the product document.
  Pass 2 — For each threat, retrieve the most relevant best practice chunks via semantic search and ask GPT-4o to generate grounded countermeasures.

Output: a structured JSON threat model report.

Usage:
    python threat-modeler.py \\
        --product product-info.md \\
        --best-practices security-best-practices.txt \\
        --output threat-model.json \\
        [--model gpt-4o] \\
        [--top-k 4] \\
        [--cache-dir .rag_cache] \\
        [--verbose]

Dependencies:
    pip install openai faiss-cpu numpy
"""

import faiss
import openai
import argparse
import hashlib
import json
import os
import sys
import textwrap
import time
import numpy as np
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# Section 1 — Chunker
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Chunk:
    chunk_id: int
    text: str
    source_file: str

def chunk_text(
    text: str,
    source_file: str,
    chunk_size: int = 400,
    overlap: int = 50,
    min_chunk_size: int = 30,
) -> list[Chunk]:
    """
    Split `text` into overlapping sliding-window chunks (measured in words).
    Returns a list of Chunk objects.
    """
    words = text.split()
    step = chunk_size - overlap
    chunks: list[Chunk] = []
    chunk_id = 0
    i = 0

    while i < len(words):
        window = words[i : i + chunk_size]
        if len(window) < min_chunk_size:
            break
        chunks.append(
            Chunk(
                chunk_id=chunk_id,
                text=" ".join(window),
                source_file=source_file,
            )
        )
        chunk_id += 1
        i += step

    return chunks

# ─────────────────────────────────────────────────────────────────────────────
# Section 2 — Embedder
# ─────────────────────────────────────────────────────────────────────────────

EMBEDDING_MODEL = "text-embedding-3-small"
EMBED_BATCH_SIZE = 100
EMBED_MAX_RETRIES = 5
EMBED_RETRY_BASE_DELAY = 1.0  # seconds

def embed_texts(client: OpenAI, texts: list[str], verbose: bool = False) -> np.ndarray:
    """
    Embed a list of texts using OpenAI text-embedding-3-small.
    Handles batching and exponential-backoff retries.
    Returns a (N, D) float32 numpy array.
    """
    all_embeddings: list[list[float]] = []

    for batch_start in range(0, len(texts), EMBED_BATCH_SIZE):
        batch = texts[batch_start : batch_start + EMBED_BATCH_SIZE]

        if verbose:
            end = min(batch_start + EMBED_BATCH_SIZE, len(texts))
            print(f"  [Embed] chunks {batch_start + 1}–{end} / {len(texts)} ...")

        for attempt in range(EMBED_MAX_RETRIES):
            try:
                response = client.embeddings.create(model=EMBEDDING_MODEL, input=batch)
                all_embeddings.extend(item.embedding for item in response.data)
                break
            except Exception as exc:
                if attempt == EMBED_MAX_RETRIES - 1:
                    raise RuntimeError(f"Embedding failed after {EMBED_MAX_RETRIES} retries: {exc}") from exc
                delay = EMBED_RETRY_BASE_DELAY * (2 ** attempt)
                if verbose:
                    print(f"  [Embed] Retrying in {delay:.1f}s ({exc}) ...")
                time.sleep(delay)

    return np.array(all_embeddings, dtype=np.float32)

def embed_query(client: OpenAI, query: str) -> np.ndarray:
    """Embed a single query string. Returns a (1, D) float32 array."""
    return embed_texts(client, [query], verbose=False)

# ─────────────────────────────────────────────────────────────────────────────
# Section 3 — FAISS Index (with disk cache)
# ─────────────────────────────────────────────────────────────────────────────

INDEX_SUFFIX = ".index"
META_SUFFIX  = ".meta.json"

def _doc_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]

def _index_paths(cache_dir: Path, content_hash: str) -> tuple[Path, Path]:
    return (
        cache_dir / f"{content_hash}{INDEX_SUFFIX}",
        cache_dir / f"{content_hash}{META_SUFFIX}",
    )

def build_index(
    client: OpenAI,
    chunks: list[Chunk],
    cache_dir: Path,
    content_hash: str,
    verbose: bool = False,
) -> faiss.Index:
    """Embed all chunks, build a FAISS IndexFlatIP, and persist to disk."""
    texts = [c.text for c in chunks]
    embeddings = embed_texts(client, texts, verbose=verbose)
    faiss.normalize_L2(embeddings)  # unit-normalise for cosine similarity via inner product

    index = faiss.IndexFlatIP(embeddings.shape[1])
    index.add(embeddings)

    idx_path, meta_path = _index_paths(cache_dir, content_hash)
    faiss.write_index(index, str(idx_path))
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump([asdict(c) for c in chunks], f, indent=2)

    if verbose:
        print(f"  [FAISS] Built index: {len(chunks)} chunks, dim={embeddings.shape[1]}. Cached → {cache_dir}/")

    return index, chunks

def load_index(
    cache_dir: Path,
    content_hash: str,
    verbose: bool = False,
) -> tuple[Optional[faiss.Index], list[Chunk]]:
    """Load a cached FAISS index from disk. Returns (None, []) on cache miss."""
    idx_path, meta_path = _index_paths(cache_dir, content_hash)

    if not idx_path.exists() or not meta_path.exists():
        return None, []

    try:
        index = faiss.read_index(str(idx_path))
        with open(meta_path, "r", encoding="utf-8") as f:
            chunks = [Chunk(**m) for m in json.load(f)]
        if verbose:
            print(f"  [FAISS] Loaded cached index ({len(chunks)} chunks) from {cache_dir}/")
        return index, chunks
    except Exception as exc:
        if verbose:
            print(f"  [FAISS] Cache load failed ({exc}), will rebuild.")
        return None, []

def retrieve(
    client: OpenAI,
    index: faiss.Index,
    chunks: list[Chunk],
    query: str,
    top_k: int = 4,
) -> list[tuple[Chunk, float]]:
    """
    Retrieve the top_k most relevant chunks for a natural-language query.
    Returns a list of (Chunk, cosine_score) tuples, sorted by descending score.
    """
    q = embed_query(client, query).astype(np.float32)
    faiss.normalize_L2(q)
    scores, indices = index.search(q, top_k)

    results = []
    for score, idx in zip(scores[0], indices[0]):
        if idx == -1:
            continue
        results.append((chunks[idx], float(score)))

    return results

def format_context(retrieved: list[tuple[Chunk, float]]) -> str:
    """Format retrieved chunks as a prompt-ready context block."""
    if not retrieved:
        return "No relevant best practices found."
    parts = []
    for rank, (chunk, score) in enumerate(retrieved, start=1):
        parts.append(f"[Excerpt {rank} | relevance: {score:.2f}]\n{chunk.text.strip()}")
    return "\n\n---\n\n".join(parts)

# ─────────────────────────────────────────────────────────────────────────────
# Section 4 — Prompts
# ─────────────────────────────────────────────────────────────────────────────

PASS1_SYSTEM = textwrap.dedent("""
    You are a senior security architect with deep expertise in threat modeling, application security, and cloud infrastructure.

    Your task is to analyse a product information document and produce a structured list of security threats. Choose the most appropriate threat modeling framework for this product (e.g., STRIDE, PASTA, LINDDUN, or a hybrid) and justify your choice. Be specific to the product — avoid generic, copy-paste threats.

    Respond ONLY with a valid JSON object. No markdown fences, no commentary.
""").strip()

def pass1_user_prompt(product_info: str) -> str:
    schema = textwrap.dedent("""
        {
          "framework_selected": "<framework name>",
          "framework_rationale": "<1-2 sentence justification>",
          "product_summary": {
            "name": "<product name>",
            "description": "<brief description>",
            "key_assets": ["<asset>"],
            "entry_points": ["<entry point>"],
            "trust_boundaries": ["<boundary>"],
            "actors": [{"name": "<actor>", "type": "internal|external|third-party"}]
          },
          "threats": [
            {
              "id": "T-001",
              "title": "<short threat title>",
              "category": "<framework category>",
              "affected_component": "<component or asset>",
              "description": "<detailed, product-specific threat description>",
              "attack_vector": "<how an attacker exploits this>",
              "attacker_profile": "<who performs this attack>",
              "impact": {
                "confidentiality": "High|Medium|Low|None",
                "integrity": "High|Medium|Low|None",
                "availability": "High|Medium|Low|None"
              },
              "severity": "Critical|High|Medium|Low"
            }
          ]
        }
    """).strip()

    return textwrap.dedent(f"""
        ## Product Information Document

        {product_info}

        ---

        Analyse this product and return a JSON object matching this schema exactly:

        {schema}

        Requirements:
        - Number threats T-001, T-002, … ordered by descending severity.
        - Every threat must be specific to this product's architecture and context.
        - Return valid JSON only — no markdown, no trailing commas, no comments.
    """).strip()

PASS2_SYSTEM = textwrap.dedent("""
    You are a senior security architect generating actionable countermeasures for a specific security threat.

    You will be given:
    1. A threat description from a threat model.
    2. Excerpts from an internal security best practices document, retrieved by semantic similarity to this threat.

    Your job is to produce concrete, prioritised countermeasures grounded in the provided best practice excerpts. Where a best practice excerpt is directly relevant, reference it explicitly (quote its control ID or a short descriptive label). If the excerpts do not cover a gap, supplement with general industry guidance and note it as such.

    Respond ONLY with a valid JSON object. No markdown fences, no commentary.
""").strip()

def pass2_user_prompt(threat: dict, context: str) -> str:
    schema = textwrap.dedent("""
        {
          "countermeasures": [
            {
              "description": "<specific, actionable recommendation>",
              "best_practice_reference": "<control ID / label from excerpts, or 'General industry guidance'>",
              "priority": "Immediate|Short-term|Long-term"
            }
          ],
          "residual_risk": "<brief note on remaining risk after countermeasures>"
        }
    """).strip()

    return textwrap.dedent(f"""
        ## Threat

        ID       : {threat['id']}
        Title    : {threat['title']}
        Category : {threat['category']}
        Component: {threat['affected_component']}
        Severity : {threat['severity']}

        {threat['description']}

        Attack vector   : {threat.get('attack_vector', 'N/A')}
        Attacker profile: {threat.get('attacker_profile', 'N/A')}

        ---

        ## Relevant Best Practice Excerpts (retrieved by semantic search)

        {context}

        ---

        Generate countermeasures as a JSON object matching this schema:

        {schema}

        Requirements:
        - Provide 2–5 countermeasures, prioritised (Immediate first).
        - Cite control IDs or labels from the excerpts wherever possible.
        - Be specific — avoid generic advice like "use encryption" without detail.
        - Return valid JSON only.
    """).strip()

# ─────────────────────────────────────────────────────────────────────────────
# Section 5 — AI calls
# ─────────────────────────────────────────────────────────────────────────────

def call_llm(client: OpenAI, model: str, system: str, user: str) -> dict:
    """Call the OpenAI chat API in JSON mode and return parsed output."""
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system},
            {"role": "user",   "content": user},
        ],
        temperature=0.2,
        response_format={"type": "json_object"},
    )
    raw = response.choices[0].message.content
    try:
        return json.loads(raw), response.model, response.usage
    except json.JSONDecodeError as exc:
        raise ValueError(f"Model returned invalid JSON: {exc}\n\nRaw output:\n{raw}") from exc

# ─────────────────────────────────────────────────────────────────────────────
# Section 6 — Two-pass orchestration
# ─────────────────────────────────────────────────────────────────────────────

def run_threat_model(
    client: OpenAI,
    model: str,
    product_info: str,
    index: faiss.Index,
    chunks: list[Chunk],
    top_k: int,
    verbose: bool,
) -> dict:
    """
    Execute the two-pass threat modeling pipeline.

    Pass 1: Identify threats from the product document.
    Pass 2: For each threat, retrieve relevant best practice chunks and
            generate grounded countermeasures.
    """

    # ── Pass 1 — Threat identification ───────────────────────────────────────────────
    if verbose:
        print("\n[Pass 1] Identifying threats ...")

    pass1_result, model_used, usage1 = call_llm(
        client, model,
        system=PASS1_SYSTEM,
        user=pass1_user_prompt(product_info),
    )

    threats = pass1_result.get("threats", [])

    if verbose:
        print(f"  → [Pass 1] Identifying threats ... Completed.")

    # ── Pass 2 — RAG-grounded countermeasure generation (per threat) ─────────────────
    if verbose:
        print("\n[Pass 2] Generating RAG-grounded countermeasures ...")

    for threat in threats:
        if verbose:
            print(f"  [{threat['id']}] {threat['title']} ({threat['severity']}) ...")

        # Semantic search over best practices
        query = f"{threat['title']}. {threat['description']}. {threat.get('attack_vector', '')}"
        retrieved = retrieve(client, index, chunks, query, top_k=top_k)
        context = format_context(retrieved)

        # LLM call for countermeasures
        pass2_result, _, usage2 = call_llm(
            client, model,
            system=PASS2_SYSTEM,
            user=pass2_user_prompt(threat, context),
        )

        threat["countermeasures"]  = pass2_result.get("countermeasures", [])
        threat["residual_risk"]    = pass2_result.get("residual_risk", "")
        threat["retrieved_excerpts"] = [
            {"rank": i + 1, "score": round(score, 3), "text": chunk.text[:300]}
            for i, (chunk, score) in enumerate(retrieved)
        ]

    if verbose:
        print(f"  → [Pass 2] Generating RAG-grounded countermeasures ... Completed.")

    # ── Assemble final report ────────────────────────────────────────────────────────
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    threats.sort(key=lambda t: severity_order.get(t.get("severity", "Low"), 4))

    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for t in threats:
        sev = t.get("severity", "")
        if sev in severity_counts:
            severity_counts[sev] += 1

    top_risks = [
        f"{t['id']}: {t['title']}"
        for t in threats
        if t.get("severity") in ("Critical", "High")
    ][:5]

    immediate_actions = []
    for t in threats:
        for cm in t.get("countermeasures", []):
            if cm.get("priority") == "Immediate":
                immediate_actions.append(f"[{t['id']}] {cm['description']}")
        if len(immediate_actions) >= 5:
            break

    report = {
        "meta": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "model_used": model_used,
            "embedding_model": EMBEDDING_MODEL,
            "framework_selected": pass1_result.get("framework_selected", ""),
            "framework_rationale": pass1_result.get("framework_rationale", ""),
            "rag": {
                "top_k": top_k,
                "total_chunks_indexed": len(chunks),
            },
        },
        "product_summary": pass1_result.get("product_summary", {}),
        "threats": threats,
        "threat_summary": {
            "total": len(threats),
            "by_severity": severity_counts,
            "top_risks": top_risks,
            "recommended_immediate_actions": immediate_actions,
        },
    }

    return report

# ─────────────────────────────────────────────────────────────────────────────
# Section 7 — Output Handling
# ─────────────────────────────────────────────────────────────────────────────

def save_report(report: dict, output_path: str) -> None:
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

def print_summary(report: dict) -> None:
    meta    = report.get("meta", {})
    product = report.get("product_summary", {})
    summary = report.get("threat_summary", {})
    by_sev  = summary.get("by_severity", {})

    sep = "=" * 68
    print(f"\n{sep}")
    print("  THREAT MODEL — SUMMARY")
    print(sep)
    print(f"  Product    : {product.get('name', 'Unknown')}")
    print(f"  Framework  : {meta.get('framework_selected', 'Unknown')}")
    print(f"  Model      : {meta.get('model_used', 'Unknown')}")
    print(f"  Generated  : {meta.get('generated_at', 'Unknown')}")
    print(f"  RAG chunks : {meta.get('rag', {}).get('total_chunks_indexed', '?')} "
          f"(top-k={meta.get('rag', {}).get('top_k', '?')})")
    print(sep)
    print(f"  Threats    : {summary.get('total', 0)}  |  "
          f"Critical: {by_sev.get('Critical', 0)}  "
          f"High: {by_sev.get('High', 0)}  "
          f"Medium: {by_sev.get('Medium', 0)}  "
          f"Low: {by_sev.get('Low', 0)}")
    print()

    top = summary.get("top_risks", [])
    if top:
        print("  TOP RISKS:")
        for r in top:
            print(f"    • {r}")
    print()

    actions = summary.get("recommended_immediate_actions", [])
    if actions:
        print("  IMMEDIATE ACTIONS:")
        for a in actions:
            print(f"    → {a}")

    print(sep)
    print()

def validate_report(report: dict) -> list[str]:
    """Return a list of structural warnings (empty = clean)."""
    warnings = []
    for key in ("meta", "product_summary", "threats", "threat_summary"):
        if key not in report:
            warnings.append(f"Missing top-level key: '{key}'")
    threats = report.get("threats", [])
    if not threats:
        warnings.append("No threats were identified.")
    for i, t in enumerate(threats):
        for field in ("id", "title", "severity", "countermeasures"):
            if field not in t:
                warnings.append(f"Threat #{i+1} missing field '{field}'")
        if not t.get("countermeasures"):
            warnings.append(f"Threat {t.get('id', f'#{i+1}')} has no countermeasures.")
    return warnings

# ─────────────────────────────────────────────────────────────────────────────
# Section 8 — Entry Point
# ─────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="AI threat modeler with RAG-grounded best practice recommendations.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
            Examples:
              python threat-modeler.py \\
                  --product product-info.md \\
                  --best-practices security-best-practices.txt

              python threat-modeler.py \\
                  --product product-info.md \\
                  --best-practices security-best-practices.txt \\
                  --output reports/model.json \\
                  --top-k 5 \\
                  --verbose
        """),
    )
    parser.add_argument("--product","-p", required=True, help="Product info document (.md)")
    parser.add_argument("--best-practices", "-b", required=True, dest="best_practices", help="Internal security best practices document (.txt)")
    parser.add_argument("--output", "-o", default="threat_model.json", help="Output JSON path (default: threat_model.json)")
    parser.add_argument("--model", "-m", default="gpt-4o", help="OpenAI model (default: gpt-4o)")
    parser.add_argument("--top-k", "-k", type=int, default=4, dest="top_k", help="Best practice chunks retrieved per threat (default: 4)")
    parser.add_argument("--cache-dir", default=".rag_cache", dest="cache_dir", help="Directory for the FAISS index cache (default: .rag_cache)")
    parser.add_argument("--api-key", default=None, help="OpenAI API key (falls back to OPENAI_API_KEY env var)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Print detailed progress")
    return parser.parse_args()

def main() -> None:
    args = parse_args()

    # ── API key ──────────────────────────────────────────────────────────────────────────
    api_key = args.api_key or os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print("[ERROR] No OpenAI API key. Set OPENAI_API_KEY or use --api-key.")
        sys.exit(1)

    client = OpenAI(api_key=api_key)

    # ── Load documents ───────────────────────────────────────────────────────────────────
    product_path = Path(args.product)
    bp_path      = Path(args.best_practices)

    if not product_path.exists():
        print(f"[ERROR] Product file not found: {product_path}")
        sys.exit(1)
    if not bp_path.exists():
        print(f"[ERROR] Best practices file not found: {bp_path}")
        sys.exit(1)

    product_info    = product_path.read_text(encoding="utf-8")
    best_practices  = bp_path.read_text(encoding="utf-8")

    if args.verbose:
        print(f"[INFO] Product doc  : {product_path} ({len(product_info):,} chars)")
        print(f"[INFO] Best practices: {bp_path} ({len(best_practices):,} chars)")

    # ── Build / load FAISS index ─────────────────────────────────────────────────────────
    cache_dir    = Path(args.cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    content_hash = _doc_hash(best_practices)

    if args.verbose:
        print(f"\n[RAG] Best practices hash: {content_hash}")

    index, chunks = load_index(cache_dir, content_hash, verbose=args.verbose)

    if index is None:
        if args.verbose:
            print("[RAG] Cache miss — chunking and embedding best practices ...")
        chunks = chunk_text(best_practices, source_file=bp_path.name)
        if args.verbose:
            print(f"[RAG] {len(chunks)} chunks created.")
        index, chunks = build_index(client, chunks, cache_dir, content_hash, verbose=args.verbose)

    # ── Run two-pass threat model ────────────────────────────────────────────────────────
    try:
        report = run_threat_model(
            client=client,
            model=args.model,
            product_info=product_info,
            index=index,
            chunks=chunks,
            top_k=args.top_k,
            verbose=args.verbose,
        )
    except Exception as exc:
        print(f"\n[ERROR] Threat modeling failed: {exc}")
        sys.exit(1)

    # ── Validate ─────────────────────────────────────────────────────────────────────────
    warnings = validate_report(report)
    if warnings:
        print("\n[WARNINGS]")
        for w in warnings:
            print(f"  ⚠  {w}")

    # ── Save + Print ─────────────────────────────────────────────────────────────────────
    save_report(report, args.output)
    print_summary(report)
    print(f"✓ Report saved to: {Path(args.output).resolve()}")


if __name__ == "__main__":
    main()
