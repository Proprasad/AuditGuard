"""
Deterministic Corpus v2 Builder (`data/regulatory_corpus/build_corpus_v2.py`).

Generates:
  1. `data/regulatory_corpus/indian_aml_corpus.jsonl` (>= 150 verifiable passages, 100-300 words each,
     strict separation of `source_type: "regulatory"` vs `source_type: "internal"`).
  2. `data/regulatory_corpus/HUMAN_VERIFICATION_CHECKLIST.md` for `[HUMAN]` verification of
     statutory section/rule/paragraph numbering against official Gazette / RBI / FIU-IND / FATF originals.
"""

from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
from typing import Any

from data.regulatory_corpus.corpus_enrichment import ensure_chunk_word_range
from data.regulatory_corpus.corpus_fiu_sop import build_fiu_and_sop_passages
from data.regulatory_corpus.corpus_pmla import RETRIEVAL_DATE, build_pmla_and_pmlr_passages
from data.regulatory_corpus.corpus_rbi_fatf import build_rbi_fatf_passages

CORPUS_DIR = Path(__file__).resolve().parent
CORPUS_PATH = CORPUS_DIR / "indian_aml_corpus.jsonl"
CHECKLIST_PATH = CORPUS_DIR / "HUMAN_VERIFICATION_CHECKLIST.md"

MIN_PASSAGES = 150
MIN_WORDS = 100
MAX_WORDS = 300
FORBIDDEN_IDS = frozenset({"PMLA-2002-S13"})  # Reserved negative-test ID in tests/test_verifier_v2.py


def collect_all_passages() -> list[dict[str, Any]]:
    """Assemble and strictly validate all Corpus v2 passages."""
    raw_passages = [
        *build_pmla_and_pmlr_passages(),
        *build_rbi_fatf_passages(),
        *build_fiu_and_sop_passages(),
    ]
    passages = [ensure_chunk_word_range(rec, MIN_WORDS, MAX_WORDS) for rec in raw_passages]
    seen_ids: set[str] = set()
    errors: list[str] = []
    for rec in passages:
        pid = str(rec["passage_id"])
        if pid in seen_ids:
            errors.append(f"Duplicate passage_id: {pid}")
        seen_ids.add(pid)
        if pid in FORBIDDEN_IDS:
            errors.append(f"Forbidden test-reserved passage_id present: {pid}")
        if pid.startswith("REG-"):
            errors.append(f"Legacy invented REG-* prefix found: {pid}")
        words = rec["text"].split()
        wc = len(words)
        rec["word_count"] = wc
        if not (MIN_WORDS <= wc <= MAX_WORDS):
            errors.append(f"{pid}: word_count={wc} outside [{MIN_WORDS}, {MAX_WORDS}]")
        if rec.get("source_type") not in ("regulatory", "internal"):
            errors.append(f"{pid}: invalid source_type={rec.get('source_type')!r}")
        if not rec.get("source_url") or not rec.get("retrieval_date") or not rec.get("clause_number"):
            errors.append(f"{pid}: missing required provenance metadata")
    if len(passages) < MIN_PASSAGES:
        errors.append(f"Corpus size {len(passages)} < required minimum {MIN_PASSAGES}")
    if errors:
        raise ValueError("Corpus v2 validation failed:\n  - " + "\n  - ".join(errors))
    return passages


def _render_checklist(passages: list[dict[str, Any]]) -> str:
    by_doc: dict[str, list[dict[str, Any]]] = {}
    for p in passages:
        if p["source_type"] == "regulatory":
            by_doc.setdefault(str(p["doc_title"]), []).append(p)
    lines = [
        "# Regulatory Corpus v2 — `[HUMAN]` Statutory Numbering Verification Checklist",
        "",
        f"- **Generated / Retrieved:** `{RETRIEVAL_DATE}`",
        f"- **Total Passages:** `{len(passages)}` "
        f"(`{sum(1 for p in passages if p['source_type'] == 'regulatory')}` regulatory, "
        f"`{sum(1 for p in passages if p['source_type'] == 'internal')}` internal SOPs)",
        "- **Status:** `PENDING [HUMAN] REVIEW` (`human_verified: false` on all regulatory passages)",
        "",
        "> **Action Required (`[HUMAN]`):** Verify exact section, rule, clause, and paragraph numbering",
        "> against official Gazette of India / India Code / RBI / FIU-IND / FATF originals before",
        "> flipping `human_verified` to `true` for production compliance deployment.",
        "",
        "| Statutory Source | Passages | Official Source URL | Sample Refs | Status |",
        "|---|---:|---|---|---|",
    ]
    for doc, items in by_doc.items():
        url = items[0]["source_url"]
        sample_refs = ", ".join(dict.fromkeys(str(i["clause_number"]).split("(")[0].strip() for i in items[:4]))
        lines.append(f"| {doc} | {len(items)} | {url} | {sample_refs} | `[ ] PENDING` |")
    lines.append("")
    return "\n".join(lines)


def build_corpus_v2() -> dict[str, Any]:
    """Write `indian_aml_corpus.jsonl` and `HUMAN_VERIFICATION_CHECKLIST.md`, returning summary stats."""
    passages = collect_all_passages()
    CORPUS_PATH.write_text(
        "\n".join(json.dumps(p, ensure_ascii=False) for p in passages) + "\n",
        encoding="utf-8",
    )
    CHECKLIST_PATH.write_text(_render_checklist(passages), encoding="utf-8")
    wcs = [int(p["word_count"]) for p in passages]
    by_type = Counter(str(p["source_type"]) for p in passages)
    return {
        "total_passages": len(passages),
        "by_source_type": dict(by_type),
        "min_words": min(wcs),
        "max_words": max(wcs),
        "mean_words": round(sum(wcs) / len(wcs), 1),
        "categories": len({str(p["category"]) for p in passages}),
        "corpus_path": str(CORPUS_PATH),
    }


if __name__ == "__main__":
    summary = build_corpus_v2()
    print(json.dumps(summary, indent=2))
