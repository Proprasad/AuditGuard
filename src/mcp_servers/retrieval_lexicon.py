"""
Hand-written retrieval lexicon for compliance-kb: stopwords and AML domain concept expansions.

Frozen (audit AG-08): `retrieval.expansion_table_sha256` in `config/models.yaml` pins this content, and a test fails
if it changes without re-measuring retrieval. Tuning these words against the benchmark would overstate Recall@5.
"""

from __future__ import annotations

# fmt: off
_STOPWORDS = frozenset({
    "a", "an", "and", "are", "as", "at", "be", "been", "being", "by", "can", "do", "does", "for",
    "from", "has", "have", "how", "if", "in", "into", "is", "it", "its", "may", "must", "not", "of",
    "on", "or", "shall", "should", "such", "that", "the", "their", "them", "there", "these", "they",
    "this", "to", "under", "was", "were", "what", "when", "where", "which", "who", "will", "with",
    "india", "indian", "act", "section", "rule", "rules", "para", "paragraph", "clause", "law",
    "legal", "bank", "banks", "entity", "entities", "financial", "institution", "institutions",
})

DOMAIN_CONCEPTS: dict[str, list[str]] = {
    "skim": ["fee", "commission", "retaining", "cut", "mule"],
    "commission": ["fee", "retaining", "skimming", "mule"],
    "delay": ["staggered", "days", "replanning", "window", "consolidation"],
    "stagger": ["staggered", "pass", "through", "window", "consolidation"],
    "smurf": ["structuring", "below", "threshold", "lakh", "cash"],
    "dodge": ["evade", "threshold", "structured"],
    "salary": ["payroll", "employer", "employee", "disbursements", "income"],
    "wage": ["salary", "payroll", "employer", "employee"],
    "payroll": ["salary", "employer", "employee", "corporate", "epfo"],
    "ngo": ["charitable", "trust", "non", "profit", "relief", "darpan", "80g"],
    "charity": ["charitable", "trust", "relief", "darpan", "80g", "npo"],
    "donat": ["charitable", "trust", "relief", "npo", "darpan"],
    "ecommerce": ["marketplace", "seller", "aggregator", "escrow", "nodal"],
    "marketplace": ["ecommerce", "seller", "aggregator", "escrow", "nodal"],
    "wedding": ["banquet", "catering", "family", "social", "hotel"],
    "marriage": ["banquet", "catering", "family", "social", "hotel"],
    "gap": ["missing", "external", "correspondent", "insufficient", "request_info"],
    "visibility": ["missing", "external", "correspondent", "insufficient"],
    "forget": ["delete", "memory", "erasable", "retention", "episodes"],
    "erase": ["delete", "memory", "erasable", "retention", "episodes"],
    "inject": ["untrusted", "memo", "override", "instructions", "prompt"],
    "hostile": ["untrusted", "memo", "override", "instructions"],
    "warn": ["tipping", "prohibited", "confidentiality", "secrecy"],
    "tipping": ["confidentiality", "prohibited", "secrecy", "disclosing"],
    "deadline": ["seven", "working", "days", "furnish", "15th", "timeline"],
    "politician": ["politically", "exposed", "pep", "senior", "wealth"],
    "official": ["politically", "exposed", "pep", "senior", "wealth"],
    "inactive": ["dormant", "inoperative", "reactivation", "velocity", "savings"],
    "dormant": ["inoperative", "reactivation", "velocity", "savings"],
    "outdated": ["expired", "minimal", "periodic", "updation", "fresh"],
    "expired": ["periodic", "updation", "minimal", "fresh", "cdd"],
    "bucket": ["categorized", "low", "medium", "high", "risk"],
    "rotating": ["chit", "installments", "subscribers", "auction", "registrar"],
    "dirty": ["proceeds", "crime", "concealment", "tainted", "untainted"],
    "launder": ["proceeds", "crime", "concealment", "layering", "pmla"],
    "guilt": ["criminal", "prohibited", "reasonable", "suspicion", "judicial"],
    "math": ["decimal", "arithmetic", "calc", "precision"],
    "aborted": ["attempted", "suspicious", "transaction", "reportable"],
    "video": ["vcip", "digital", "onboarding", "identification"],
    "darpan": ["npo", "charitable", "trust", "80g", "niti"],
    "lakh": ["lakhs", "1000000", "threshold", "ctr", "cbwtr"],
}
# fmt: on
