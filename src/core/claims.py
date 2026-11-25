"""
Claim-Level Evidence Grounding & Case-Ownership Verification (`src/core/claims.py`).

Pure deterministic module separating:
  * Deterministic claim verification (ID existence, namespace provenance, case/alert ownership)
  * Structured `EvidenceClaim` construction from hypotheses, rationale, and specialist findings
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from src.core.investigation_contracts import ClaimRelationship, ClaimVerificationStatus, EvidenceClaim
from src.core.verifier_patterns import CLAUSE_ID_PREFIXES, REF_PATTERN

_REG_PREFIXES = CLAUSE_ID_PREFIXES
_DATA_PREFIXES = ("TXN-", "TX-", "KYC-", "PATH-", "CALC-", "REGISTRY-", "CP-")


def classify_evidence_source(evidence_id: str, record: Any = None) -> str:
    """Derive canonical evidence source category from immutable ID namespace."""
    eid = str(evidence_id)
    if eid.startswith(("TXN-", "TX-")):
        return "bank-records.transaction"
    if eid.startswith("KYC-"):
        return "bank-records.kyc"
    if eid.startswith("REGISTRY-"):
        return "bank-records.commercial_registry"
    if eid.startswith("CP-"):
        return "bank-records.counterparty_history"
    if eid.startswith("PATH-"):
        return "graph-engine.fund_flow_path"
    if eid.startswith("CALC-"):
        return "graph-engine.decimal_calc"
    if eid.startswith(_REG_PREFIXES):
        return "compliance-kb.regulatory_clause"
    if isinstance(record, Mapping) and record.get("source"):
        return str(record["source"])
    return "unknown"


def _extract_case_accounts(
    alert_id: str,
    root_account: str,
    network_accounts: Sequence[str],
    transactions: Sequence[Mapping[str, Any]],
) -> set[str]:
    accounts: set[str] = set()
    if root_account:
        accounts.add(root_account)
    for acc in network_accounts:
        if acc:
            accounts.add(str(acc))
    for tx in transactions:
        tx_alert = str(tx.get("alert_id") or "")
        if tx_alert and alert_id and tx_alert != alert_id:
            continue
        for key in ("sender_account", "receiver_account", "account_id"):
            if tx.get(key):
                accounts.add(str(tx[key]))
    return accounts


def check_evidence_case_ownership(
    evidence_id: str,
    record: Any,
    *,
    alert_id: str,
    known_accounts: set[str],
) -> tuple[bool, str]:
    """
    Deterministic ownership check: reject evidence records tagged with another `alert_id`
    or account-scoped records belonging to an unrelated account outside this case.
    """
    if not isinstance(record, Mapping):
        return True, ""
    if str(evidence_id).startswith(_REG_PREFIXES) or str(evidence_id).startswith("CALC-"):
        return True, ""
    rec_alert = str(record.get("alert_id") or "").strip()
    if alert_id and rec_alert and rec_alert != alert_id:
        return False, f"{evidence_id} belongs to alert {rec_alert!r}, not {alert_id!r}"

    if not known_accounts:
        return True, ""

    if str(evidence_id).startswith(("KYC-", "REGISTRY-")):
        acc = str(record.get("account_id") or "").strip()
        if acc and acc not in known_accounts:
            return False, f"{evidence_id} account {acc!r} is not associated with alert {alert_id!r}"
    elif str(evidence_id).startswith(("TXN-", "TX-")):
        sender = str(record.get("sender_account") or "").strip()
        receiver = str(record.get("receiver_account") or "").strip()
        if (sender or receiver) and not ({sender, receiver} & known_accounts):
            return False, f"{evidence_id} ({sender}->{receiver}) has no account in alert {alert_id!r}"
    elif str(evidence_id).startswith("PATH-"):
        nodes = [str(n) for n in (record.get("nodes") or []) if n]
        if nodes and not (set(nodes) & known_accounts):
            return False, f"{evidence_id} path nodes {nodes} are unrelated to alert {alert_id!r}"
    return True, ""


def verify_claim_grounding(
    claims: Sequence[EvidenceClaim],
    evidence_registry: Mapping[str, Any],
    *,
    alert_id: str = "",
    root_account: str = "",
    network_accounts: Sequence[str] = (),
    transactions: Sequence[Mapping[str, Any]] = (),
) -> list[EvidenceClaim]:
    """Deterministically verify every claim's evidence existence, namespace, and case ownership."""
    known_accounts = _extract_case_accounts(alert_id, root_account, network_accounts, transactions)
    verified: list[EvidenceClaim] = []
    for claim in claims:
        issues: list[str] = []
        sources: list[str] = []
        status: ClaimVerificationStatus = "verified"

        if not claim.evidence_ids:
            status = "ungrounded"
            issues.append("Claim carries zero evidence references")
        else:
            for eid in claim.evidence_ids:
                if eid not in evidence_registry:
                    status = "ungrounded"
                    issues.append(f"Evidence ID {eid!r} not found in evidence_registry")
                    continue
                rec = evidence_registry[eid]
                sources.append(classify_evidence_source(eid, rec))
                owned, reason = check_evidence_case_ownership(
                    eid, rec, alert_id=alert_id, known_accounts=known_accounts
                )
                if not owned:
                    status = "wrong_case"
                    issues.append(reason)

        verified.append(
            claim.model_copy(
                update={
                    "evidence_sources": list(dict.fromkeys(sources)),
                    "verification_status": status,
                    "issues": issues,
                }
            )
        )
    return verified


def _refs_in_text(text: str) -> list[str]:
    return list(dict.fromkeys(r.rstrip("-_.") for r in REF_PATTERN.findall(text or "")))


def _data_ids(ids: Iterable[str]) -> list[str]:
    return [i for i in ids if str(i).startswith(_DATA_PREFIXES)]


def build_evidence_claims(
    *,
    rationale: str,
    hypotheses: Sequence[Mapping[str, Any]],
    regulatory_citations: Sequence[str],
    evidence_registry: Mapping[str, Any],
    alert_id: str = "",
    root_account: str = "",
    network_accounts: Sequence[str] = (),
    transactions: Sequence[Mapping[str, Any]] = (),
) -> list[EvidenceClaim]:
    """Build and deterministically verify structured `EvidenceClaim` items from worksheet narratives."""
    raw_claims: list[EvidenceClaim] = []
    idx = 1

    if rationale.strip():
        rat_refs = list(dict.fromkeys([*_refs_in_text(rationale), *regulatory_citations]))
        raw_claims.append(
            EvidenceClaim(
                claim_id=f"CLM-{idx:02d}",
                claim_text=rationale.strip()[:320],
                evidence_ids=rat_refs,
                relationship="supporting",
                relevance_explanation="Primary disposition rationale grounded in gathered evidence and citations.",
            )
        )
        idx += 1

    for hyp in hypotheses:
        label = str(hyp.get("label", "unknown")).lower()
        expl = str(hyp.get("explanation", "")).strip()
        h_ids = list(
            dict.fromkeys(
                [
                    *(str(x) for x in hyp.get("evidence_ids", []) if x),
                    *_refs_in_text(expl),
                    *(str(c) for c in hyp.get("regulatory_citations", []) if c),
                ]
            )
        )
        if expl:
            rel: ClaimRelationship = "supporting" if label == "suspicious" else "contextual"
            raw_claims.append(
                EvidenceClaim(
                    claim_id=f"CLM-{idx:02d}",
                    claim_text=f"[{label}] {expl[:280]}",
                    evidence_ids=h_ids,
                    relationship=rel,
                    relevance_explanation=f"Core {label} hypothesis claim linked to case evidence.",
                )
            )
            idx += 1
        for key, rel_type in (("supporting_evidence", "supporting"), ("contradicting_evidence", "contradicting")):
            for item in hyp.get(key, [])[:3]:
                txt = str(item).strip()
                if not txt:
                    continue
                item_refs = _refs_in_text(txt) or _data_ids(h_ids)[:3]
                raw_claims.append(
                    EvidenceClaim(
                        claim_id=f"CLM-{idx:02d}",
                        claim_text=f"[{label}:{key}] {txt[:240]}",
                        evidence_ids=item_refs,
                        relationship=rel_type,  # type: ignore[arg-type]
                        relevance_explanation=f"{rel_type.capitalize()} point for {label} hypothesis.",
                    )
                )
                idx += 1

    return verify_claim_grounding(
        raw_claims,
        evidence_registry,
        alert_id=alert_id,
        root_account=root_account,
        network_accounts=network_accounts,
        transactions=transactions,
    )
