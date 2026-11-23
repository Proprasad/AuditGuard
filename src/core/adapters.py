"""
Pure adapters shared by C0 / C1 / C2 (replaces three copy-pasted mappers).

No framework imports: converts raw tool/DB records into core types and back into API-model types.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from src.core.canonical import dec_str, parse_utc_timestamp, to_money
from src.core.graph_math import Txn
from src.models import FundFlowPath


def txn_from_record(rec: Mapping[str, Any]) -> Txn:
    """Accept both DB-style (`sender_account`) and graph-style (`sender`) records."""
    return Txn(
        tx_id=str(rec["tx_id"]),
        sender=str(rec.get("sender_account") or rec["sender"]),
        receiver=str(rec.get("receiver_account") or rec["receiver"]),
        amount=to_money(rec["amount_inr"]),
        timestamp=parse_utc_timestamp(rec["timestamp"]),
        memo=rec.get("memo"),
    )


def graph_tx_payload(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Records -> payload for the graph-engine MCP tool (amounts as exact strings)."""
    payload: list[dict[str, Any]] = []
    for rec in records:
        txn = txn_from_record(rec)
        payload.append(
            {
                "tx_id": txn.tx_id,
                "sender": txn.sender,
                "receiver": txn.receiver,
                "amount_inr": dec_str(txn.amount),
                "timestamp": txn.timestamp.isoformat(),
                "memo": txn.memo,
            }
        )
    return payload


def flow_path_from_dict(path: Mapping[str, Any]) -> FundFlowPath:
    return FundFlowPath.model_validate(dict(path))


def flow_paths_from_result(graph_result: Mapping[str, Any], limit: int) -> list[FundFlowPath]:
    return [flow_path_from_dict(p) for p in list(graph_result.get("paths", []))[:limit]]


def is_registered(kyc: Mapping[str, Any]) -> bool:
    check = kyc.get("registry_check") or {}
    return bool(kyc.get("is_commercially_registered") or check.get("is_registered"))


def kyc_summary_line(kyc: Mapping[str, Any]) -> str:
    return (
        f"{kyc.get('account_id', 'unknown')}: {kyc.get('entity_type', 'unknown')}, "
        f"risk={kyc.get('risk_category', 'unknown')}, registered={is_registered(kyc)}"
    )


def kyc_summaries(profiles: Sequence[Mapping[str, Any]], limit: int) -> list[str]:
    return [kyc_summary_line(k) for k in profiles[:limit]]
