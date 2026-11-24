"""
Anti-Shortcut Baselines (`docs/AGENT_GUIDE.md` §4 Phase 1.5):
  (a) `RootKYCLookupTree`             : decision tree on root KYC attributes only (must be <= 0.80 on held-out)
  (b) `HandFeatureLogisticRegression` : L2-regularised multinomial logistic regression on 10 hand features
  (c) `MemoKeywordClassifier`         : Laplace-smoothed unigram + bigram Naive Bayes over memos + `kyc_notes`

All classifiers fit strictly on `dev` (`redact_case_for_agent` inputs + dev gold labels) and predict
using ONLY redacted agent-visible inputs (`redact_case_for_agent`), never touching evaluation gold fields.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from decimal import Decimal
import json
import math
from pathlib import Path
import re
from typing import Any

from src.core.canonical import parse_utc_timestamp
from src.mcp_servers.bank_records import redact_case_for_agent

CLASSES: tuple[str, ...] = ("escalate_str", "close_benign", "request_info")
_WORD_RE = re.compile(r"[a-z0-9_]{2,}")


def _is_correct(pred: str, gold_case: dict[str, Any]) -> bool:
    acceptable = gold_case.get("acceptable_dispositions")
    if isinstance(acceptable, list) and acceptable:
        return pred in acceptable
    return pred == str(gold_case.get("gold_disposition") or gold_case.get("expected_disposition"))


def _gold_label(case: dict[str, Any]) -> str:
    return str(case.get("gold_disposition") or case.get("expected_disposition"))


def _get_root_kyc(redacted: dict[str, Any]) -> dict[str, Any]:
    root = str(redacted["root_account"])
    kp = redacted.get("kyc_profiles") or {}
    if isinstance(kp, dict):
        return dict(kp.get(root) or {})
    if isinstance(kp, list):
        for item in kp:
            if isinstance(item, dict) and str(item.get("account_id")) == root:
                return item
    return {}


# ── (a) Root KYC Lookup Tree ──────────────────────────────────────────────────
def _kyc_key(redacted: dict[str, Any]) -> tuple[str, str, str, str]:
    kyc = _get_root_kyc(redacted)
    risk = str(kyc.get("risk_category", "missing")).lower()
    reg = "reg" if kyc.get("is_commercially_registered") else "unreg"
    etype = str(kyc.get("entity_type", "missing")).lower()
    alert_amt = float(Decimal(str(redacted.get("total_amount_inr", "1"))))
    inc = float(Decimal(str(kyc.get("declared_annual_income_inr", "1"))))
    ratio = alert_amt / max(inc, 1.0)
    rbucket = "high_ratio" if ratio > 1.2 else ("mid_ratio" if ratio > 0.35 else "low_ratio")
    return (risk, reg, etype, rbucket)


class RootKYCLookupTree:
    """Hierarchical lookup tree over `(risk_category, registered, entity_type, alert_income_ratio)`."""

    def __init__(self) -> None:
        self._l4: dict[tuple[str, str, str, str], str] = {}
        self._l2: dict[tuple[str, str], str] = {}
        self._l1: dict[str, str] = {}
        self._prior: str = "escalate_str"

    def fit(self, dev_cases: list[dict[str, Any]]) -> RootKYCLookupTree:
        c4: dict[tuple[str, str, str, str], Counter[str]] = defaultdict(Counter)
        c2: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
        c1: dict[str, Counter[str]] = defaultdict(Counter)
        overall: Counter[str] = Counter()
        for raw in dev_cases:
            y = _gold_label(raw)
            k = _kyc_key(redact_case_for_agent(raw))
            c4[k][y] += 1
            c2[(k[0], k[1])][y] += 1
            c1[k[0]][y] += 1
            overall[y] += 1
        self._l4 = {k: v.most_common(1)[0][0] for k, v in c4.items()}
        self._l2 = {k: v.most_common(1)[0][0] for k, v in c2.items()}
        self._l1 = {k: v.most_common(1)[0][0] for k, v in c1.items()}
        self._prior = overall.most_common(1)[0][0] if overall else "escalate_str"
        return self

    def predict(self, redacted_case: dict[str, Any]) -> str:
        k = _kyc_key(redacted_case)
        return self._l4.get(k) or self._l2.get((k[0], k[1])) or self._l1.get(k[0]) or self._prior


# ── (b) 10-Feature Multinomial Logistic Regression ────────────────────────────
def extract_10_hand_features(redacted: dict[str, Any]) -> list[float]:
    root = str(redacted["root_account"])
    kyc = _get_root_kyc(redacted)
    txs = redacted.get("transactions") or []
    alert_amt = float(Decimal(str(redacted.get("total_amount_inr", "1"))))
    income = float(Decimal(str(kyc.get("declared_annual_income_inr", "500000"))))
    risk = str(kyc.get("risk_category", "medium")).lower()

    stamps = [parse_utc_timestamp(t["timestamp"]) for t in txs if t.get("timestamp")]
    span_days = (max(stamps) - min(stamps)).total_seconds() / 86400.0 if len(stamps) >= 2 else 0.0
    large_round = sum(
        1 for t in txs if float(Decimal(str(t.get("amount_inr", "0")))) >= 100_000.0
    ) / max(len(txs), 1)
    root_out_cnt = sum(1 for t in txs if t.get("sender_account") == root)

    return [
        math.log1p(max(alert_amt, 0.0)),
        math.log1p(max(income, 0.0)),
        min(20.0, alert_amt / max(income, 1.0)),
        1.0 if risk == "high" else 0.0,
        1.0 if risk == "low" else 0.0,
        1.0 if kyc.get("is_commercially_registered") else 0.0,
        len(redacted.get("network_accounts", [])) / 10.0,
        len(txs) / 80.0,
        min(40.0, span_days) / 30.0,
        0.5 * large_round + 0.5 * (root_out_cnt / max(len(txs), 1)),
    ]


def _softmax(logits: list[float]) -> list[float]:
    m = max(logits)
    exps = [math.exp(z - m) for z in logits]
    s = sum(exps)
    return [e / s for e in exps]


class HandFeatureLogisticRegression:
    """Deterministic L2-regularised 3-class softmax regression over 10 tabular features."""

    def __init__(self, lr: float = 0.15, epochs: int = 350, l2: float = 0.05) -> None:
        self.lr = lr
        self.epochs = epochs
        self.l2 = l2
        self._means: list[float] = [0.0] * 10
        self._stds: list[float] = [1.0] * 10
        self._weights: list[list[float]] = [[0.0] * 10 for _ in CLASSES]
        self._bias: list[float] = [0.0 for _ in CLASSES]

    def _standardize(self, row: list[float]) -> list[float]:
        return [(x - mu) / sd for x, mu, sd in zip(row, self._means, self._stds, strict=True)]

    def fit(self, dev_cases: list[dict[str, Any]]) -> HandFeatureLogisticRegression:
        raw_x = [extract_10_hand_features(redact_case_for_agent(c)) for c in dev_cases]
        ys = [CLASSES.index(_gold_label(c)) for c in dev_cases]
        n = max(len(raw_x), 1)
        self._means = [sum(r[j] for r in raw_x) / n for j in range(10)]
        self._stds = [
            max(1e-6, math.sqrt(sum((r[j] - self._means[j]) ** 2 for r in raw_x) / n)) for j in range(10)
        ]
        xs = [self._standardize(r) for r in raw_x]
        self._weights = [[0.0] * 10 for _ in CLASSES]
        self._bias = [0.0 for _ in CLASSES]

        for _ in range(self.epochs):
            grad_w = [[0.0] * 10 for _ in CLASSES]
            grad_b = [0.0 for _ in CLASSES]
            for x, y_idx in zip(xs, ys, strict=True):
                logits = [
                    sum(w * xj for w, xj in zip(self._weights[c], x, strict=True)) + self._bias[c]
                    for c in range(len(CLASSES))
                ]
                probs = _softmax(logits)
                for c in range(len(CLASSES)):
                    err = probs[c] - (1.0 if c == y_idx else 0.0)
                    grad_b[c] += err / n
                    for j in range(10):
                        grad_w[c][j] += (err * x[j]) / n
            for c in range(len(CLASSES)):
                self._bias[c] -= self.lr * grad_b[c]
                for j in range(10):
                    self._weights[c][j] -= self.lr * (grad_w[c][j] + self.l2 * self._weights[c][j])
        return self

    def predict(self, redacted_case: dict[str, Any]) -> str:
        x = self._standardize(extract_10_hand_features(redacted_case))
        logits = [
            sum(w * xj for w, xj in zip(self._weights[c], x, strict=True)) + self._bias[c]
            for c in range(len(CLASSES))
        ]
        best = max(range(len(CLASSES)), key=lambda idx: logits[idx])
        return CLASSES[best]


# ── (c) Memo-Keyword Naive Bayes Classifier ───────────────────────────────────
def _tokenize_case_text(redacted: dict[str, Any]) -> list[str]:
    parts: list[str] = []
    for tx in redacted.get("transactions") or []:
        parts.append(str(tx.get("memo") or tx.get("memo_text") or ""))
    root_kyc = _get_root_kyc(redacted)
    parts.append(str(root_kyc.get("kyc_notes", "")))
    words = _WORD_RE.findall(" ".join(parts).lower())
    bigrams = [f"{a}_{b}" for a, b in zip(words, words[1:], strict=False)]
    return [*words, *bigrams]


class MemoKeywordClassifier:
    """Laplace-smoothed multinomial Naive Bayes over memo + KYC-note unigrams/bigrams."""

    def __init__(self) -> None:
        self._priors: dict[str, float] = {}
        self._tok_counts: dict[str, Counter[str]] = {c: Counter() for c in CLASSES}
        self._totals: dict[str, int] = {c: 0 for c in CLASSES}
        self._vocab: set[str] = set()

    def fit(self, dev_cases: list[dict[str, Any]]) -> MemoKeywordClassifier:
        cls_docs: Counter[str] = Counter()
        self._tok_counts = {c: Counter() for c in CLASSES}
        self._vocab = set()
        for raw in dev_cases:
            y = _gold_label(raw)
            cls_docs[y] += 1
            toks = _tokenize_case_text(redact_case_for_agent(raw))
            self._tok_counts[y].update(toks)
            self._vocab.update(toks)
        n_docs = max(len(dev_cases), 1)
        self._priors = {c: math.log((cls_docs[c] + 1.0) / (n_docs + len(CLASSES))) for c in CLASSES}
        self._totals = {c: sum(self._tok_counts[c].values()) for c in CLASSES}
        return self

    def predict(self, redacted_case: dict[str, Any]) -> str:
        toks = _tokenize_case_text(redacted_case)
        v_size = max(len(self._vocab), 1)
        best_cls = CLASSES[0]
        best_score = -1e18
        for c in CLASSES:
            denom = self._totals[c] + v_size
            score = self._priors[c] + sum(math.log((self._tok_counts[c][t] + 1.0) / denom) for t in toks)
            if score > best_score:
                best_score = score
                best_cls = c
        return best_cls


def evaluate_shortcuts(
    dev_cases: list[dict[str, Any]], eval_cases: list[dict[str, Any]]
) -> dict[str, dict[str, float]]:
    tree = RootKYCLookupTree().fit(dev_cases)
    logreg = HandFeatureLogisticRegression().fit(dev_cases)
    memo_nb = MemoKeywordClassifier().fit(dev_cases)

    models: dict[str, Any] = {
        "root_kyc_tree": tree,
        "hand_features_logreg": logreg,
        "memo_keyword_nb": memo_nb,
    }
    report: dict[str, dict[str, float]] = {}
    n = max(len(eval_cases), 1)
    for name, clf in models.items():
        preds = [clf.predict(redact_case_for_agent(c)) for c in eval_cases]
        acc = sum(1 for p, c in zip(preds, eval_cases, strict=True) if _is_correct(p, c)) / n
        strict_acc = sum(1 for p, c in zip(preds, eval_cases, strict=True) if p == _gold_label(c)) / n
        report[name] = {
            "accuracy": round(acc, 4),
            "strict_gold_accuracy": round(strict_acc, 4),
        }
    return report


def assert_shortcut_ceiling(
    dev_cases: list[dict[str, Any]],
    held_out_cases: list[dict[str, Any]],
    ceiling: float = 0.80,
) -> dict[str, dict[str, float]]:
    metrics = evaluate_shortcuts(dev_cases, held_out_cases)
    kyc_acc = metrics["root_kyc_tree"]["accuracy"]
    if kyc_acc > ceiling:
        raise AssertionError(f"Root KYC shortcut tree accuracy {kyc_acc:.3f} exceeded ceiling {ceiling:.2f}")
    return metrics


def _load_dir(path: Path) -> list[dict[str, Any]]:
    return [json.loads(fp.read_text(encoding="utf-8")) for fp in sorted(path.glob("*.json"))]


def main() -> None:
    dev = _load_dir(Path("data/golden_v2/dev"))
    held = _load_dir(Path("eval/golden_v2/held_out"))
    chal = _load_dir(Path("eval/golden_v2/challenge"))
    out = {
        "dev_self": evaluate_shortcuts(dev, dev),
        "held_out": assert_shortcut_ceiling(dev, held, ceiling=0.80),
        "challenge": evaluate_shortcuts(dev, chal),
    }
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
