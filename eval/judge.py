"""
Cross-Family LLM Judge & Cohen's Kappa Calibration
Uses an independent model family (Gemini / Llama) to score reasoning quality
and computes Cohen's kappa against human labels.
"""
from __future__ import annotations

from typing import Sequence


def cohens_kappa(labels_a: Sequence[str], labels_b: Sequence[str]) -> float:
    """Compute Cohen's kappa between two raters (target >= 0.75)."""
    if len(labels_a) != len(labels_b) or not labels_a:
        return 0.0

    n = len(labels_a)
    categories = sorted(set(labels_a) | set(labels_b))
    p_o = sum(1 for a, b in zip(labels_a, labels_b, strict=True) if a == b) / n

    p_e = 0.0
    for cat in categories:
        freq_a = sum(1 for a in labels_a if a == cat) / n
        freq_b = sum(1 for b in labels_b if b == cat) / n
        p_e += freq_a * freq_b

    if p_e == 1.0:
        return 1.0
    return (p_o - p_e) / (1.0 - p_e)
