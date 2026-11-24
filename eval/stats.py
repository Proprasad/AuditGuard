"""
Phase 5 Statistical Inference Utilities (`eval/stats.py`).

Implements:
  * `wilson_ci`: exact Wilson 95% score confidence interval for proportions
  * `cluster_bootstrap_ci`: 10,000-iteration cluster bootstrap 95% CI (clustering on case `family` variant)
  * `paired_cluster_bootstrap_diff`: 10,000-iteration paired cluster bootstrap difference CI + effect size
    (enforcing: no claim of 'outperforms' unless the paired 95% CI excludes 0)
  * `mcnemar_test`: exact two-sided binomial McNemar test + continuity-corrected chi-square + odds ratio
  * `percentile`: exact linear-interpolated percentiles (`p50`, `p95`)
"""

from __future__ import annotations

from collections.abc import Sequence
import math
import random
from typing import Any

Z_95: float = 1.959963984540054


def percentile(values: Sequence[float], q: float) -> float:
    """Compute linear-interpolated `q`-th percentile (`0 <= q <= 100`)."""
    if not values:
        raise ValueError("Cannot compute percentile of an empty sequence")
    if not (0.0 <= q <= 100.0):
        raise ValueError(f"Percentile q must be in [0, 100], got {q}")
    ordered = sorted(float(v) for v in values)
    if len(ordered) == 1:
        return ordered[0]
    pos = (q / 100.0) * (len(ordered) - 1)
    lo = int(math.floor(pos))
    hi = int(math.ceil(pos))
    if lo == hi:
        return ordered[lo]
    frac = pos - lo
    return ordered[lo] + frac * (ordered[hi] - ordered[lo])


def wilson_ci(successes: int | float, total: int, *, z: float = Z_95) -> dict[str, Any]:
    """Compute Wilson 95% score confidence interval for a binomial proportion `successes / total`."""
    if total < 0 or successes < -1e-9 or successes > total + 1e-9:
        raise ValueError(f"Invalid binomial counts: successes={successes}, total={total}")
    if total == 0:
        return {"mean": 0.0, "ci_low": 0.0, "ci_high": 0.0, "n": 0}
    k = max(0.0, min(float(total), float(successes)))
    n = float(total)
    p = k / n
    z2 = z * z
    denom = 1.0 + z2 / n
    center = (p + z2 / (2.0 * n)) / denom
    radicand = max(0.0, (p * (1.0 - p) / n) + (z2 / (4.0 * n * n)))
    half = (z / denom) * math.sqrt(radicand)
    return {
        "mean": round(p, 6),
        "ci_low": round(max(0.0, center - half), 6),
        "ci_high": round(min(1.0, center + half), 6),
        "n": total,
    }


def _group_clusters(
    values: Sequence[float], clusters: Sequence[str] | None
) -> list[tuple[float, int]]:
    if clusters is not None and len(clusters) != len(values):
        raise ValueError(f"clusters length ({len(clusters)}) != values length ({len(values)})")
    labels = [str(c) for c in clusters] if clusters is not None else [str(i) for i in range(len(values))]
    buckets: dict[str, list[float]] = {}
    for val, cid in zip(values, labels, strict=True):
        buckets.setdefault(cid, []).append(float(val))
    return [(sum(vs), len(vs)) for vs in buckets.values()]


def cluster_bootstrap_ci(
    values: Sequence[float],
    clusters: Sequence[str] | None = None,
    *,
    n_boot: int = 10_000,
    seed: int = 42,
) -> dict[str, Any]:
    """Compute 95% cluster-bootstrap confidence interval for the mean over `n_boot` resamples."""
    if not values:
        raise ValueError("Cannot compute cluster_bootstrap_ci over an empty sequence")
    obs_mean = sum(float(v) for v in values) / len(values)
    grouped = _group_clusters(values, clusters)
    k = len(grouped)
    if k == 1 or n_boot <= 0:
        r = round(obs_mean, 6)
        return {"mean": r, "ci_low": r, "ci_high": r, "n": len(values), "n_clusters": k}

    rng = random.Random(seed)
    boot_means: list[float] = []
    for _ in range(n_boot):
        sampled = rng.choices(grouped, k=k)
        tot_s = sum(s for s, _ in sampled)
        tot_n = sum(c for _, c in sampled)
        boot_means.append(tot_s / tot_n)
    return {
        "mean": round(obs_mean, 6),
        "ci_low": round(percentile(boot_means, 2.5), 6),
        "ci_high": round(percentile(boot_means, 97.5), 6),
        "n": len(values),
        "n_clusters": k,
    }


def _paired_cohens_d(diffs: Sequence[float]) -> float:
    n = len(diffs)
    if n < 2:
        return 0.0
    mean_d = sum(diffs) / n
    var_d = sum((d - mean_d) ** 2 for d in diffs) / (n - 1)
    sd_d = math.sqrt(var_d)
    if sd_d <= 1e-12:
        return 0.0
    return round(mean_d / sd_d, 4)


def paired_cluster_bootstrap_diff(
    vals_a: Sequence[float],
    vals_b: Sequence[float],
    clusters: Sequence[str] | None = None,
    *,
    n_boot: int = 10_000,
    seed: int = 42,
    higher_is_better: bool = True,
) -> dict[str, Any]:
    """
    Compute 10,000-iteration paired cluster-bootstrap 95% CI for `mean(vals_a) - mean(vals_b)`.
    Enforces the pre-registered rule: `verdict` claims `outperforms` ONLY when `[ci_low, ci_high]` excludes `0`.
    """
    if len(vals_a) != len(vals_b) or not vals_a:
        raise ValueError("vals_a and vals_b must be non-empty sequences of identical length")
    n = len(vals_a)
    labels = [str(c) for c in clusters] if clusters is not None else [str(i) for i in range(n)]
    if len(labels) != n:
        raise ValueError("clusters length must match vals_a/vals_b")

    mean_a = sum(float(x) for x in vals_a) / n
    mean_b = sum(float(y) for y in vals_b) / n
    obs_diff = mean_a - mean_b
    unit_diffs = [float(a) - float(b) for a, b in zip(vals_a, vals_b, strict=True)]

    buckets: dict[str, list[tuple[float, float]]] = {}
    for a, b, cid in zip(vals_a, vals_b, labels, strict=True):
        buckets.setdefault(cid, []).append((float(a), float(b)))
    grouped = [(sum(p[0] for p in pairs), sum(p[1] for p in pairs), len(pairs)) for pairs in buckets.values()]
    k = len(grouped)

    if k == 1 or n_boot <= 0:
        ci_lo = ci_hi = obs_diff
    else:
        rng = random.Random(seed)
        boot_diffs: list[float] = []
        for _ in range(n_boot):
            sampled = rng.choices(grouped, k=k)
            sa = sum(x[0] for x in sampled)
            sb = sum(x[1] for x in sampled)
            sn = sum(x[2] for x in sampled)
            boot_diffs.append((sa - sb) / sn)
        ci_lo = percentile(boot_diffs, 2.5)
        ci_hi = percentile(boot_diffs, 97.5)

    excludes_zero = (ci_lo > 0.0) or (ci_hi < 0.0)
    if not excludes_zero:
        verdict = "inconclusive_ci_includes_zero"
    elif (obs_diff > 0 and higher_is_better) or (obs_diff < 0 and not higher_is_better):
        verdict = "a_outperforms_b"
    else:
        verdict = "b_outperforms_a"

    return {
        "mean_a": round(mean_a, 6),
        "mean_b": round(mean_b, 6),
        "diff_a_minus_b": round(obs_diff, 6),
        "ci_low": round(ci_lo, 6),
        "ci_high": round(ci_hi, 6),
        "ci_excludes_zero": excludes_zero,
        "cohens_d": _paired_cohens_d(unit_diffs),
        "verdict": verdict,
        "n_cases": n,
        "n_clusters": k,
    }


def mcnemar_test(correct_a: Sequence[bool], correct_b: Sequence[bool]) -> dict[str, Any]:
    """Exact two-sided binomial McNemar test + continuity-corrected chi2 + Haldane-Anscombe odds ratio."""
    if len(correct_a) != len(correct_b) or not correct_a:
        raise ValueError("correct_a and correct_b must be non-empty sequences of identical length")
    n = len(correct_a)
    both_right = sum(1 for a, b in zip(correct_a, correct_b, strict=True) if a and b)
    b_only_a = sum(1 for a, b in zip(correct_a, correct_b, strict=True) if a and not b)
    c_only_b = sum(1 for a, b in zip(correct_a, correct_b, strict=True) if (not a) and b)
    both_wrong = n - both_right - b_only_a - c_only_b

    disc = b_only_a + c_only_b
    if disc == 0:
        p_exact = 1.0
        chi2_cc = 0.0
    else:
        k_min = min(b_only_a, c_only_b)
        tail = sum(math.comb(disc, i) for i in range(k_min + 1)) / (2**disc)
        p_exact = min(1.0, 2.0 * tail)
        chi2_cc = (max(0.0, abs(b_only_a - c_only_b) - 1.0) ** 2) / disc

    odds_ratio = (b_only_a + 0.5) / (c_only_b + 0.5)
    acc_diff = (sum(1 for a in correct_a if a) - sum(1 for b in correct_b if b)) / n
    return {
        "n": n,
        "both_correct": both_right,
        "a_only_correct": b_only_a,
        "b_only_correct": c_only_b,
        "both_wrong": both_wrong,
        "accuracy_diff": round(acc_diff, 6),
        "chi2_cc": round(chi2_cc, 6),
        "p_value_exact": round(p_exact, 6),
        "odds_ratio": round(odds_ratio, 4),
    }


def compute_paired_mode_table(
    all_results: dict[str, dict[str, Any]], gold_records: Sequence[ dict[str, Any]], seed: int = 42
) -> list[dict[str, Any]]:
    """Build pairwise 10k cluster-bootstrap (accuracy & error cost) + exact McNemar table across modes."""
    labels = list(all_results.keys())
    clusters = [str(g.get("family") or g["case_id"]) for g in gold_records]
    comparisons: list[dict[str, Any]] = []
    for i in range(len(labels)):
        for j in range(i + 1, len(labels)):
            la, lb = labels[i], labels[j]
            sa = all_results[la]["metrics"]["_case_series"]
            sb = all_results[lb]["metrics"]["_case_series"]
            acc_b = paired_cluster_bootstrap_diff(
                [float(x["correct"]) for x in sa], [float(x["correct"]) for x in sb], clusters, seed=seed
            )
            err_b = paired_cluster_bootstrap_diff(
                [float(x["error_cost"]) for x in sa],
                [float(x["error_cost"]) for x in sb],
                clusters,
                seed=seed,
                higher_is_better=False,
            )
            mc = mcnemar_test([float(x["correct"]) >= 0.5 for x in sa], [float(x["correct"]) >= 0.5 for x in sb])
            comparisons.append(
                {"pair": f"{la} vs {lb}", "accuracy_bootstrap": acc_b, "error_cost_bootstrap": err_b, "mcnemar": mc}
            )
    return comparisons
