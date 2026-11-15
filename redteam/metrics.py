"""Agreement and rate metrics."""

from __future__ import annotations

import math


def cohen_kappa(a: list[bool], b: list[bool]) -> float:
    """Cohen's kappa for two binary raters. Returns nan when chance agreement is 1 (no variation at all)."""
    if len(a) != len(b) or not a:
        raise ValueError("need two equal-length, non-empty label lists")
    n = len(a)
    po = sum(x == y for x, y in zip(a, b, strict=True)) / n
    pa, pb = sum(a) / n, sum(b) / n
    pe = pa * pb + (1 - pa) * (1 - pb)
    if math.isclose(pe, 1.0):
        return math.nan
    return (po - pe) / (1 - pe)


def confusion(pred: list[bool], truth: list[bool]) -> dict[str, int]:
    pairs = list(zip(pred, truth, strict=True))
    return {
        "tp": sum(p and t for p, t in pairs),
        "fp": sum(p and not t for p, t in pairs),
        "fn": sum(t and not p for p, t in pairs),
        "tn": sum(not p and not t for p, t in pairs),
    }


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for a proportion."""
    if n == 0:
        return (math.nan, math.nan)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))
