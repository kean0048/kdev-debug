"""Evidence verification: every log line the AI quotes must exist verbatim in the original log, to prevent hallucination."""

from __future__ import annotations

import re
from dataclasses import dataclass

# strip leading bracketed prefixes such as [timestamp] / [drm]
_TS_RE = re.compile(r"^\s*(\[[^\]]*\]\s*)+")


@dataclass
class VerifySummary:
    total: int = 0
    passed: int = 0
    line_mismatch: int = 0  # content found but the line number did not match

    @property
    def rate(self) -> str:
        return f"{self.passed}/{self.total}"


def normalize(line: str) -> str:
    line = _TS_RE.sub("", line)
    return " ".join(line.split()).casefold()


def _match(quote_norm: str, line_norm: str) -> bool:
    if not quote_norm or not line_norm:
        return False
    if quote_norm == line_norm:
        return True
    # the model may truncate/extend a quote, so allow one-way containment
    # (very short quotes must match exactly, to avoid false positives)
    if len(quote_norm) >= 12:
        return quote_norm in line_norm or line_norm in quote_norm
    return False


def verify_result(result: dict, log_lines: list[str]) -> VerifySummary:
    """Mutates result in place: tags each evidence entry with verified / actual_line."""
    summary = VerifySummary()
    norm_all = [normalize(l) for l in log_lines]
    for finding in result.get("findings", []):
        if not isinstance(finding, dict):
            continue
        any_verified = False
        for ev in finding.get("evidence", []):
            if not isinstance(ev, dict):
                continue
            summary.total += 1
            quote = normalize(str(ev.get("quote", "")))
            claimed = ev.get("line")
            found_at: int | None = None

            # first check a ±5 window around the claimed line number
            # (sashiko-style drift tolerance: small local models frequently
            # mis-count by a few lines; that is a line drift, not a mismatch)
            try:
                c = int(claimed)
                window = range(max(1, c - 5), min(len(norm_all), c + 5) + 1)
                for n in window:
                    if _match(quote, norm_all[n - 1]):
                        found_at = n
                        break
            except (TypeError, ValueError):
                pass
            if found_at is None:
                for idx, ln in enumerate(norm_all):
                    if _match(quote, ln):
                        found_at = idx + 1
                        break

            ev["verified"] = found_at is not None
            if found_at is not None:
                summary.passed += 1
                any_verified = True
                try:
                    if int(claimed) != found_at:
                        summary.line_mismatch += 1
                        ev["actual_line"] = found_at
                except (TypeError, ValueError):
                    ev["actual_line"] = found_at
        finding["evidence_verified"] = any_verified

    for c in result.get("inconclusive_concerns", []):
        if not isinstance(c, dict):
            continue
        for ev in c.get("evidence", []):
            if not isinstance(ev, dict):
                continue
            summary.total += 1
            quote = normalize(str(ev.get("quote", "")))
            found = next((n for n, ln in enumerate(norm_all, 1) if _match(quote, ln)), None)
            ev["verified"] = found is not None
            if found:
                summary.passed += 1

    for d in result.get("dismissed_concerns", []):
        if not isinstance(d, dict):
            continue
        summary.total += 1
        quote = normalize(str(d.get("counter_evidence_quote", "")))
        d["quote_verified"] = any(_match(quote, ln) for ln in norm_all) if quote else False
        if d["quote_verified"]:
            summary.passed += 1
    return summary
