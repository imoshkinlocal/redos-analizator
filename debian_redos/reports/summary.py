"""Plain-text summary, also printed by the CLI."""

from __future__ import annotations

import os
from typing import List

from ..models import Finding, ScanResult

_BAR = "=" * 78


def _row(label: str, value) -> str:
    return f"  {label:<24} {value}"


def format_summary(result: ScanResult, max_findings: int = 25) -> str:
    stats = result.stats
    lines: List[str] = []
    lines.append(_BAR)
    lines.append(" Debian ReDoS scan summary")
    lines.append(_BAR)
    lines.append(_row("run", result.run_id))
    lines.append(_row("mode", result.mode))
    lines.append(_row("started", result.started_at))
    lines.append(_row("finished", result.finished_at))
    lines.append(_row("duration", f"{stats.duration_seconds:.2f} s"))
    lines.append(_row("packages", stats.packages))
    lines.append(_row("files (total/scanned)", f"{stats.files}/{stats.files_scanned}"))
    lines.append(_row("files reused (cached)", stats.files_skipped_cached))
    lines.append(_row("regexp candidates", stats.candidates))
    lines.append(_row("unique patterns", stats.unique_patterns))
    lines.append(_row("suspicious (static)", stats.static_suspicious))
    lines.append(_row("dynamic tests", stats.dynamic_run))
    lines.append(_row("confirmed", stats.confirmed))
    lines.append(_row("exploitable", stats.exploitable))
    lines.append(_row("needs review", stats.needs_review))
    lines.append(_row("known matches", stats.known_matched))
    lines.append("")

    severity = result.counts_by_severity()
    if severity:
        lines.append("  severity: " + ", ".join(
            f"{name}={severity[name]}" for name in
            ("critical", "high", "medium", "low", "info") if name in severity))
    verdicts = {}
    for finding in result.findings:
        verdicts[finding.verdict] = verdicts.get(finding.verdict, 0) + 1
    if verdicts:
        lines.append("  verdict:  " + ", ".join(
            f"{name}={count}" for name, count in sorted(verdicts.items())))
    lines.append("")

    if result.findings:
        lines.append("  Top findings")
        lines.append("  " + "-" * 74)
        lines.append(f"  {'SEVERITY':<9} {'VERDICT':<13} {'COMPLEXITY':<12} "
                     f"{'LOCATION':<32} PATTERN")
        for finding in result.findings[:max_findings]:
            location = f"{finding.package}/{finding.file}:{finding.line}"
            if len(location) > 32:
                location = "..." + location[-29:]
            pattern = (finding.pattern or "<dynamic>").replace("\n", "\\n")
            if finding.known:
                label = finding.known[0].cve or finding.known[0].id
                pattern = f"{pattern} [{label}]"
            if len(pattern) > 40:
                pattern = pattern[:37] + "..."
            lines.append(
                f"  {finding.severity:<9} {finding.verdict:<13} "
                f"{finding.static.complexity:<12} {location:<32} {pattern}"
            )
        if len(result.findings) > max_findings:
            lines.append(f"  ... {len(result.findings) - max_findings} more finding(s)")
        lines.append("")

    known_groups: dict = {}
    for finding in result.findings:
        for match in finding.known:
            key = (match.cve or match.id, match.title, match.severity or "info")
            known_groups.setdefault(key, []).append(finding)
    if known_groups:
        lines.append("  Known matches")
        lines.append("  " + "-" * 74)
        for (identifier, title, severity), findings in sorted(known_groups.items()):
            locations = ", ".join(
                f"{f.package}/{f.file}:{f.line}" for f in findings[:4])
            if len(findings) > 4:
                locations += ", ..."
            lines.append(f"  {identifier:<18} {severity:<9} {len(findings)} finding(s)")
            lines.append(f"    {title}")
            lines.append(f"    {locations}")
        lines.append("")

    if result.notes:
        lines.append("  Notes")
        for note in result.notes[:20]:
            lines.append(f"    - {note}")
        lines.append("")
    lines.append(_BAR)
    return "\n".join(lines)


def write_summary(result: ScanResult, output_dir: str,
                  filename: str = "redos-summary.txt") -> str:
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, filename)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(format_summary(result))
        fh.write("\n")
    return path
