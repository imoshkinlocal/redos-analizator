"""SARIF 2.1.0 reporter.

The output is accepted by GitHub code scanning, GitLab SAST consumers and any
SARIF viewer.  One rule per (complexity, verdict) pair keeps the rule list
small while preserving the most useful filter.
"""

from __future__ import annotations

import json
import os
from typing import Dict, List

from .. import __version__
from ..models import Finding, ScanResult, SEVERITY_ORDER

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
          "low": "note", "info": "note"}

_RULE_TEXT = {
    "exponential": "Exponential ReDoS: backtracking paths grow multiplicatively",
    "polynomial": "Polynomial ReDoS: overlapping repetitions cause quadratic work",
    "unknown": "Unmodelled ReDoS risk: manual review required",
    "linear": "Linear regexp complexity",
    "none": "Constant regexp complexity",
}


def _rule_id(finding: Finding) -> str:
    complexity = finding.static.complexity or "unknown"
    return f"redos/{complexity}/{finding.verdict}"


def _message(finding: Finding) -> str:
    complexity = finding.static.complexity or "unknown"
    parts = [
        f"{finding.verdict.replace('_', ' ')} {complexity} ReDoS",
        f"in {finding.function or 'unknown function'}",
        f"({finding.language}, {finding.engine})",
    ]
    if finding.dynamic.confirmed:
        if finding.dynamic.max_elapsed_ms is not None:
            parts.append(f"-- reproduced: {finding.dynamic.max_elapsed_ms:.1f} ms")
        else:
            parts.append("-- reproduced by the dynamic engine")
    elif finding.static.evidence:
        parts.append("-- " + finding.static.evidence[0].message)
    if finding.known:
        labels = [match.cve or match.id for match in finding.known[:2]]
        parts.append("-- known: " + ", ".join(labels))
    return ", ".join(parts[:3]) + (" " + " ".join(parts[3:]) if len(parts) > 3 else "")


def build(result: ScanResult) -> Dict:
    rules: Dict[str, Dict] = {}
    results: List[Dict] = []
    for finding in result.findings:
        rule_id = _rule_id(finding)
        if rule_id not in rules:
            complexity = finding.static.complexity or "unknown"
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_id.replace("/", "-"),
                "shortDescription": {"text": _RULE_TEXT.get(
                    complexity, "Regexp denial of service")},
                "help": {
                    "text": (
                        "Static analysis of the regexp structure plus dynamic "
                        "measurement in the target engine.  A finding is only "
                        "reported as confirmed when degradation was reproduced "
                        "in the real engine."
                    )
                },
                "properties": {
                    "tags": ["security", "redos", complexity] + (
                        ["known-vulnerability"] if finding.known else []),
                    "precision": "high" if finding.dynamic.confirmed else "medium",
                },
            }
        artifact = f"{finding.package}/{finding.file}".replace(os.sep, "/")
        results.append({
            "ruleId": rule_id,
            "level": _LEVEL.get(finding.severity, "warning"),
            "message": {"text": _message(finding)},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": artifact,
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {"startLine": max(1, finding.line)},
                },
                "logicalLocations": [{
                    "name": finding.function or "unknown",
                    "kind": "function",
                }],
            }],
            "partialFingerprints": {
                "redosFindingId/v1": finding.id,
            },
            "properties": {
                "package": finding.package,
                "version": finding.version,
                "findingId": finding.id,
                "verdict": finding.verdict,
                "severity": finding.severity,
                "priority": finding.priority,
                "complexity": finding.static.complexity,
                "inputControl": finding.input_control,
                "dynamicStatus": finding.dynamic.status,
                "growthClass": finding.dynamic.growth_class,
                "cve": finding.cve,
                "known": [
                    {
                        "id": match.id,
                        "cve": match.cve,
                        "title": match.title,
                        "kind": match.kind,
                        "score": match.score,
                        "confidence": match.confidence,
                        "matchTypes": list(match.match_types),
                        "patternMatched": match.pattern_matched,
                        "autoAssigned": match.auto_assigned,
                    }
                    for match in finding.known
                ],
                "duplicates": finding.duplicates,
            },
        })

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": "debian-redos",
                    "version": __version__,
                    "informationUri": "https://github.com/",
                    "rules": list(rules.values()),
                }
            },
            "automationDetails": {"id": result.run_id},
            "results": results,
            "invocations": [{
                "executionSuccessful": True,
                "startTimeUtc": result.started_at,
                "endTimeUtc": result.finished_at,
            }],
            "properties": {
                "mode": result.mode,
                "stats": result.stats.to_dict(),
            },
        }],
    }


def write_sarif(result: ScanResult, output_dir: str,
                filename: str = "redos.sarif") -> str:
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, filename)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(build(result), fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    return path
