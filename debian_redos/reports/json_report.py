"""JSON and JSONL reporters."""

from __future__ import annotations

import json
import os
from typing import Dict

from .. import __version__
from ..models import ScanResult

SCHEMA_VERSION = "1.0"


def _metadata(result: ScanResult) -> Dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "debian-redos", "version": __version__},
        "run_id": result.run_id,
        "started_at": result.started_at,
        "finished_at": result.finished_at,
        "mode": result.mode,
    }


def write_json(result: ScanResult, output_dir: str,
               filename: str = "redos-report.json") -> str:
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, filename)
    payload = _metadata(result)
    payload.update({
        "packages": [p.to_dict() for p in result.packages],
        "stats": result.stats.to_dict(),
        "config": result.config,
        "notes": result.notes,
        "findings": [f.to_dict() for f in result.findings],
    })
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    return path


def write_jsonl(result: ScanResult, output_dir: str,
                filename: str = "redos-findings.jsonl") -> str:
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, filename)
    with open(path, "w", encoding="utf-8") as fh:
        header = _metadata(result)
        header["kind"] = "scan"
        header["stats"] = result.stats.to_dict()
        fh.write(json.dumps(header, ensure_ascii=False) + "\n")
        for finding in result.findings:
            record = {"kind": "finding"}
            record.update(finding.to_dict())
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    return path
