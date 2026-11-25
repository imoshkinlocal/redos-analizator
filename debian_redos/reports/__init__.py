"""Report writers and the ``write_reports`` dispatcher."""

from __future__ import annotations

import json
import os
from typing import Dict, Iterable, Optional, Sequence

from ..models import ScanResult
from . import html_report, json_report, sarif, summary

FORMATS = ("json", "jsonl", "sarif", "html", "summary")

_WRITERS = {
    "json": json_report.write_json,
    "jsonl": json_report.write_jsonl,
    "sarif": sarif.write_sarif,
    "html": html_report.write_html,
    "summary": summary.write_summary,
}


def write_reports(result: ScanResult, output_dir: str,
                  formats: Optional[Sequence[str]] = None) -> Dict[str, str]:
    """Write the requested reports and return ``{format: path}``."""
    os.makedirs(output_dir, exist_ok=True)
    chosen = [name for name in (formats or FORMATS) if name in _WRITERS]
    if not chosen:
        raise ValueError(f"no known report format in {formats!r}; "
                         f"expected any of {', '.join(FORMATS)}")
    paths: Dict[str, str] = {}
    for name in chosen:
        paths[name] = _WRITERS[name](result, output_dir)
    manifest = os.path.join(output_dir, "manifest.json")
    data = {
        "run_id": result.run_id,
        "generated_at": result.finished_at,
        "reports": {name: os.path.basename(path) for name, path in paths.items()},
        "stats": result.stats.to_dict(),
    }
    with open(manifest, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    paths["manifest"] = manifest
    return paths


def read_jsonl_findings(path: str):
    from ..models import Finding

    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            if record.get("kind") == "finding":
                record.pop("kind", None)
                yield Finding.from_dict(record)
