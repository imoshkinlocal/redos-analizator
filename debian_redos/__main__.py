"""Allow ``python -m debian_redos`` as a shortcut for the CLI."""

from __future__ import annotations

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
