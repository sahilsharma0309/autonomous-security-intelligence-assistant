"""Process entry point.

Thin by design: everything the CLI does lives in
:mod:`security_assistant.cli`, so this module stays importable and testable
and there is exactly one place where argument parsing happens.
"""

from __future__ import annotations

import sys
from collections.abc import Sequence

from security_assistant.cli import main as cli_main

__all__ = ["main"]


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return a process exit code."""
    return cli_main(argv)


if __name__ == "__main__":  # pragma: no cover - process entry
    sys.exit(main())
