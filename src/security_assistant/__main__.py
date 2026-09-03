"""``python -m security_assistant`` entry point."""

from __future__ import annotations

import sys

from security_assistant.main import main

if __name__ == "__main__":  # pragma: no cover - process entry
    sys.exit(main())
