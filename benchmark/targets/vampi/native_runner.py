#!/usr/bin/env python3
"""Run a checked-out VAmPI tree on loopback without Docker.

VAmPI's `app.py` relies on being executed as `__main__`; importing it as a
module creates a circular import through `config.py`. This runner executes the
same file under `__main__` (preserving that behavior), suppresses its hardcoded
0.0.0.0:5000/debug entrypoint, and binds the requested local port instead.

Usage, from a VAmPI checkout:
    PORT=5001 VAMPI_PYTHON=/path/to/python python native_runner.py
"""

from __future__ import annotations

import os
from pathlib import Path

SOURCE = Path("app.py")
code = SOURCE.read_text(encoding="utf-8")
marker = "if __name__ == '__main__':"
if marker not in code:
    raise SystemExit("app.py entrypoint marker not found")
code = code.replace(marker, "if False:", 1)
namespace = {
    "__name__": "__main__",
    "__file__": str(SOURCE.resolve()),
    "__package__": None,
}
exec(compile(code, str(SOURCE), "exec"), namespace)  # noqa: S102 - local benchmark target
namespace["vuln_app"].run(
    host="127.0.0.1",
    port=int(os.environ.get("PORT", "5000")),
    debug=False,
)
