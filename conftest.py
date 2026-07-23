"""Ensures `src/` is on sys.path for test collection, independent of whether
the editable install (`pip install -e .`) correctly linked the package.
This is a safety net for environments where editable installs misbehave
(e.g. certain older pip/setuptools versions on Windows) — pytest will find
vulnscan modules even if `import vulnscan` would otherwise fail.
"""

import sys
from pathlib import Path

SRC_DIR = Path(__file__).parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
