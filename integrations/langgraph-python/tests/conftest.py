import sys
from pathlib import Path

# Allow running the test suite directly against the sibling `python/` core package's source tree
# (editable installs already cover this in CI/dev, but this keeps `pytest` runnable standalone
# from a fresh checkout without a separate install step for local iteration).
_PY_CORE_SRC = Path(__file__).resolve().parents[3] / "python" / "src"
if _PY_CORE_SRC.exists() and str(_PY_CORE_SRC) not in sys.path:
    sys.path.insert(0, str(_PY_CORE_SRC))
