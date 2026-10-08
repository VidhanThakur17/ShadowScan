"""Enables ``python -m shadow_scan ...`` (equivalent to the ``shadowscan`` script
and to ``python -m shadow_scan.main``)."""

import sys

from .main import main

if __name__ == "__main__":
    sys.exit(main())
