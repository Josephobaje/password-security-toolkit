"""Allow ``python -m pwtool``."""

from pwtool.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
