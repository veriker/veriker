"""``python -m veriker`` — run the offline bundle verifier."""

import sys

from veriker.cli.verify import main

if __name__ == "__main__":
    sys.exit(main())
