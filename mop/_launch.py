"""Internal subprocess entry point for relocatable installations."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from mop.cli import main

if __name__ == '__main__':
    main()
