import os
from .cli import main
raise SystemExit(main(os.environ.get("MOP_FRONTEND", "top")))
