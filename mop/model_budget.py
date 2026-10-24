"""Local tokenizer discovery shared by all observation adapters."""
import os
from functools import lru_cache
from pathlib import Path

@lru_cache(maxsize=1)
def tokenizer():
    path=os.environ.get("MOP_TOKENIZER_PATH")
    if not path:
        from .paths import runtime_root
        path=str(runtime_root()/"models/Open-Jev-2B/tokenizer.json")
    if not Path(path).is_file():return None
    try:
        from tokenizers import Tokenizer
    except ImportError:return None
    return Tokenizer.from_file(path)

