#!/usr/bin/python3 -I
"""Launch an isolated, relocatable MOP installation."""
import sys
from pathlib import Path

if sys.platform != 'linux':
    raise SystemExit('MOP monitoring requires Linux. Use a Linux host or VM.')
if sys.version_info < (3, 10):
    raise SystemExit('MOP requires Python 3.10 or newer.')
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'share/modeio-mop'))
from mop.cli import main, hmain, bmain

{'mop': main, 'hmop': hmain, 'bmop': bmain}[Path(__file__).name]()
