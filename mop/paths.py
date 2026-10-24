"""Writable runtime locations for source and package installations."""
import os
from pathlib import Path


def runtime_root(project_root=None):
    if os.environ.get('MOP_RUNTIME_DIR'):
        return Path(os.environ['MOP_RUNTIME_DIR']).expanduser()
    project = Path(project_root) if project_root else Path(__file__).resolve().parents[1]
    if (project / 'scripts/env.sh').is_file():
        return project / '.runtime'
    from .model_slots import state_root
    return state_root() / 'runtime'


def python_command(*arguments):
    """Keep subprocess imports independent of the current working directory."""
    import sys
    return [sys.executable, '-I', str(Path(__file__).with_name('_launch.py')), *arguments]
