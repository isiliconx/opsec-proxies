"""Load a project module by file path under a private name.

Needed because the pipeline stage directory is literally named `enum/`, which
would otherwise shadow the stdlib `enum` module that `re`, `json`, `os` and half
of the standard library import at interpreter start. The directory name is part
of the layout, so instead of renaming it we load those two modules explicitly.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parent.parent
_cache: dict[str, ModuleType] = {}


def load(relpath: str, alias: str) -> ModuleType:
    """Import ROOT/relpath as `alias` (e.g. load('enum/queue.py', 'resi_enum_queue'))."""
    if alias in _cache:
        return _cache[alias]
    path = ROOT / relpath
    if not path.exists():
        raise ImportError(f"no such module file: {path}")
    spec = importlib.util.spec_from_file_location(alias, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[alias] = mod
    spec.loader.exec_module(mod)
    _cache[alias] = mod
    return mod


def build_queue_module():
    return load("enum/queue.py", "resi_enum_queue")


def ports_module():
    return load("enum/ports.py", "resi_enum_ports")
