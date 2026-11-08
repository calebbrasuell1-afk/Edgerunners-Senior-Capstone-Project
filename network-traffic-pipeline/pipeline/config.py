"""Config loading + path resolution. All relative paths resolve against the
project root (the parent of this ``pipeline`` package), so scripts work no
matter what directory they are invoked from."""
from __future__ import annotations

import os
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG = Path(__file__).resolve().parent / "config.yaml"


def load_dotenv(env_path: str | os.PathLike | None = None) -> None:
    """Populate os.environ from a project-root ``.env`` file (KEY=VALUE lines).

    Real environment variables always win (we only fill what's unset), and empty
    values are skipped. Loaded on import so both the backend and the pipeline
    pick up secrets kept out of version control.
    """
    p = Path(env_path) if env_path else (PROJECT_ROOT / ".env")
    if not p.exists():
        return
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if key and val and key not in os.environ:
            os.environ[key] = val


load_dotenv()


def load_config(path: str | os.PathLike | None = None) -> dict:
    cfg_path = Path(path) if path else DEFAULT_CONFIG
    with open(cfg_path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def resolve(rel_path: str | os.PathLike) -> Path:
    """Resolve a (possibly relative) config path against the project root."""
    p = Path(rel_path)
    return p if p.is_absolute() else (PROJECT_ROOT / p)
