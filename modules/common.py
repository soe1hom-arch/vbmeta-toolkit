# ============================================================
# VBMeta Toolkit — Common Helpers
# By. soe1hom-arch / Wandi
# ============================================================

import os
from pathlib import Path
from dataclasses import dataclass


BASE_DIR = Path(__file__).resolve().parent.parent
INPUT_DIR = BASE_DIR / "input"
OUTPUT_DIR = BASE_DIR / "output"


def ensure_workspace():
    for path in (INPUT_DIR, OUTPUT_DIR):
        path.mkdir(parents=True, exist_ok=True)


def safe_mkdir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


@dataclass
class OperationResult:
    ok: bool
    title: str
    message: str
    output_path: str = ""
