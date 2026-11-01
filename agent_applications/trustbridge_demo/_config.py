"""Configuration and runtime paths for the TrustBridge demo application."""

from __future__ import annotations

import os
from pathlib import Path

from nlip_sdk.config import load_config

APP_DIR = Path(__file__).parent
DOCUMENTS_DIR = APP_DIR / "documents"
# Side effects of the tools land here so a run can be inspected afterwards.
RUNTIME_DIR = APP_DIR / "runtime"

# TRUSTBRIDGE_CONFIG lets evaluation runs switch between defended and undefended setups.
CONFIG_PATH = Path(os.environ.get("TRUSTBRIDGE_CONFIG", APP_DIR / "config.toml"))
CONFIG = load_config(CONFIG_PATH)
