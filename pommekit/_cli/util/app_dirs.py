#  Copyright (C) 2024  Cypheriel
from pathlib import Path

from appdirs import AppDirs

_APP_DIRS = AppDirs(
    "PommeKit",
    "Cypheriel",
)

USER_DATA_DIR = Path(_APP_DIRS.user_data_dir)
USER_LOG_DIR = Path(_APP_DIRS.user_log_dir)
