from __future__ import annotations

import re
import sys
from pathlib import Path

from loguru import logger


OUTPUT_DIR = Path(__file__).resolve().parent.parent / "output"
LOG_FILE = OUTPUT_DIR / "swarm.log"
_LOGGER_CONFIGURED = False

_TERMINAL_FORMAT = (
    "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
    "<cyan>{extra[agent_name]}</cyan> | "
    "{level} | "
    "<level>{message}</level>"
)

_FILE_FORMAT = (
    "{time:YYYY-MM-DD HH:mm:ss} | "
    "{extra[agent_name]} | "
    "{level} | "
    "{message}"
)

_LEVEL_CONFIGS = (
    ("AGENT_START", 25, "<green>", ""),
    ("AGENT_DONE", 26, "<bold><green>", ""),
    ("HANDOFF", 27, "<magenta>", ""),
)


def _format_agent_name(name: str) -> str:
    spaced_name = re.sub(r"(?<!^)(?=[A-Z])", " ", name).strip()
    return spaced_name.upper()


def _register_custom_levels() -> None:
    logger.level("INFO", color="<cyan>")
    logger.level("SUCCESS", color="<green>")
    logger.level("WARNING", color="<yellow>")
    logger.level("ERROR", color="<red>")
    logger.level("CRITICAL", color="<bold><red>")

    for level_name, level_no, color, icon in _LEVEL_CONFIGS:
        try:
            logger.level(level_name, color=color, icon=icon)
        except ValueError:
            logger.level(level_name, no=level_no, color=color, icon=icon)


def _configure_logger() -> None:
    global _LOGGER_CONFIGURED

    if _LOGGER_CONFIGURED:
        return

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    _register_custom_levels()

    logger.remove()
    logger.add(
        sys.stdout,
        colorize=True,
        format=_TERMINAL_FORMAT,
        level="INFO",
    )
    logger.add(
        LOG_FILE,
        colorize=False,
        format=_FILE_FORMAT,
        level="INFO",
        enqueue=True,
    )

    _LOGGER_CONFIGURED = True


def get_logger(name: str):
    _configure_logger()
    return logger.bind(agent_name=_format_agent_name(name))
