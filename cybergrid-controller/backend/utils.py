"""
Utility helpers for the CyberGrid controller backend.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from cryptography.fernet import Fernet, InvalidToken


LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger("cybergrid.utils")


_FERNET_KEY_ENV = "CYBERGRID_FERNET_KEY"
_lock = threading.Lock()
_fernet_instance: Optional[Fernet] = None


def _load_fernet_key() -> bytes:
    """
    Load or generate the encryption key used throughout the backend.
    """
    key = os.getenv(_FERNET_KEY_ENV)
    if key:
        return key.encode("utf-8")

    # Generate a key if none exists and persist to local file for dev usage.
    key_path = Path(".fernet.key")
    if key_path.exists():
        data = key_path.read_bytes()
        os.environ[_FERNET_KEY_ENV] = data.decode("utf-8")
        return data

    key = Fernet.generate_key()
    key_path.write_bytes(key)
    os.environ[_FERNET_KEY_ENV] = key.decode("utf-8")
    logger.info("Generated new Fernet key at %s", key_path)
    return key


def get_cipher() -> Fernet:
    """
    Thread-safe accessor for the shared Fernet cipher.
    """
    global _fernet_instance
    if _fernet_instance is None:
        with _lock:
            if _fernet_instance is None:
                _fernet_instance = Fernet(_load_fernet_key())
    return _fernet_instance


def encrypt(value: str) -> str:
    """
    Encrypt a string using Fernet symmetric encryption.
    """
    cipher = get_cipher()
    token = cipher.encrypt(value.encode("utf-8"))
    return token.decode("utf-8")


def decrypt(token: str) -> Optional[str]:
    """
    Decrypt a token and return the original string.

    Returns None if the token is invalid.
    """
    cipher = get_cipher()
    try:
        value = cipher.decrypt(token.encode("utf-8"))
    except InvalidToken:
        logger.warning("Failed to decrypt token")
        return None
    return value.decode("utf-8")


_SANITIZE_RE = re.compile(r"[^\w\s\-@.:/]")


def sanitize_text(value: str) -> str:
    """
    Basic input sanitization to strip unusual characters.
    """
    cleaned = _SANITIZE_RE.sub("", value)
    return re.sub(r"\s+", " ", cleaned).strip()


def load_json(path: Path) -> Any:
    """
    Load JSON data from disk with helpful error logging.
    """
    logger.debug("Loading JSON file: %s", path)
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def env_flag(name: str, default: bool = False) -> bool:
    """
    Read a boolean flag from the environment.
    """
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class SchedulerJob:
    """
    Descriptor for background tasks handled by the lightweight scheduler.
    """

    interval_seconds: int
    target: Any
    name: str
    args: tuple[Any, ...] = ()
    kwargs: Dict[str, Any] = None

    def __post_init__(self) -> None:
        if self.kwargs is None:
            self.kwargs = {}


class RepeatingTimer(threading.Thread):
    """
    Minimal background scheduler for periodic jobs.
    """

    def __init__(self) -> None:
        super().__init__(daemon=True)
        self._jobs: list[SchedulerJob] = []
        self._stop_event = threading.Event()

    def register(self, job: SchedulerJob) -> None:
        logger.info("Registered background job '%s'", job.name)
        self._jobs.append(job)

    def stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        logger.info("Starting background scheduler with %d jobs", len(self._jobs))
        import time

        last_run: Dict[str, float] = {}
        while not self._stop_event.is_set():
            for job in self._jobs:
                previous = last_run.get(job.name, 0.0)
                current = time.monotonic()
                if current - previous >= job.interval_seconds:
                    try:
                        job.target(*job.args, **job.kwargs)
                    except Exception as exc:  # pragma: no cover - fail-safe logging
                        logger.exception("Job '%s' failed: %s", job.name, exc)
                    last_run[job.name] = current
            self._stop_event.wait(timeout=1.0)


