"""Non-blocking reverse-DNS with a small daemon worker pool.

``reverse_dns(ip)`` never waits: it returns a cached hostname or ``None`` and
queues the lookup on background threads. A lookup that has not finished after
``timeout`` seconds is given up on (cached as unknown), so a slow Android
resolver can never stall packet capture. Workers are daemon threads, so a hung
lookup cannot block process exit either.
"""
from __future__ import annotations

import logging
import queue
import socket
import threading
import time
from typing import Callable

import config

log = logging.getLogger("wit")

_META_MARKERS = ("whatsapp", "facebook", "fbcdn", "fbsv", "instagram", "1e100")
_MAX_CACHE = 8192


class Resolver:
    def __init__(self, workers: int = 4, timeout: float = 2.0, enabled: bool = True,
                 resolver: Callable[[str], tuple] = socket.gethostbyaddr,
                 max_pending: int = 256):
        self.workers = max(1, workers)
        self.timeout = timeout
        self.enabled = enabled
        self.max_pending = max_pending
        self._resolver = resolver
        self._cache: dict[str, str | None] = {}
        self._pending: dict[str, float] = {}
        self._queue: queue.Queue[str | None] = queue.Queue()
        self._lock = threading.Lock()
        self._threads: list[threading.Thread] = []

    # -- public API ---------------------------------------------------------
    def lookup(self, ip: str) -> str | None:
        """Cached hostname or None. Queues a background lookup on first sight."""
        if not self.enabled or not ip:
            return None
        with self._lock:
            if ip in self._cache:
                return self._cache[ip]
            started = self._pending.get(ip)
            if started is not None:
                if time.monotonic() - started > self.timeout:
                    self._pending.pop(ip, None)
                    self._cache[ip] = None  # give up; late answers still overwrite
                return None
            if len(self._pending) >= self.max_pending:
                return None
            self._pending[ip] = time.monotonic()
        self._ensure_workers()
        self._queue.put(ip)
        return None

    def wait_for(self, ip: str, timeout: float = 2.0) -> str | None:
        """Test/diagnostic helper: poll until ``ip`` is resolved or time is up."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                if ip in self._cache:
                    return self._cache[ip]
            self.lookup(ip)
            time.sleep(0.01)
        return None

    def shutdown(self) -> None:
        for _ in self._threads:
            self._queue.put(None)
        self._threads = []

    # -- internals ----------------------------------------------------------
    def _ensure_workers(self) -> None:
        with self._lock:
            alive = [t for t in self._threads if t.is_alive()]
            self._threads = alive
            missing = self.workers - len(alive)
        for _ in range(max(0, missing)):
            t = threading.Thread(target=self._worker, name="wit-rdns", daemon=True)
            t.start()
            with self._lock:
                self._threads.append(t)

    def _worker(self) -> None:
        while True:
            ip = self._queue.get()
            if ip is None:
                return
            try:
                host = self._resolver(ip)[0]
            except (OSError, UnicodeError, IndexError):
                host = None
            except Exception as exc:  # defensive: a worker must never die
                log.debug("reverse DNS error for %s: %s", ip, exc)
                host = None
            with self._lock:
                self._pending.pop(ip, None)
                if len(self._cache) >= _MAX_CACHE:
                    self._cache.clear()
                self._cache[ip] = host


_default: Resolver | None = None
_default_lock = threading.Lock()


def get_resolver() -> Resolver:
    global _default
    with _default_lock:
        if _default is None:
            _default = Resolver(
                workers=config.RDNS_WORKERS,
                timeout=config.RDNS_TIMEOUT,
                enabled=config.RDNS_ENABLED,
            )
        return _default


def reverse_dns(ip: str) -> str | None:
    return get_resolver().lookup(ip)


def shutdown() -> None:
    global _default
    with _default_lock:
        if _default is not None:
            _default.shutdown()
            _default = None


def is_meta_hostname(host) -> bool:
    if not host:
        return False
    host = host.lower()
    return any(d in host for d in _META_MARKERS)
