"""Live web dashboard: Starlette + WebSocket feed + offline canvas map.

Runs the sniffer in a background thread and streams enriched flow records to
connected browsers. Serves a single self-contained HTML page.

Built on Starlette (what FastAPI is built on) because this dashboard needs no
request validation, and Starlette avoids pydantic/pydantic-core, which need a
Rust toolchain on Termux. Binds to 127.0.0.1:8000 by default (WIT_HOST/WIT_PORT).
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
import threading
from pathlib import Path

from starlette.applications import Starlette
from starlette.responses import HTMLResponse, JSONResponse
from starlette.routing import Route, WebSocketRoute
from starlette.websockets import WebSocket, WebSocketDisconnect

import config
from core.dns_resolver import shutdown as shutdown_dns
from core.ip_filter import load_networks
from core.meta_ranges import refresh_ranges
from core.packet_sniffer import PacketSniffer
from core.reporting import write_rows
from utils.geo_ip import close as close_geo
from utils.helpers import ensure_dirs, finalize_outputs

log = logging.getLogger("wit")

INDEX = Path(__file__).resolve().parent / "static" / "index.html"

_clients: set[WebSocket] = set()
_loop: asyncio.AbstractEventLoop | None = None
_sniffer: PacketSniffer | None = None
_thread: threading.Thread | None = None
_error: str | None = None
_options: dict = {"iface": "", "count": 0, "timeout": None, "no_refresh": False,
                  "export_dir": None, "backend": config.DEFAULT_BACKEND}


def _broadcast(record: dict) -> None:
    """Called from the sniffer thread; hands the record to the asyncio loop."""
    loop = _loop
    if loop is None or loop.is_closed():
        return
    try:
        asyncio.run_coroutine_threadsafe(_push(record), loop)
    except RuntimeError:  # loop shutting down
        pass


async def _push(record: dict) -> None:
    dead = []
    for ws in list(_clients):
        try:
            await ws.send_json(record)
        except Exception:
            dead.append(ws)
    for ws in dead:
        _clients.discard(ws)


def _run_sniffer() -> None:
    global _sniffer, _error
    try:
        ranges = config.WHATSAPP_IP_RANGES if _options["no_refresh"] else refresh_ranges()
        load_networks(ranges)
        _sniffer = PacketSniffer(on_record=_broadcast, backend=_options["backend"])
        _sniffer.start_sniffing(
            iface=_options["iface"], count=_options["count"], timeout=_options["timeout"]
        )
    except PermissionError as exc:
        _error = str(exc)
        log.error("%s", exc)
    except Exception as exc:  # CaptureError, OSError, ...
        _error = f"Capture stopped: {exc}"
        log.error("%s", _error)


def _stop_sniffer() -> None:
    sniffer, thread = _sniffer, _thread
    if sniffer is not None:
        sniffer.stop()
    if thread is not None and thread.is_alive():
        thread.join(timeout=5)
    if sniffer is not None:
        rows = sniffer.rows()
        if rows:
            write_rows(rows)
    close_geo()
    shutdown_dns()
    finalize_outputs(_options["export_dir"])


@contextlib.asynccontextmanager
async def lifespan(_app):
    global _loop, _thread
    ensure_dirs()
    _loop = asyncio.get_running_loop()
    _thread = threading.Thread(target=_run_sniffer, name="wit-sniffer", daemon=True)
    _thread.start()
    log.info("Dashboard ready at http://%s:%d", config.DASH_HOST, config.DASH_PORT)
    try:
        yield
    finally:
        await _loop.run_in_executor(None, _stop_sniffer)


async def index(_request):
    return HTMLResponse(INDEX.read_text(encoding="utf-8"))


async def report(_request):
    return JSONResponse(_sniffer.rows() if _sniffer else [])


async def status(_request):
    running = bool(_thread and _thread.is_alive())
    return JSONResponse({
        "running": running,
        "iface": _sniffer.iface if _sniffer else None,
        "backend": _sniffer.backend if _sniffer else None,
        "link_kind": _sniffer.link_kind if _sniffer else None,
        "filter_mode": _sniffer.filter_mode if _sniffer else None,
        "frames": _sniffer.frames_seen if _sniffer else 0,
        "error": _error,
    })


async def ws(websocket: WebSocket):
    await websocket.accept()
    _clients.add(websocket)
    try:
        while True:
            await websocket.receive_text()  # keep-alive / ignore
    except WebSocketDisconnect:
        pass
    finally:
        _clients.discard(websocket)


app = Starlette(
    routes=[
        Route("/", index),
        Route("/api/report", report),
        Route("/api/status", status),
        WebSocketRoute("/ws", ws),
    ],
    lifespan=lifespan,
)


def run(iface: str = "", count: int = 0, timeout: int | None = None,
        no_refresh: bool = False, export_dir: str | None = None,
        backend: str | None = None) -> int:
    import uvicorn

    _options.update(iface=iface, count=count, timeout=timeout, no_refresh=no_refresh,
                    export_dir=export_dir, backend=backend or config.DEFAULT_BACKEND)
    try:
        # Plain asyncio + h11: no uvloop/httptools/watchfiles needed (Termux-friendly).
        uvicorn.run(app, host=config.DASH_HOST, port=config.DASH_PORT, log_level="warning",
                    loop="asyncio", http="h11")
    except OSError as exc:
        log.error("Dashboard failed to bind %s:%d (%s). Is another instance running? "
                  "Change WIT_PORT.", config.DASH_HOST, config.DASH_PORT, exc)
        return 1
    return 0


if __name__ == "__main__":
    from utils.helpers import require_root, setup_logging

    require_root(setup_logging())
    raise SystemExit(run(iface=config.DEFAULT_IFACE, count=config.DEFAULT_COUNT))
