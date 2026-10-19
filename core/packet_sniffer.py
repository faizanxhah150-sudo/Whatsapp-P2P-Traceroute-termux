"""Packet capture engine (TCP + UDP) with a backend fallback chain.

Backends (``--backend`` / WIT_BACKEND, default ``auto``):

* ``afpacket`` - native AF_PACKET raw socket. No libpcap, no tcpdump, no Scapy.
  Preferred on Linux and Android.
* ``tcpdump``  - spawns ``tcpdump -w -`` and parses the pcap stream. Used by
  ``auto`` when AF_PACKET fails for a reason other than missing permissions.
* ``scapy``    - Windows/macOS only, or when explicitly requested. Scapy does
  not support Android, so it is never imported implicitly there.

Backend selection is capability based (``utils.platform_utils``), never based on
OS-name strings: Python 3.13+ reports ``sys.platform == "android"`` in Termux.

The link type is read per interface: Ethernet (Wi-Fi, type 1) frames carry a
14-byte header, raw-IP frames (cellular ccmni*/rmnet*, type 519/512) do not.
The PCAP is written with the matching linktype (1 = Ethernet, 101 = raw IP).

BPF: try a kernel filter first; on any failure fall back to Python-side
filtering with a clear warning. The capture never crashes over a filter.
A PermissionError never triggers a silent fallback: it means "not root".
"""
from __future__ import annotations

import errno
import logging
import os
import re
import select
import socket
import subprocess
import threading
import time
from collections import deque

import config
from core.bpf import (
    attach_kernel_filter,
    build_fallback_filter,
    compile_kernel_filter,
)
from core.classifier import classify_info
from core.packet_parser import LINK_ETHERNET, LINK_RAW, LINK_UNKNOWN, parse_frame
from core.pcap_stream import PcapStreamError, PcapStreamParser
from core.reporting import Aggregator
from utils import netif
from utils.pcap import PcapWriter, linktype_for_kind
from utils.platform_utils import (
    af_packet_supported,
    find_tcpdump,
    is_android_platform,
    is_linux,
    netif_available,
    root_help_message,
)

log = logging.getLogger("wit")

ETH_P_ALL = 0x0003
PACKET_OUTGOING = 4
RECV_BUFSIZE = 65535


class CaptureError(RuntimeError):
    """Capture could not start (bad interface, no usable network, ...)."""


class CapturePermissionError(PermissionError):
    """Raw socket creation was denied (not root / SELinux)."""


class InterfaceNotFoundError(CaptureError):
    """The requested --iface does not exist."""


VALID_BACKENDS = ("auto", "afpacket", "tcpdump", "scapy")
_PERMISSION_RE = re.compile(r"permission|not permitted|don't have permission", re.I)


def _scapy_autodetect() -> str:
    """Interface auto-detect for platforms without /sys (Windows/macOS) - lazy Scapy."""
    if is_linux() or is_android_platform():
        raise CaptureError(
            "Cannot auto-detect an interface: /sys/class/net and /proc/net/dev are not "
            "readable. Run through root (bash scripts/run_root.sh) or pass --iface NAME."
        )
    try:
        from scapy.all import get_working_ifaces

        ifaces = get_working_ifaces()
        if ifaces:
            name = getattr(ifaces[0], "name", str(ifaces[0]))
            log.info("Auto-selected interface: %s", name)
            return name
    except Exception as exc:
        log.debug("Scapy interface auto-detect failed: %s", exc)
    raise CaptureError("Could not auto-detect an interface; pass --iface explicitly.")


def pick_interface(requested: str = "") -> str:
    """Return a usable interface name using only /sys and /proc (never Scapy on Linux/Android).

    ``--iface`` is accepted as a plain string but validated against the kernel's list so a
    typo gives a clean message with the available names instead of a traceback.
    """
    ifaces = netif.list_interfaces() if netif_available() else []
    if requested:
        names = sorted(i.name for i in ifaces)
        if names and requested not in names:
            raise InterfaceNotFoundError(
                f"Interface '{requested}' not found. Available: {', '.join(names)} "
                "(typical: wlan0, ap0, wlan1, swlan0, ccmni*, rmnet_data*). "
                "Run with --list-ifaces for details."
            )
        return requested

    if ifaces:
        chosen, warnings = netif.choose_interface(ifaces, netif.default_route_ifaces())
        for w in warnings:
            log.warning(w)
        if chosen:
            log.info("Auto-selected interface: %s (%s, link %s)",
                     chosen.name, chosen.category, chosen.link_kind)
            return chosen.name
        raise CaptureError(
            "No usable network interface found. Run with --list-ifaces to see what "
            "the system exposes and pick one with --iface (hotspot clients: ap0 / "
            "wlan1 / swlan0)."
        )
    return _scapy_autodetect()


def select_backends(requested: str = "auto") -> list[str]:
    """Ordered backend chain. ``auto`` never includes Scapy on Linux/Android."""
    requested = (requested or "auto").strip().lower()
    if requested not in VALID_BACKENDS:
        raise CaptureError(
            f"Unknown backend '{requested}'. Choose one of: {', '.join(VALID_BACKENDS)}."
        )
    if requested != "auto":
        return [requested]
    if is_linux() or is_android_platform():
        chain = ["afpacket"] if af_packet_supported() else []
        chain.append("tcpdump")
        return chain
    return ["scapy"]


def _permission_message(iface: str, exc: Exception) -> str:
    return (
        f"Cannot open a raw packet socket on '{iface}' ({exc}). {root_help_message()} "
        "If you are already root and it still fails, check the Magisk grant for Termux "
        "(Superuser tab) - SELinux is only a last-resort suspect (`su -c getenforce`)."
    )


class PacketSniffer:
    def __init__(self, log_file=None, on_record=None, bpf: str | None = None,
                 backend: str | None = None):
        self.log_file = str(log_file or config.LOG_FILE)
        self.backend_pref = config.DEFAULT_BACKEND if backend is None else backend
        self.backend: str | None = None       # backend actually running (for status/logs)
        self.on_record = on_record            # optional callback(record_dict) for live feed
        self.bpf = config.BPF_FILTER if bpf is None else bpf
        self.records: deque = deque(maxlen=config.MAX_RECORDS)  # recent FlowRecords
        self.aggregator = Aggregator()
        self.iface: str | None = None
        self.link_kind: str = LINK_UNKNOWN
        self.frames_seen = 0
        self.packets_saved = 0
        self.filter_mode = "none"             # "kernel" | "python" | "none"
        self.local_ips: set[str] = set()
        self._py_filter = None
        self._pcap: PcapWriter | None = None
        self._pcap_kind: str | None = None
        self._pcap_mismatch_warned = False
        self._stop = threading.Event()

    # -- control ------------------------------------------------------------
    def stop(self) -> None:
        self._stop.set()

    @property
    def stopped(self) -> bool:
        return self._stop.is_set()

    def rows(self) -> list[dict]:
        return self.aggregator.rows()

    # -- frame pipeline -----------------------------------------------------
    def process_frame(self, data: bytes, kind: str, direction: str | None = None,
                      ts: float | None = None) -> bool:
        """Parse, filter, classify, record. Returns True if the frame was recorded."""
        info = parse_frame(data, kind)
        if info is None:
            return False
        if self._py_filter is not None and not self._py_filter(info):
            return False
        self.frames_seen += 1
        record = classify_info(info, direction, self.local_ips)
        if record is None:
            return False

        self.records.append(record)
        as_dict = record.to_dict()
        self.aggregator.add(as_dict)
        self._write_pcap(data, kind, ts)

        tag = "PEER?" if record.candidate_peer else ("META" if record.is_meta else "REMOTE")
        log.info(
            "[%s] %s %s:%d -> %s:%d %s %s",
            tag, record.proto, record.src, record.sport,
            record.dst, record.dport, record.org, record.country,
        )
        if self.on_record:
            try:
                self.on_record(as_dict)
            except Exception as exc:
                log.debug("on_record callback error: %s", exc)
        return True

    def _write_pcap(self, data: bytes, kind: str, ts: float | None) -> None:
        if self._pcap is None:
            self._pcap_kind = kind
            self._pcap = PcapWriter(self.log_file, linktype_for_kind(kind))
        elif kind != self._pcap_kind:
            if not self._pcap_mismatch_warned:
                log.warning("Link type changed mid-capture (%s -> %s); extra frames not "
                            "written to the PCAP.", self._pcap_kind, kind)
                self._pcap_mismatch_warned = True
            return
        self._pcap.write(data, ts)
        self.packets_saved += 1

    # -- capture ------------------------------------------------------------
    def start_sniffing(self, iface: str = "", count: int = 0, timeout: float | None = None):
        self._stop.clear()
        iface = pick_interface(iface)
        self.iface = iface
        backends = select_backends(self.backend_pref)
        runners = {
            "afpacket": self._sniff_af_packet,
            "tcpdump": self._sniff_tcpdump,
            "scapy": self._sniff_scapy,
        }
        errors: list[str] = []
        try:
            for idx, name in enumerate(backends):
                self.backend = name
                log.info("Capture backend: %s | interface: %s | filter: %r | count: %s",
                         name, iface, self.bpf, count or "unlimited")
                try:
                    runners[name](iface, count, timeout)
                    return
                except CapturePermissionError:
                    raise  # not root / Magisk not granted: never fall back silently
                except (CaptureError, OSError) as exc:
                    errors.append(f"{name}: {exc}")
                    final = idx == len(backends) - 1
                    if final or self.frames_seen or self._stop.is_set():
                        if len(errors) > 1:
                            raise CaptureError(
                                "All capture backends failed - " + "; ".join(errors)
                            ) from exc
                        raise
                    log.warning("Backend '%s' failed (%s); falling back to '%s'.",
                                name, exc, backends[idx + 1])
        finally:
            self.save_packets()

    def _open_socket(self, iface: str) -> socket.socket:
        try:
            # protocol 0: receive nothing until bound, so the BPF filter is in place first
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
        except PermissionError as exc:
            raise CapturePermissionError(_permission_message(iface, exc)) from exc
        except OSError as exc:
            if exc.errno in (errno.EPERM, errno.EACCES):
                raise CapturePermissionError(_permission_message(iface, exc)) from exc
            raise CaptureError(f"Cannot create AF_PACKET socket: {exc}") from exc

        try:
            self._setup_filter(sock, iface)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
            except OSError:
                pass
            sock.bind((iface, ETH_P_ALL))
            sock.settimeout(0.5)
        except PermissionError as exc:
            sock.close()
            raise CapturePermissionError(_permission_message(iface, exc)) from exc
        except OSError as exc:
            sock.close()
            if exc.errno in (errno.EPERM, errno.EACCES):
                raise CapturePermissionError(_permission_message(iface, exc)) from exc
            if exc.errno in (errno.ENODEV, errno.ENXIO):
                raise CaptureError(
                    f"Interface '{iface}' does not exist (see --list-ifaces)."
                ) from exc
            raise CaptureError(f"Cannot bind to '{iface}': {exc}") from exc
        return sock

    def _setup_filter(self, sock, iface: str) -> None:
        """Kernel BPF if possible, else Python-side filtering (never fatal)."""
        self.filter_mode = "none"
        self._py_filter = None
        if not self.bpf:
            return
        insns, reason = compile_kernel_filter(self.bpf, iface)
        if insns:
            try:
                attach_kernel_filter(sock, insns)
                self.filter_mode = "kernel"
                log.info("Kernel BPF filter attached (%d instructions).", len(insns))
                return
            except (OSError, ValueError, TypeError) as exc:
                reason = f"SO_ATTACH_FILTER failed: {exc}"
        log.warning(
            "Kernel BPF filter unavailable (%s). Falling back to Python-side filtering; "
            "capture still works, it is just a little slower.", reason,
        )
        self._py_filter = build_fallback_filter(self.bpf)
        self.filter_mode = "python" if self._py_filter else "none"

    def _sniff_af_packet(self, iface: str, count: int, timeout: float | None) -> None:
        if not af_packet_supported():
            raise CaptureError(
                "AF_PACKET raw sockets are not available here (no AF_PACKET support or "
                "/sys/class/net not readable). Try --backend tcpdump."
            )
        self.link_kind = netif.link_kind_for(iface)
        self.local_ips = netif.local_addresses(iface)
        if self.link_kind == LINK_RAW:
            log.info("Interface %s is raw-IP (no Ethernet header).", iface)
        elif self.link_kind == LINK_UNKNOWN:
            log.info("Link type of %s unknown; deciding per packet.", iface)
        if self.local_ips:
            log.debug("Local addresses on %s: %s", iface, ", ".join(sorted(self.local_ips)))

        sock = self._open_socket(iface)
        deadline = time.monotonic() + timeout if timeout else None
        try:
            while not self._stop.is_set():
                if deadline is not None and time.monotonic() >= deadline:
                    break
                try:
                    data, addr = sock.recvfrom(RECV_BUFSIZE)
                except socket.timeout:
                    continue
                except InterruptedError:
                    continue
                except OSError as exc:
                    if exc.errno in (errno.ENETDOWN, errno.ENODEV, errno.ENXIO):
                        log.warning("Interface %s went away (%s); stopping capture.", iface, exc)
                        break
                    raise
                kind, direction = self._frame_meta(addr)
                self.process_frame(data, kind, direction, time.time())
                if count and self.frames_seen >= count:
                    break
        finally:
            sock.close()

    def _frame_meta(self, addr) -> tuple[str, str | None]:
        """Per-frame link kind and direction from the sockaddr_ll tuple."""
        kind = self.link_kind
        direction = None
        try:
            pkttype, hatype = addr[2], addr[3]
        except (IndexError, TypeError):
            return kind, None
        if kind == LINK_UNKNOWN:
            kind = netif.link_kind_from_type(hatype)
            if kind == LINK_UNKNOWN:
                kind = LINK_RAW  # parse_frame sniffs the IP version nibble
        if pkttype == PACKET_OUTGOING:
            direction = "out"
        elif pkttype in (0, 1, 2):
            direction = "in"
        return kind, direction

    def _sniff_tcpdump(self, iface: str, count: int, timeout: float | None) -> None:
        """Run ``tcpdump -w -`` and feed its pcap stream into process_frame()."""
        exe = find_tcpdump()
        if not exe:
            raise CaptureError(
                "tcpdump not found. Install it (Termux: pkg install tcpdump; Debian/Ubuntu: "
                "apt install tcpdump) or use --backend afpacket."
            )
        cmd = [exe, "-i", iface, "-n", "-U", "-s", "0", "-w", "-"]
        if self.bpf:
            cmd.append(self.bpf)
        self._py_filter = None
        self.filter_mode = "tcpdump" if self.bpf else "none"
        self.local_ips = netif.local_addresses(iface)
        log.info("Running: %s", " ".join(cmd))

        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        except PermissionError as exc:
            raise CapturePermissionError(_permission_message(iface, exc)) from exc
        except OSError as exc:
            raise CaptureError(f"Cannot start tcpdump ({exc}).") from exc

        stderr_lines: deque = deque(maxlen=40)

        def drain_stderr():
            try:
                for raw in iter(proc.stderr.readline, b""):
                    stderr_lines.append(raw.decode("utf-8", "replace").rstrip())
            except (OSError, ValueError):
                pass

        err_thread = threading.Thread(target=drain_stderr, name="wit-tcpdump-stderr", daemon=True)
        err_thread.start()

        parser = PcapStreamParser()
        deadline = time.monotonic() + timeout if timeout else None
        hit_eof = False
        try:
            fd = proc.stdout.fileno()
            while not self._stop.is_set():
                if deadline is not None and time.monotonic() >= deadline:
                    break
                ready, _, _ = select.select([fd], [], [], 0.5)
                if not ready:
                    continue
                chunk = os.read(fd, 65536)
                if not chunk:
                    hit_eof = True
                    break
                try:
                    frames = parser.feed(chunk)
                except PcapStreamError as exc:
                    raise CaptureError(f"tcpdump produced an unreadable pcap stream: {exc}") from exc
                for fr in frames:
                    self.process_frame(fr.data, fr.kind, fr.direction, fr.ts)
                    if count and self.frames_seen >= count:
                        break
                if count and self.frames_seen >= count:
                    break
        finally:
            self._terminate_process(proc)
            err_thread.join(timeout=1)  # let it drain stderr before the pipes are closed
            self._close_streams(proc)

        if parser.leftover:
            log.warning("tcpdump stream ended mid-packet (%d bytes discarded).", parser.leftover)
        if hit_eof and not self._stop.is_set() and not self.frames_seen:
            message = "\n".join(stderr_lines).strip()
            if _PERMISSION_RE.search(message):
                raise CapturePermissionError(_permission_message(iface, RuntimeError(message)))
            code = proc.returncode
            if code not in (0, None) or message:
                raise CaptureError(
                    f"tcpdump exited early (code {code}): {message or 'no output'}"
                )

    @staticmethod
    def _terminate_process(proc) -> None:
        """terminate -> wait -> kill. Safe to call repeatedly."""
        try:
            if proc.poll() is None:
                proc.terminate()
        except OSError:
            pass
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
                proc.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                pass

    @staticmethod
    def _close_streams(proc) -> None:
        for stream in (proc.stdout, proc.stderr):
            try:
                stream.close()
            except (OSError, ValueError, AttributeError):
                pass

    def _sniff_scapy(self, iface: str, count: int, timeout: float | None) -> None:
        """Scapy sniff(): Windows/macOS, or explicit ``--backend scapy`` (best effort on Android).

        Imported lazily and only here, so Android/Linux never load Scapy implicitly (on
        Android Scapy prints "does not support android" and cannot resolve interfaces).
        """
        android = is_android_platform()
        if android:
            log.warning("Scapy does not support Android; this backend is best effort. "
                        "Prefer --backend afpacket or --backend tcpdump.")
            for name in ("scapy", "scapy.runtime", "scapy.loading", "scapy.interactive"):
                logging.getLogger(name).setLevel(logging.CRITICAL + 10)
        try:
            from scapy.all import Ether, conf, sniff
        except Exception as exc:
            hint = " Use --backend afpacket or --backend tcpdump." if android else ""
            raise CaptureError(
                f"Scapy backend unavailable ({exc}). Install scapy (and Npcap on Windows).{hint}"
            ) from exc
        if is_linux() or android:
            try:
                conf.use_pcap = False
            except Exception:
                pass

        def handle(pkt):
            kind = LINK_ETHERNET if Ether in pkt else LINK_RAW
            self.process_frame(bytes(pkt), kind, None, float(getattr(pkt, "time", time.time())))
            if count and self.frames_seen >= count:
                self._stop.set()

        def run(bpf):
            # iface is passed as a plain name; no get_if_list()/resolve_iface() on our side.
            sniff(iface=iface, filter=bpf or None, prn=handle, count=0, timeout=timeout,
                  store=0, stop_filter=lambda _p: self._stop.is_set())

        self._py_filter = None
        try:
            run(self.bpf)
            self.filter_mode = "kernel" if self.bpf else "none"
        except PermissionError as exc:
            raise CapturePermissionError(_permission_message(iface, exc)) from exc
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            if android:
                raise CaptureError(
                    f"Scapy cannot capture on Android ({exc}). Use --backend afpacket "
                    "(native sockets) or --backend tcpdump (pkg install tcpdump)."
                ) from exc
            if not self.bpf or self.frames_seen:
                raise CaptureError(f"Capture failed: {exc}") from exc
            log.warning("BPF filter rejected by libpcap/tcpdump (%s). Falling back to "
                        "Python-side filtering.", exc)
            self._py_filter = build_fallback_filter(self.bpf)
            self.filter_mode = "python" if self._py_filter else "none"
            run("")

    # -- output -------------------------------------------------------------
    def save_packets(self) -> None:
        """Flush and close the PCAP (frames are streamed to disk while capturing)."""
        if self._pcap is None:
            log.info("No packets captured; nothing to save.")
            return
        count = self._pcap.count
        linktype = self._pcap.linktype
        self._pcap.close()
        self._pcap = None
        log.info("Saved %d packets to %s (linktype %d)", count, self.log_file, linktype)
