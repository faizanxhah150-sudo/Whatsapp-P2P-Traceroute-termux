"""Packet filtering: kernel BPF when possible, Python-side fallback otherwise.

Scapy (and libpcap) compile BPF expressions by shelling out to ``tcpdump``,
which is frequently missing or broken on Android. We therefore:

1. try ``tcpdump -ddd`` to get kernel bytecode and attach it with
   SO_ATTACH_FILTER;
2. if that fails for ANY reason, parse the expression ourselves (common
   subset: tcp/udp/icmp/ip/ip6/port/host/net, and/or/not, parentheses) and
   filter in Python; unsupported expressions disable filtering with a warning.

Nothing here ever raises into the capture loop.
"""
from __future__ import annotations

import ctypes
import ipaddress
import logging
import re
import shutil
import socket
import struct
import subprocess
from typing import Callable

from core.packet_parser import PacketInfo

log = logging.getLogger("wit")

BPF_MAX_INSNS = 4096
SO_ATTACH_FILTER = getattr(socket, "SO_ATTACH_FILTER", 26)

Instruction = tuple[int, int, int, int]  # code, jt, jf, k


class FilterError(ValueError):
    """Raised for expressions the Python-side matcher does not support."""


# --- Kernel BPF ------------------------------------------------------------
def parse_ddd(text: str) -> tuple[list[Instruction] | None, str]:
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if not lines:
        return None, "empty tcpdump output"
    try:
        count = int(lines[0])
        insns = []
        for ln in lines[1:]:
            code, jt, jf, k = (int(x) for x in ln.split())
            insns.append((code, jt, jf, k))
    except ValueError:
        return None, "unparseable tcpdump -ddd output"
    if count <= 0 or count != len(insns) or count > BPF_MAX_INSNS:
        return None, "unexpected instruction count from tcpdump"
    return insns, ""


def compile_kernel_filter(expr: str, iface: str, runner=subprocess.run, which=shutil.which,
                          timeout: float = 5.0) -> tuple[list[Instruction] | None, str]:
    """Compile ``expr`` with ``tcpdump -ddd``. Returns ``(insns|None, reason)``."""
    exe = which("tcpdump")
    if not exe:
        return None, "tcpdump not found (Termux: pkg install tcpdump)"
    try:
        cp = runner([exe, "-i", iface, "-ddd", expr], capture_output=True, text=True,
                    timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        return None, f"tcpdump failed: {exc}"
    if cp.returncode != 0:
        detail = (cp.stderr or "").strip().splitlines()
        return None, "tcpdump error: " + (detail[-1] if detail else f"exit {cp.returncode}")
    return parse_ddd(cp.stdout)


def attach_kernel_filter(sock, insns: list[Instruction]) -> None:
    """Attach classic BPF to a packet socket. Raises OSError on failure."""
    raw = b"".join(struct.pack("=HBBI", *i) for i in insns)
    buf = ctypes.create_string_buffer(raw, len(raw))  # keep alive during the call
    fprog = struct.pack("@HP", len(insns), ctypes.addressof(buf))
    sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, fprog)


# --- Python-side filter ----------------------------------------------------
Predicate = Callable[[PacketInfo], bool]

_TOKEN_RE = re.compile(r"\(|\)|&&|\|\||!|[^\s()!&|]+")
_PROTOS = {"tcp", "udp", "icmp", "icmp6"}


class _Parser:
    def __init__(self, expr: str):
        self.tokens = [t.lower() for t in _TOKEN_RE.findall(expr)]
        self.pos = 0

    def _peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _next(self) -> str:
        tok = self._peek()
        if tok is None:
            raise FilterError("unexpected end of filter expression")
        self.pos += 1
        return tok

    def parse(self) -> Predicate:
        pred = self._or()
        if self._peek() is not None:
            raise FilterError(f"unexpected token {self._peek()!r}")
        return pred

    def _or(self) -> Predicate:
        left = self._and()
        while self._peek() in ("or", "||"):
            self._next()
            right = self._and()
            left = (lambda a, b: lambda i: a(i) or b(i))(left, right)
        return left

    def _and(self) -> Predicate:
        left = self._not()
        while self._peek() not in (None, "or", "||", ")"):
            if self._peek() in ("and", "&&"):
                self._next()
            right = self._not()  # implicit AND, e.g. "udp port 3478"
            left = (lambda a, b: lambda i: a(i) and b(i))(left, right)
        return left

    def _not(self) -> Predicate:
        if self._peek() in ("not", "!"):
            self._next()
            inner = self._not()
            return lambda i: not inner(i)
        return self._primary()

    def _primary(self) -> Predicate:
        tok = self._next()
        if tok == "(":
            inner = self._or()
            if self._next() != ")":
                raise FilterError("missing closing parenthesis")
            return inner
        if tok in _PROTOS:
            return lambda i, p=tok: i.proto == p
        if tok == "ip":
            return lambda i: i.version == 4
        if tok == "ip6":
            return lambda i: i.version == 6
        direction = ""
        if tok in ("src", "dst"):
            direction, tok = tok, self._next()
        if tok == "port":
            port = self._int(self._next())
            return self._port(direction, port)
        if tok == "host":
            addr = self._addr(self._next())
            return self._host(direction, lambda ip, a=addr: ip == a)
        if tok == "net":
            net = self._net(self._next())
            return self._host(direction, lambda ip, n=net: ip in n)
        raise FilterError(f"unsupported filter token {tok!r}")

    @staticmethod
    def _int(tok: str) -> int:
        try:
            return int(tok)
        except ValueError as exc:
            raise FilterError(f"expected a number, got {tok!r}") from exc

    @staticmethod
    def _addr(tok: str):
        try:
            return ipaddress.ip_address(tok)
        except ValueError as exc:
            raise FilterError(f"hostnames are not supported in fallback filter: {tok!r}") from exc

    @staticmethod
    def _net(tok: str):
        try:
            return ipaddress.ip_network(tok, strict=False)
        except ValueError as exc:
            raise FilterError(f"bad network {tok!r}") from exc

    @staticmethod
    def _port(direction: str, port: int) -> Predicate:
        def pred(i: PacketInfo) -> bool:
            if i.proto not in ("tcp", "udp"):
                return False
            if direction == "src":
                return i.sport == port
            if direction == "dst":
                return i.dport == port
            return port in (i.sport, i.dport)
        return pred

    @staticmethod
    def _host(direction: str, match) -> Predicate:
        def parse(ip: str):
            try:
                return ipaddress.ip_address(ip)
            except ValueError:
                return None

        def pred(i: PacketInfo) -> bool:
            src, dst = parse(i.src), parse(i.dst)
            try:
                if direction == "src":
                    return src is not None and match(src)
                if direction == "dst":
                    return dst is not None and match(dst)
                return (src is not None and match(src)) or (dst is not None and match(dst))
            except TypeError:  # IPv4 vs IPv6 comparison
                return False
        return pred


def compile_python_filter(expr: str) -> Predicate | None:
    """Return a predicate for ``expr`` (None for an empty expression).

    Raises FilterError when the expression uses unsupported syntax.
    """
    if not expr or not expr.strip():
        return None
    return _Parser(expr).parse()


def build_fallback_filter(expr: str) -> Predicate | None:
    """Like compile_python_filter but never raises; warns and returns None."""
    try:
        return compile_python_filter(expr)
    except FilterError as exc:
        log.warning(
            "BPF fallback: cannot evaluate %r in Python (%s); capturing without a "
            "capture-side filter (only TCP/UDP flows are analysed anyway).", expr, exc,
        )
        return None
