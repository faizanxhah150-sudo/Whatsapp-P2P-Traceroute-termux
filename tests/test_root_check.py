import os
import sys
import types

import pytest

from utils import platform_utils as pu


def test_is_root_uses_geteuid_on_posix(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    assert pu.is_root() is True
    monkeypatch.setattr(os, "geteuid", lambda: 10234, raising=False)
    assert pu.is_root() is False


def test_is_root_windows_branch_only_touches_windll_on_win32(monkeypatch):
    fake_ctypes = types.SimpleNamespace(
        windll=types.SimpleNamespace(shell32=types.SimpleNamespace(IsUserAnAdmin=lambda: 1))
    )
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setitem(sys.modules, "ctypes", fake_ctypes)
    assert pu.is_root() is True
    fake_ctypes.windll.shell32.IsUserAnAdmin = lambda: 0
    assert pu.is_root() is False


def test_require_root_exits_with_actionable_message(monkeypatch):
    messages = []

    class Rec:
        def error(self, fmt, *args):
            messages.append(fmt % args)

    monkeypatch.setattr(pu, "is_root", lambda: False)
    monkeypatch.setenv("PREFIX", "/data/data/com.termux/files/usr")
    with pytest.raises(SystemExit) as exc:
        pu.require_root(Rec())
    assert exc.value.code == 1
    assert "scripts/run_root.sh" in messages[0] and "su -c id" in messages[0]


def test_require_root_returns_when_root(monkeypatch):
    monkeypatch.setattr(pu, "is_root", lambda: True)
    assert pu.require_root() is None


def test_help_text_is_platform_specific(monkeypatch):
    monkeypatch.delenv("PREFIX", raising=False)
    monkeypatch.delenv("TERMUX_VERSION", raising=False)
    monkeypatch.delenv("ANDROID_ROOT", raising=False)
    monkeypatch.delenv("ANDROID_DATA", raising=False)
    monkeypatch.setattr(sys, "platform", "linux")
    assert "sudo" in pu.root_help_message()
    monkeypatch.setattr(sys, "platform", "win32")
    assert "Administrator" in pu.root_help_message()


def test_termux_detection():
    assert pu.is_termux({"PREFIX": "/data/data/com.termux/files/usr"}) is True
    assert pu.is_termux({"TERMUX_VERSION": "0.118"}) is True
    assert pu.is_termux({"PREFIX": "/usr"}) is False
    assert pu.is_termux({}) is False
    assert pu.is_android({"ANDROID_ROOT": "/system"}) is True
    assert pu.is_android({}) is False
