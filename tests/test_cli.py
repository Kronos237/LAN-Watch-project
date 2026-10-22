import sys
import types
from types import SimpleNamespace

import pytest

import lan_watch_scanner as cli
from lanwatch.scanner import ScanResult


def install_fake_scapy(monkeypatch):
    scapy_package=types.ModuleType("scapy")
    scapy_module=types.ModuleType("scapy.all")
    scapy_module.conf=object()
    scapy_package.all=scapy_module
    monkeypatch.setitem(sys.modules,"scapy",scapy_package)
    monkeypatch.setitem(sys.modules,"scapy.all",scapy_module)
    return scapy_module


def config():
    return SimpleNamespace(name="WiFi",address="172.16.16.159",prefix=21,
                           network="172.16.16.0/21",gateway="172.16.16.1")


def result(status="success",error=None):
    return ScanResult(status,"start","finish",{"network":"172.16.16.0/21"},[],error)


def setup_cli(monkeypatch, scan_result):
    scapy=install_fake_scapy(monkeypatch)
    monkeypatch.setattr(cli,"select_network",lambda **kwargs: config())
    monkeypatch.setattr(cli,"arp_scan",lambda *args,**kwargs: scan_result)
    class Store:
        def __init__(self,*args): pass
        def save(self,*args): pass
        def record_events(self,*args): pass
    monkeypatch.setattr(cli,"HistoryStore",Store)
    return scapy


def test_one_shot_completes_with_summary_and_zero_status(monkeypatch,capsys):
    setup_cli(monkeypatch,result())
    assert cli.main([])==0
    output=capsys.readouterr().out
    assert "Scan complete: status=success" in output
    assert "172.16.16.0/21" in output


def test_one_shot_scan_failure_is_reported_and_nonzero(monkeypatch,capsys):
    setup_cli(monkeypatch,result("error","Npcap unavailable"))
    assert cli.main([])==1
    captured=capsys.readouterr()
    assert "Scan failed: Npcap unavailable" in captured.err
    assert "Scan complete: status=error" in captured.out


def test_monitor_interruption_exits_cleanly(monkeypatch,capsys):
    setup_cli(monkeypatch,result())
    monkeypatch.setattr(cli.time,"sleep",lambda _: (_ for _ in ()).throw(KeyboardInterrupt()))
    assert cli.main(["--monitor","--interval","60"])==0
    assert "Monitoring stopped by user." in capsys.readouterr().out


def test_unexpected_scan_exception_is_visible(monkeypatch,capsys):
    setup_cli(monkeypatch,result())
    monkeypatch.setattr(cli,"arp_scan",lambda *args,**kwargs: (_ for _ in ()).throw(RuntimeError("driver failed")))
    assert cli.main([])==1
    assert "Scan failed: driver failed" in capsys.readouterr().err


def test_version_is_available_without_network(monkeypatch,capsys):
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["--version"])
    assert exit_info.value.code==0
    assert "LAN Watch 1.0" in capsys.readouterr().out
