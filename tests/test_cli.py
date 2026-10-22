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


def test_ble_table_formats_observations_and_ist_timestamp(capsys):
    observation={"name":"Temperature Sensor","identifier":"AA:BB:CC:DD:EE:FF",
                 "rssi":-58,"service_uuids":["0000180F-0000-1000-8000-00805F9B34FB"],
                 "observed_at":"2026-10-22T14:54:51Z"}
    cli.print_ble_results([observation])
    output=capsys.readouterr().out
    assert "=== BLE discovery ===" in output
    assert "BLE scan complete: 1 observation(s) found." in output
    assert "Name" in output and "Identifier" in output
    assert "RSSI (dBm)" in output and "Advertised service UUIDs" in output
    assert "Observation time (IST)" in output
    assert "Temperature Sensor" in output and "-58" in output
    assert "22 Oct 2026, 08:24:51 PM IST" in output


def test_ble_table_uses_unknown_and_none_for_missing_fields(capsys):
    cli.print_ble_results([{"name":None,"identifier":"BLE-ID","rssi":None,
                            "service_uuids":[],"observed_at":None}])
    output=capsys.readouterr().out
    assert "Unknown" in output
    assert "BLE-ID" in output
    assert "None" in output
    assert "Unavailable" in output


def test_ble_table_truncates_long_values_only_for_display(capsys):
    identifier="identifier-"+"x"*80
    services=["service-"+"y"*80]
    observation={"name":"n","identifier":identifier,"rssi":-44,
                 "service_uuids":services,"observed_at":"2026-10-22T14:54:51+00:00"}
    cli.print_ble_results([observation])
    output=capsys.readouterr().out
    assert "..." in output
    assert identifier not in output
    assert services[0] not in output
    assert observation["identifier"] == identifier
    assert observation["service_uuids"] == services


def test_ble_empty_success_is_distinct_from_failure(capsys):
    cli.print_ble_results([])
    empty_output=capsys.readouterr().out
    assert "BLE scan complete: 0 observation(s) found." in empty_output
    assert "No BLE observations found." in empty_output
    assert "BLE scan failed" not in empty_output

    cli.print_ble_results([],"Bluetooth adapter unavailable")
    failed_output=capsys.readouterr().out
    assert "BLE scan failed: Bluetooth adapter unavailable" in failed_output
    assert "found: unavailable (scan failed)" in failed_output


def test_ble_scan_failure_does_not_abort_successful_lan_scan(monkeypatch,capsys):
    setup_cli(monkeypatch,result())
    async def failed_scan():
        return [],"adapter unavailable"
    monkeypatch.setattr(cli,"scan_ble",lambda: failed_scan())
    assert cli.main(["--ble"])==0
    output=capsys.readouterr().out
    assert "Scan complete: status=success" in output
    assert "BLE scan failed: adapter unavailable" in output


def test_optional_discovery_sections_are_separately_headed(monkeypatch,capsys):
    setup_cli(monkeypatch,result())
    monkeypatch.setattr(cli,"scan_ssids",lambda: (["Example WiFi"],None))
    async def successful_ble_scan():
        return ([{"name":"BLE tag","identifier":"ble-1","rssi":-50,
                  "service_uuids":[],"observed_at":"2026-10-22T14:54:51Z"}],None)
    monkeypatch.setattr(cli,"scan_ble",successful_ble_scan)
    assert cli.main(["--ssids","--ble"])==0
    output=capsys.readouterr().out
    assert output.index("=== Nearby SSIDs ===") < output.index("=== LAN scan ===")
    assert output.index("=== LAN scan ===") < output.index("=== BLE discovery ===")
    assert "Example WiFi" in output and "BLE tag" in output


def test_ble_json_output_option_is_preserved(capsys):
    observations=[{"name":None,"identifier":"ble-1","rssi":None,
                   "service_uuids":[],"observed_at":"2026-10-22T14:54:51Z"}]
    cli.print_ble_results(observations,json_output=True)
    captured=capsys.readouterr()
    assert "=== BLE discovery ===" in captured.err
    import json
    assert json.loads(captured.out)=={"ble_observations":observations,"error":None}
