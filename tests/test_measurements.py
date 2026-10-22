import subprocess

import pytest

from lanwatch.diagnostics import measure_connectivity


def test_connectivity_measurements_parse_ping_and_dns_with_bounded_commands(monkeypatch):
    calls=[]
    def run(command,**kwargs):
        calls.append((command,kwargs))
        if command[0]=="ping":
            return subprocess.CompletedProcess(command,0,
                "Packets: Sent = 4, Received = 3, Lost = 1 (25% loss)\nMinimum = 2ms, Maximum = 4ms, Average = 3ms\nReply from 172.16.16.1: time=2ms\nReply from 172.16.16.1: time=4ms\n","")
        return subprocess.CompletedProcess(command,0,"Server: 172.16.16.1\nNon-authoritative answer:\nName: example.com\nAddresses: 93.184.216.34\n","")
    monkeypatch.setattr("lanwatch.diagnostics.subprocess.run",run)
    monkeypatch.setattr("lanwatch.diagnostics.platform.system",lambda:"Windows")
    data=measure_connectivity("172.16.16.1",probe_count=4,timeout=0.5)
    assert data["gateway_reachability"]["value"] is True
    assert data["latency"]["value_ms"]==3
    assert data["packet_loss"]["value_pct"]==25
    assert data["dns"]["responsive"] is True
    assert calls[0][1]["timeout"]==5.0
    assert calls[0][0][calls[0][0].index("-w")+1]=="500"
    assert calls[1][1]["timeout"]==0.5


def test_no_gateway_marks_gateway_components_unavailable_but_measures_dns(monkeypatch):
    monkeypatch.setattr("lanwatch.diagnostics.subprocess.run",lambda *a,**k: subprocess.CompletedProcess(a[0],0,"Name: example.com\nAddress: 93.184.216.34\n",""))
    data=measure_connectivity(None)
    assert data["gateway_reachability"]["status"]=="unavailable"
    assert data["latency"]["value_ms"] is None
    assert data["packet_loss"]["value_pct"] is None
    assert data["dns"]["responsive"] is True


def test_missing_probe_tools_are_unavailable_without_crashing(monkeypatch):
    def missing(command,**kwargs): raise FileNotFoundError("tool missing")
    monkeypatch.setattr("lanwatch.diagnostics.subprocess.run",missing)
    data=measure_connectivity("192.0.2.1")
    assert data["gateway_reachability"]["status"]=="unavailable"
    assert data["dns"]["status"]=="unavailable"
    assert data["latency"]["value_ms"] is None


def test_blocked_gateway_and_dns_timeout_are_reported_without_zeroing_unavailable_values(monkeypatch):
    def run(command,**kwargs):
        if command[0]=="ping":
            return subprocess.CompletedProcess(command,1,
                "Packets: Sent = 4, Received = 0, Lost = 4 (100% loss)\n","")
        raise subprocess.TimeoutExpired(command,kwargs["timeout"])
    monkeypatch.setattr("lanwatch.diagnostics.subprocess.run",run)
    monkeypatch.setattr("lanwatch.diagnostics.platform.system",lambda:"Windows")
    data=measure_connectivity("192.0.2.1")
    assert data["gateway_reachability"]["status"]=="no_reply_or_blocked"
    assert data["gateway_reachability"]["value"] is False
    assert data["packet_loss"]["status"]=="measured"
    assert data["packet_loss"]["value_pct"]==100
    assert data["latency"]["value_ms"] is None
    assert data["dns"]["status"]=="timed_out"
    assert data["dns"]["responsive"] is False


def test_probe_limits_are_validated():
    with pytest.raises(ValueError): measure_connectivity("192.0.2.1",probe_count=6)
    with pytest.raises(ValueError): measure_connectivity("192.0.2.1",timeout=0.1)
