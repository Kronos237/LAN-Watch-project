import ipaddress
import subprocess

from streamlit.testing.v1 import AppTest

import lanwatch.diagnostics as diagnostics
import lanwatch.network as network
import lanwatch.scanner as scanner
import lanwatch.storage as storage
from lanwatch.network import NetworkConfig
from lanwatch.scanner import ScanResult


class MemoryStore:
    saved=[]
    recorded_events=[]
    def __init__(self,*args): pass
    def save(self,result): self.saved.append(result); return len(self.saved)
    def record_events(self,events): self.recorded_events.extend(events)
    def scans(self): return []
    def events(self): return list(self.recorded_events)
    def compare(self,*args): return {}
    def observations(self,*args): return []


def make_result(devices=(),status="success",error=None):
    config={"name":"WiFi","address":"192.0.2.10","prefix":24,"mask":"255.255.255.0",
            "network":"192.0.2.0/24","broadcast":"192.0.2.255","gateway":"192.0.2.1",
            "dns_servers":[],"description":"test adapter"}
    return ScanResult(status,"start","finish",config,list(devices),error)


def test_dashboard_pages_topology_health_and_monitor_controls(monkeypatch):
    config=NetworkConfig("WiFi",ipaddress.IPv4Address("192.0.2.10"),24,"192.0.2.1",scapy_interface=object())
    monkeypatch.setattr(network,"select_network",lambda **kwargs:config)
    scans=[]
    observations=[make_result([{"ip":"192.0.2.11","mac":"00:11:22:33:44:55","is_local":False,"is_gateway":False}]),
                  make_result(status="error",error="mock monitor failure")]
    def fake_scan(*args,**kwargs):
        scans.append(kwargs)
        return observations[min(len(scans)-1,len(observations)-1)]
    monkeypatch.setattr(scanner,"arp_scan",fake_scan)
    MemoryStore.saved=[]; MemoryStore.recorded_events=[]
    monkeypatch.setattr(storage,"HistoryStore",MemoryStore)

    app=AppTest.from_file("lan_watch_dashboard.py").run(timeout=20)
    assert not app.exception
    for page in ["Devices","Network topology","Diagnostics","Monitoring","Bluetooth",
                 "History and exports","Network configuration and health","Overview"]:
        app.radio[0].set_value(page).run(timeout=20)
        assert not app.exception, f"Dashboard page failed: {page}"

    app.session_state["scan_result"]=make_result()
    app.radio[0].set_value("Network topology").run(timeout=20)
    assert len(app.get("graphviz_chart"))==1
    app.session_state["scan_result"]=make_result([
        {"ip":"192.0.2.11","mac":None,"hostname":None,"vendor":None,"is_local":False,"is_gateway":False},
        {"ip":"192.0.2.11","mac":None,"hostname":"partial.local","vendor":None,"is_local":False,"is_gateway":False},
    ])
    app.run(timeout=20)
    assert len(app.get("graphviz_chart"))==1
    app.session_state["scan_result"]=make_result(status="error",error="mock scan failure")
    app.run(timeout=20)
    assert len(app.get("graphviz_chart"))==0
    assert not app.exception

    app.radio[0].set_value("Monitoring").run(timeout=20)
    next(button for button in app.button if button.label=="Start monitoring").click().run(timeout=20)
    assert app.session_state["monitor_active"] is True
    assert len(scans)==1
    assert scans[0]["enrich"] is False
    assert len(MemoryStore.saved)==1
    assert app.session_state["monitor_last_success"]=="finish"
    assert MemoryStore.recorded_events[0]["kind"]=="newly_observed"
    app.run(timeout=20)
    assert len(scans)==2
    assert app.session_state["monitor_last_success"]=="finish"
    assert app.session_state["monitor_last_error"]=="mock monitor failure"
    next(button for button in app.button if button.label=="Stop monitoring").click().run(timeout=20)
    assert app.session_state["monitor_active"] is False
    assert len(scans)==2
    assert not app.exception

    def missing_tool(command,**kwargs): raise FileNotFoundError("mock tool unavailable")
    monkeypatch.setattr(diagnostics.subprocess,"run",missing_tool)
    app.radio[0].set_value("Network configuration and health").run(timeout=20)
    next(button for button in app.button if button.label=="Measure connectivity").click().run(timeout=20)
    assert app.session_state.health_measurements["gateway_reachability"]["status"]=="unavailable"
    assert app.session_state.health_measurements["dns"]["status"]=="unavailable"
    assert not app.exception
