import csv
import ipaddress
import json

import pytest

from lanwatch.network import InterfaceSelectionError, discover_networks
from lanwatch.scanner import arp_scan, reverse_hostname, ScanResult, local_vendor
from lanwatch.storage import HistoryStore
from lanwatch.health import health_score
from lanwatch.diagnostics import validate_host
from lanwatch.ble import scan_ble
import asyncio


def wifi(alias="WiFi", ip="172.16.16.159", prefix=21, desc="Intel(R) Wi-Fi 6 AX201", status="Up"):
    return {"Name": alias, "Alias": alias, "Description": desc, "Status": status,
            "IPv4": ip, "Prefix": prefix, "Gateway": "172.16.16.1", "DNS": ["1.1.1.1"]}


class Iface:
    def __init__(self, ip, name): self.ip=ip; self.name=name

class Conf:
    def __init__(self, interfaces): self.ifaces={i.name:i for i in interfaces}


def test_virtualbox_first_selects_wifi_and_reference_network_and_scapy_interface():
    virtual={"Name":"VirtualBox Host-Only", "Alias":"VirtualBox Host-Only Network", "Description":"VirtualBox Host-Only Ethernet Adapter", "Status":"Up", "IPv4":"192.168.56.1", "Prefix":24}
    chosen=Iface("172.16.16.159","Wi-Fi Scapy")
    config=discover_networks(adapters=[virtual,wifi()],scapy_conf=Conf([Iface("192.168.56.1","VBox"),chosen]))
    assert config.name == "WiFi"
    assert config.network == ipaddress.ip_network("172.16.16.0/21")
    assert config.scapy_interface is chosen


def test_no_wifi_and_multiple_candidates_are_explicit():
    with pytest.raises(InterfaceSelectionError,match="No active Wi-Fi"):
        discover_networks(adapters=[wifi(desc="VirtualBox Host-Only")])
    with pytest.raises(InterfaceSelectionError,match="Multiple"):
        discover_networks(adapters=[wifi("WiFi"),wifi("WiFi 2")])


def test_explicit_override_and_missing_scapy_interface():
    with pytest.raises(InterfaceSelectionError,match="Scapy has no interface"):
        from lanwatch.network import discover_networks as discover
        # explicit interface configuration is retained even if Scapy mapping isn't requested;
        # actual Scapy mapping errors are surfaced by requiring a conf with no match.
        discover(interface="WiFi",adapters=[wifi()],scapy_conf=Conf([]))


class FakeScapy:
    class Ether:
        def __init__(self,**kwargs): pass
        def __truediv__(self,other): return self
    class ARP:
        def __init__(self,**kwargs): pass
    def __init__(self,answer): self.answer=answer; self.iface=None
    def srp(self,packet,**kwargs): self.iface=kwargs["iface"]; return [self.answer]


class Response:
    psrc="172.16.16.20"; hwsrc="02:11:22:33:44:55"


def test_arp_results_enriched_and_explicit_iface():
    selected=Iface("172.16.16.159","Wi-Fi")
    cfg=discover_networks(adapters=[wifi()],scapy_conf=Conf([selected]))
    fake=FakeScapy([(None,Response())])
    result=arp_scan(cfg,scapy=fake,enrich=False)
    assert result.status=="success" and result.devices[0]["ip"]=="172.16.16.20"
    assert fake.iface is selected
    assert result.devices[0]["hostname"] is None
    assert result.devices[0]["vendor"] is None


def test_vendor_mapping_skips_randomized_local_mac_addresses():
    mapping={"00BBCC":"Example Vendor"}
    assert local_vendor("00:bb:cc:11:22:33",mapping)=="Example Vendor"
    assert local_vendor("02:bb:cc:11:22:33",mapping) is None


def test_missing_hostname_and_scan_error_are_not_empty_success(monkeypatch):
    monkeypatch.setattr("lanwatch.scanner.socket.gethostbyaddr",lambda _: (_ for _ in ()).throw(OSError("no PTR")))
    assert reverse_hostname("192.0.2.2") is None
    cfg=discover_networks(adapters=[wifi()])
    result=arp_scan(cfg,scapy=FakeScapy([]))
    assert result.status=="error"
    class Empty:
        class Ether(FakeScapy.Ether): pass
        class ARP(FakeScapy.ARP): pass
        def srp(self,*a,**k): return [[]]
    cfg=discover_networks(adapters=[wifi()],scapy_conf=Conf([Iface("172.16.16.159","wifi")]))
    assert arp_scan(cfg,scapy=Empty()).status=="success"
    assert arp_scan(cfg,scapy=Empty()).devices==[]


@pytest.mark.parametrize("addr,prefix,network",[("10.0.0.2",8,"10.0.0.0/8"),("172.16.16.159",21,"172.16.16.0/21"),("192.168.1.4",24,"192.168.1.0/24"),("192.0.2.1",31,"192.0.2.0/31"),("192.0.2.1",32,"192.0.2.1/32")])
def test_subnet_calculation(addr,prefix,network):
    row=wifi(ip=addr,prefix=prefix)
    assert discover_networks(adapters=[row]).network==ipaddress.ip_network(network)


def test_storage_lazy_exports_and_comparison(tmp_path):
    path=tmp_path/"nested"/"history.db"; store=HistoryStore(path)
    assert not path.exists()
    def result(ip, mac, started):
        return ScanResult("success",started,started,{"network":"192.168.1.0/24"},[{"ip":ip,"mac":mac,"hostname":None,"vendor":None,"last_observed":started,"source":"arp","is_local":False,"is_gateway":False}])
    one=store.save(result("192.168.1.2","aa:00:00:00:00:01","a")); two=store.save(result("192.168.1.3","aa:00:00:00:00:02","b"))
    assert store.compare(one,two)["new_observations"]==["aa:00:00:00:00:02"]
    j=tmp_path/"export.json"; c=tmp_path/"export.csv"
    store.export(two,"json",j); store.export(two,"csv",c)
    assert json.loads(j.read_text())[0]["ip"]=="192.168.1.3"
    assert next(csv.DictReader(c.open()))["ip"]=="192.168.1.3"


def test_health_score_and_unavailable():
    assert health_score(gateway_reachable=True)["score"] is None
    s=health_score(gateway_reachable=True,latency_ms=0,packet_loss_pct=0,dns_responsive=None)
    assert s["score"]==100
    assert s["contributions"]["dns"] is None
    assert health_score(gateway_reachable=False,latency_ms=500)["score"]==0


def test_diagnostics_validation():
    assert validate_host("example.org")=="example.org"
    with pytest.raises(ValueError): validate_host("bad host")


def test_ble_failure_is_contained(monkeypatch):
    import bleak
    async def fail(**kwargs): raise RuntimeError("adapter unavailable")
    monkeypatch.setattr(bleak.BleakScanner,"discover",fail)
    observations,error=asyncio.run(scan_ble())
    assert observations==[] and "adapter unavailable" in error

