"""LAN discovery and optional enrichment."""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
import socket


@dataclass
class ScanResult:
    status: str
    started_at: str
    finished_at: str
    network: dict
    devices: list[dict] = field(default_factory=list)
    error: str | None = None
    source: str = "arp"


def reverse_hostname(address):
    previous_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(0.5)
        return socket.gethostbyaddr(address)[0]
    except (OSError, socket.herror, socket.gaierror):
        return None
    finally:
        socket.setdefaulttimeout(previous_timeout)


def local_vendor(mac, oui_db=None):
    if not mac or not oui_db:
        return None
    normalized = mac.replace(":", "").replace("-", "").replace(".", "").upper()
    if len(normalized) < 12 or any(ch not in "0123456789ABCDEF" for ch in normalized[:12]):
        return None
    # The U/L bit signals a locally administered address; an OUI prefix is
    # not reliable vendor evidence for randomized/local identifiers.
    if int(normalized[:2], 16) & 2:
        return None
    key = normalized[:6]
    return oui_db.get(key)


def arp_scan(config, *, scapy=None, timeout=3, enrich=True, oui_db=None):
    started = datetime.now(timezone.utc).isoformat()
    try:
        if scapy is None:
            import scapy.all as scapy
        if config.scapy_interface is None:
            raise RuntimeError("No matching Scapy interface is available.")
        answered = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=str(config.network)),
                             iface=config.scapy_interface, timeout=timeout, retry=1, verbose=False)[0]
        devices = []
        for sent, response in answered:
            ip = str(response.psrc); mac = str(response.hwsrc).lower()
            administered = bool(int(mac.split(":")[0], 16) & 2) if len(mac.split(":")) == 6 else None
            devices.append({"ip": ip, "mac": mac, "hostname": reverse_hostname(ip) if enrich else None,
                            "vendor": local_vendor(mac, oui_db), "locally_administered_mac": administered,
                            "is_local": ip == str(config.address), "is_gateway": ip == config.gateway,
                            "first_observed": started, "last_observed": started, "status": "observed", "source": "arp"})
        return ScanResult("success", started, datetime.now(timezone.utc).isoformat(), config.as_dict(), devices)
    except Exception as exc:
        return ScanResult("error", started, datetime.now(timezone.utc).isoformat(), config.as_dict(), error=str(exc))


def scan_ssids(runner=None):
    import platform, re, subprocess
    if platform.system() != "Windows":
        return [], "Nearby SSID discovery is supported on Windows only."
    runner = runner or subprocess.run
    try:
        output = runner(["netsh", "wlan", "show", "networks", "mode=bssid"], capture_output=True,
                        text=True, encoding="utf-8", errors="replace", check=True, timeout=15).stdout
        return list(dict.fromkeys(x.strip() for x in re.findall(r"^\s*SSID\s+\d+\s*:\s*(.*)$", output, re.M) if x.strip())), None
    except (OSError, subprocess.SubprocessError) as exc:
        return [], str(exc)
