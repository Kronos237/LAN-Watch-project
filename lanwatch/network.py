"""Interface discovery and IPv4 network configuration."""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
import platform
import subprocess


@dataclass(frozen=True)
class NetworkConfig:
    name: str
    address: ipaddress.IPv4Address
    prefix: int
    gateway: str | None = None
    dns_servers: tuple[str, ...] = ()
    description: str = ""
    scapy_interface: object | None = None

    @property
    def interface(self):
        return ipaddress.ip_interface(f"{self.address}/{self.prefix}")

    @property
    def network(self):
        return self.interface.network

    @property
    def subnet_mask(self):
        return str(self.network.netmask)

    def as_dict(self):
        return {"name": self.name, "address": str(self.address), "prefix": self.prefix,
                "mask": self.subnet_mask, "network": str(self.network),
                "broadcast": str(self.network.broadcast_address), "gateway": self.gateway,
                "dns_servers": list(self.dns_servers), "description": self.description}


class InterfaceSelectionError(RuntimeError):
    pass


def windows_adapters(runner=subprocess.run):
    """Return adapter and IPv4 configuration from structured PowerShell JSON."""
    script = ("$ErrorActionPreference='Stop'; Get-NetAdapter | ForEach-Object { $a=$_; "
              "Get-NetIPConfiguration -InterfaceIndex $a.ifIndex -ErrorAction SilentlyContinue | "
              "ForEach-Object { [PSCustomObject]@{Name=$a.Name;Alias=$a.InterfaceAlias; "
              "Description=$a.InterfaceDescription;Status=$a.Status;InterfaceType=$a.NdisPhysicalMedium; "
              "IPv4=$_.IPv4Address.IPAddress;Prefix=$_.IPv4Address.PrefixLength; "
              "Gateway=$_.IPv4DefaultGateway.NextHop;DNS=$_.DNSServer.ServerAddresses} } } | ConvertTo-Json -Depth 5 -Compress")
    result = runner(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                    capture_output=True, text=True, check=True, timeout=15)
    raw = json.loads(result.stdout or "[]")
    return raw if isinstance(raw, list) else [raw]


def _usable(row):
    ip = row.get("IPv4")
    try:
        parsed = ipaddress.ip_address(ip)
        prefix = int(row.get("Prefix"))
        if parsed.version != 4 or parsed.is_loopback or parsed.is_link_local or not 0 <= prefix <= 32:
            return False
        row["_ip"] = parsed
        row["_prefix"] = prefix
        return True
    except (ValueError, TypeError):
        return False


def discover_networks(*, interface=None, adapters=None, system=None, scapy_conf=None):
    """Choose an operational physical Wi-Fi interface, or honor a name override."""
    system = system or platform.system()
    if adapters is None:
        if system != "Windows":
            raise InterfaceSelectionError(f"Automatic interface discovery is not implemented for {system}.")
        try:
            adapters = windows_adapters()
        except (OSError, subprocess.SubprocessError, ValueError, json.JSONDecodeError) as exc:
            raise InterfaceSelectionError(f"Could not read Windows adapter configuration: {exc}") from exc
    rows = []
    for item in adapters:
        row = dict(item)
        if _usable(row):
            rows.append(row)
    if interface:
        candidates = [r for r in rows if interface.casefold() in
                      (str(r.get("Name", "")).casefold(), str(r.get("Alias", "")).casefold(),
                       str(r.get("Description", "")).casefold())]
        if not candidates:
            raise InterfaceSelectionError(f"No usable IPv4 configuration for interface {interface!r}.")
    else:
        def is_wifi_adapter(row):
            metadata = " ".join(str(row.get(key, "")) for key in ("Description", "Name", "Alias")).casefold()
            # A friendly alias such as "WiFi" must not override contradictory
            # hardware metadata that identifies a virtual, VPN, or wired adapter.
            excluded = ("virtual", "vbox", "vmware", "hyper-v", "vpn", "ethernet")
            return (str(row.get("Status", "")).casefold() == "up"
                    and not any(marker in metadata for marker in excluded)
                    and any(token in metadata for token in ("wi-fi", "wifi", "wireless", "802.11")))

        candidates = [r for r in rows if is_wifi_adapter(r)]
        if not candidates:
            raise InterfaceSelectionError("No active Wi-Fi IPv4 interface found. Use --interface to select an adapter explicitly.")
    if len(candidates) > 1:
        names = ", ".join(str(r.get("Alias") or r.get("Name")) for r in candidates)
        raise InterfaceSelectionError(f"Multiple Wi-Fi interfaces are candidates ({names}); select one with --interface.")
    row = candidates[0]
    scapy_iface = None
    if scapy_conf is not None:
        scapy_ifaces = list(scapy_conf.ifaces.values())
        matches = [i for i in scapy_ifaces if getattr(i, "ip", None) == str(row["_ip"])]
        if not matches:
            raise InterfaceSelectionError(f"Scapy has no interface for {row['_ip']}; check Npcap/interface permissions.")
        scapy_iface = matches[0]
    dns = row.get("DNS") or []
    if isinstance(dns, str):
        dns = [dns]
    return NetworkConfig(str(row.get("Alias") or row.get("Name") or "unknown"), row["_ip"], row["_prefix"],
                         row.get("Gateway") or None, tuple(str(x) for x in dns if x),
                         str(row.get("Description") or ""), scapy_iface)


def select_network(*, interface=None, scapy_conf=None):
    if scapy_conf is None:
        try:
            import scapy.all as scapy
            scapy_conf = scapy.conf
        except ImportError:
            scapy_conf = None
    return discover_networks(interface=interface, scapy_conf=scapy_conf)

