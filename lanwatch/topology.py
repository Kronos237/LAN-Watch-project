"""Build explainable LAN topology nodes and subnet-membership relationships."""
from __future__ import annotations

from collections import OrderedDict


def _get(value, key, default=None):
    return value.get(key, default) if isinstance(value, dict) else getattr(value, key, default)


def build_topology(config, devices):
    """Return a graph whose edges describe observations/configuration, not physical links."""
    address = str(_get(config, "address", "unknown"))
    network = str(_get(config, "network", "unknown"))
    interface = str(_get(config, "name", "interface"))
    gateway_value = _get(config, "gateway")
    gateway = str(gateway_value) if gateway_value else None
    nodes = OrderedDict()
    edges = []
    subnet_id = f"subnet:{network}"
    nodes[subnet_id] = {
        "id": subnet_id,
        "kind": "subnet",
        "label": f"{interface}\n{network}",
        "observed": True,
        "details": f"Configured on {interface}; subnet calculation does not prove reachability.",
    }

    local_id = f"device:{address}"
    nodes[local_id] = {"id": local_id, "kind": "local", "label": f"This machine\n{address}",
                       "ip": address, "mac": None, "hostname": None, "observed": True,
                       "details": "Local IPv4 address from selected interface configuration."}
    edges.append({"source": subnet_id, "target": local_id, "kind": "configured_interface",
                  "label": "interface configuration", "evidence": "configured"})

    if gateway:
        gateway_id = f"device:{gateway}"
        nodes[gateway_id] = {"id": gateway_id, "kind": "gateway", "label": f"Default gateway\n{gateway}",
                             "ip": gateway, "mac": None, "hostname": None, "observed": False,
                             "details": "Gateway configured on this interface; ARP response has not been observed."}
        edges.append({"source": subnet_id, "target": gateway_id, "kind": "configured_gateway",
                      "label": "configured gateway; path unverified", "evidence": "configured"})

    # Deduplicate repeated ARP rows by IP, with MAC as a fallback identity for incomplete data.
    deduplicated = OrderedDict()
    for index, device in enumerate(devices or []):
        ip = str(device.get("ip") or "").strip()
        mac = str(device.get("mac") or "").strip()
        key = ("ip", ip) if ip else (("mac", mac.casefold()) if mac else ("unknown", index))
        current = deduplicated.setdefault(key, {})
        for field, value in device.items():
            if value is not None and value != "":
                current[field] = value

    for key, device in deduplicated.items():
        ip = str(device.get("ip") or "").strip()
        mac = str(device.get("mac") or "").strip()
        is_local = bool(device.get("is_local")) or (ip and ip == address)
        is_gateway = bool(device.get("is_gateway")) or (gateway and ip == gateway)
        kind = "local" if is_local else "gateway" if is_gateway else "device"
        node_id = f"device:{ip}" if ip else f"device:{key[0]}:{key[1]}"
        if not ip and not mac:
            node_id = f"device:unknown:{key[1]}"
        if node_id in nodes:
            node = nodes[node_id]
            was_observed = node.get("observed", False)
            for field in ("ip", "mac", "hostname", "vendor"):
                if device.get(field):
                    node[field] = device[field]
            node["observed"] = True
            node["details"] = "ARP response observed; physical path is not established."
            title = "This machine" if kind == "local" else "Default gateway" if kind == "gateway" else device.get("hostname") or "Observed device"
            node["label"] = "\n".join(part for part in (title, ip, mac) if part)
            if kind == "gateway" and not was_observed:
                node["details"] = "ARP response observed for the configured gateway; physical path is not established."
                for edge in edges:
                    if edge["target"] == node_id and edge["kind"] == "configured_gateway":
                        edge["label"] = "configured gateway; ARP response observed"
                        edge["evidence"] = "configured_and_observed_arp"
            continue
        title = "This machine" if kind == "local" else "Default gateway" if kind == "gateway" else device.get("hostname") or "Observed device"
        label = "\n".join(part for part in (title, ip, mac) if part)
        details = "; ".join(f"{field}: {device[field]}" for field in ("ip", "mac", "hostname", "vendor") if device.get(field))
        missing = [field for field in ("ip", "mac", "hostname", "vendor") if not device.get(field)]
        if missing:
            details = (details + "; " if details else "") + "unavailable: " + ", ".join(missing)
        details = (details + "; " if details else "") + "ARP response observed; physical path is not established."
        nodes[node_id] = {"id": node_id, "kind": kind, "label": label, "ip": ip or None,
                          "mac": mac or None, "hostname": device.get("hostname"),
                          "vendor": device.get("vendor"), "observed": True, "details": details}
        if kind != "local":
            edges.append({"source": subnet_id, "target": node_id, "kind": "arp_subnet_observation",
                          "label": "ARP observed; subnet membership inferred", "evidence": "observed_arp"})

    return {"nodes": list(nodes.values()), "edges": edges,
            "semantics": "ARP responses show devices observed on the selected subnet. Edges do not represent verified physical links or packet paths."}


def topology_to_dot(graph):
    """Render the graph as Graphviz DOT without requiring a Python graph package."""
    def quote(text):
        return str(text).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")

    colors = {"subnet": "#dbeafe", "local": "#bbf7d0", "gateway": "#fde68a", "device": "#e5e7eb"}
    lines = ["graph lan_watch {", "  graph [rankdir=LR, overlap=false, splines=true, bgcolor=\"transparent\"];"]
    for node in graph.get("nodes", []):
        shape = "box" if node["kind"] == "subnet" else "ellipse"
        tooltip = node.get("details", "") + ("; observed" if node.get("observed") else "; configured, not observed")
        lines.append(f'  "{quote(node["id"])}" [label="{quote(node["label"])}", tooltip="{quote(tooltip)}", shape={shape}, style=filled, fillcolor="{colors[node["kind"]]}"];')
    for edge in graph.get("edges", []):
        lines.append(f'  "{quote(edge["source"])}" -- "{quote(edge["target"])}" [label="{quote(edge["label"])}", tooltip="Evidence: {quote(edge["evidence"])}"];')
    lines.append("}")
    return "\n".join(lines)
