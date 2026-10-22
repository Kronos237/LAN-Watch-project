"""Safe, bounded connectivity diagnostics."""
from __future__ import annotations
import ipaddress, platform, re, socket, subprocess, time


def validate_host(host):
    host = host.strip()
    if not host or len(host) > 253 or any(c.isspace() for c in host):
        raise ValueError("Enter a valid IP address or hostname.")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if any(not label or len(label) > 63 for label in host.rstrip(".").split(".")):
            raise ValueError("Enter a valid IP address or hostname.")
    return host


def dns_lookup(host):
    host = validate_host(host); started = time.perf_counter()
    try:
        results = sorted({item[4][0] for item in socket.getaddrinfo(host, None)})
        return {"status": "success", "addresses": results, "elapsed_ms": (time.perf_counter()-started)*1000, "error": None}
    except OSError as exc:
        return {"status": "error", "addresses": [], "elapsed_ms": (time.perf_counter()-started)*1000, "error": str(exc)}


def ping(host, count=4, timeout=2):
    host = validate_host(host)
    if not 1 <= count <= 10: raise ValueError("Ping count must be between 1 and 10.")
    if not 0.1 <= timeout <= 10: raise ValueError("Ping timeout must be between 0.1 and 10 seconds.")
    windows = platform.system() == "Windows"
    platform_timeout = str(round(timeout*1000)) if windows else str(timeout)
    cmd = ["ping", "-n" if windows else "-c", str(count), "-w" if windows else "-W", platform_timeout, host]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=count*timeout+3, check=False)
        return {"status": "success" if result.returncode == 0 else "unreachable_or_blocked", "returncode": result.returncode,
                "output": (result.stdout + result.stderr)[-6000:], "command": cmd}
    except FileNotFoundError as exc:
        return {"status": "unavailable", "error": str(exc), "command": cmd}
    except subprocess.TimeoutExpired as exc:
        return {"status": "timed_out", "error": str(exc), "command": cmd}
    except OSError as exc:
        return {"status": "error", "error": str(exc), "command": cmd}


def traceroute(host, max_hops=20):
    host = validate_host(host)
    if not 1 <= max_hops <= 30: raise ValueError("Maximum hops must be between 1 and 30.")
    cmd = (["tracert", "-d", "-h", str(max_hops), "-w", "1000", host] if platform.system() == "Windows"
           else ["traceroute", "-n", "-m", str(max_hops), "-w", "1", host])
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=max_hops+5, check=False)
        return {"status": "success" if result.returncode == 0 else "unreachable_or_blocked", "output": (result.stdout+result.stderr)[-10000:]}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "error", "error": str(exc)}


def _ping_metrics(output, count):
    """Parse common Windows and Unix ping summaries; return only measured values."""
    loss = None
    match = re.search(r"\((\d+(?:\.\d+)?)%\s*loss\)", output, re.I)
    if not match:
        match = re.search(r"(\d+(?:\.\d+)?)%\s*packet\s*loss", output, re.I)
    if match:
        loss = float(match.group(1))
    else:
        sent = re.search(r"Sent\s*=\s*(\d+).*?Received\s*=\s*(\d+)", output, re.I)
        if sent and int(sent.group(1)) > 0:
            loss = 100.0 * (int(sent.group(1))-int(sent.group(2))) / int(sent.group(1))
        else:
            sent = re.search(r"(\d+)\s+packets? transmitted,\s*(\d+)\s+(?:packets? )?received", output, re.I)
            if sent and int(sent.group(1)) > 0:
                loss = 100.0 * (int(sent.group(1))-int(sent.group(2))) / int(sent.group(1))
    latencies = []
    for match in re.finditer(r"time([=<])\s*([\d.]+)\s*ms", output, re.I):
        value = float(match.group(2))
        latencies.append(value / 2 if match.group(1) == "<" else value)
    latency = sum(latencies)/len(latencies) if latencies else None
    # Windows can print time<1ms; 0.5 ms is an explicit midpoint estimate.
    if latency is None and re.search(r"time<\s*1\s*ms", output, re.I):
        latency = 0.5
    return {"latency_ms": latency, "packet_loss_pct": loss}


def _dns_probe(host, timeout):
    started = time.perf_counter()
    command = ["nslookup", host]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
        elapsed = (time.perf_counter()-started)*1000
        output = result.stdout + result.stderr
        # An address in the answer section after a resolved name distinguishes an
        # answer from the resolver's own address in the header.
        answer_section = re.split(r"(?:Non-authoritative answer|Authoritative answers?|Name:)\s*:?", output, flags=re.I)
        answer_text = "\n".join(answer_section[1:]) if len(answer_section) > 1 else ""
        has_address = any(_is_ip_token(token) for token in re.findall(r"(?<![\w:])(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{3,})", answer_text))
        if result.returncode == 0 and has_address:
            return {"status": "measured", "responsive": True, "latency_ms": elapsed, "error": None,
                    "details": f"nslookup completed for {host}"}
        return {"status": "failed", "responsive": False, "latency_ms": None,
                "error": "DNS lookup returned no answer.", "details": output[-2000:]}
    except subprocess.TimeoutExpired:
        return {"status": "timed_out", "responsive": False, "latency_ms": None,
                "error": f"DNS lookup exceeded {timeout:g} seconds.", "details": None}
    except FileNotFoundError as exc:
        return {"status": "unavailable", "responsive": None, "latency_ms": None,
                "error": f"nslookup is unavailable: {exc}", "details": None}
    except OSError as exc:
        return {"status": "error", "responsive": None, "latency_ms": None, "error": str(exc), "details": None}


def _is_ip_token(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def measure_connectivity(gateway, *, probe_count=4, timeout=1.0, dns_name="example.com"):
    """Collect bounded gateway ICMP/loss and DNS measurements; no score is computed here."""
    if not 1 <= probe_count <= 5:
        raise ValueError("Probe count must be between 1 and 5.")
    if not 0.2 <= timeout <= 5:
        raise ValueError("Probe timeout must be between 0.2 and 5 seconds.")
    dns_name = validate_host(dns_name)
    if gateway:
        gateway = validate_host(str(gateway))
        probe = ping(gateway, count=probe_count, timeout=timeout)
        parsed = _ping_metrics(probe.get("output", ""), probe_count)
        if probe["status"] in ("success", "unreachable_or_blocked"):
            reachable = probe["status"] == "success"
            reachability = {"status": "reachable" if reachable else "no_reply_or_blocked", "value": reachable, "error": None,
                            "probe_count": probe_count, "timeout_seconds": timeout}
        elif probe.get("status") == "unavailable":
            reachability = {"status": "unavailable", "value": None, "error": probe.get("error")}
        else:
            reachability = {"status": probe.get("status", "error"), "value": None, "error": probe.get("error")}
        no_measurement_status = probe.get("status") if probe.get("status") in ("unavailable", "timed_out", "error") else "unavailable"
        latency = {"status": "measured" if parsed["latency_ms"] is not None else no_measurement_status,
                   "value_ms": parsed["latency_ms"], "error": None if parsed["latency_ms"] is not None else probe.get("error") or "No latency replies parsed.",
                   "probe_count": probe_count, "timeout_seconds": timeout}
        loss = {"status": "measured" if parsed["packet_loss_pct"] is not None else no_measurement_status,
                "value_pct": parsed["packet_loss_pct"], "error": None if parsed["packet_loss_pct"] is not None else probe.get("error") or "No packet-loss summary parsed.",
                "probe_count": probe_count, "timeout_seconds": timeout}
    else:
        reason = "No default gateway is configured for the selected interface."
        reachability = {"status": "unavailable", "value": None, "error": reason}
        latency = {"status": "unavailable", "value_ms": None, "error": reason}
        loss = {"status": "unavailable", "value_pct": None, "error": reason}
    dns = _dns_probe(dns_name, timeout)
    return {"gateway_reachability": reachability, "latency": latency,
            "packet_loss": loss, "dns": dns,
            "limitations": f"Uses {probe_count} system ping probes (each bounded by {timeout:g}s) and one nslookup bounded by {timeout:g}s. ICMP filtering and resolver policy can affect results."}
