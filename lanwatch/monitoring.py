"""Session-scoped, sequential monitoring helpers for Streamlit and CLI tests."""
from datetime import datetime, timezone


def validate_interval(seconds):
    seconds = int(seconds)
    if seconds < 60:
        raise ValueError("Monitoring interval must be at least 60 seconds.")
    return seconds


def start_monitoring(state, seconds):
    state["monitor_interval"] = validate_interval(seconds)
    state["monitor_active"] = True
    state.setdefault("monitor_previous", {})
    state.setdefault("monitor_seen", set())
    state.setdefault("monitor_last_success", None)
    state.setdefault("monitor_last_error_at", None)
    state.setdefault("monitor_last_error", None)


def stop_monitoring(state):
    state["monitor_active"] = False


def begin_monitor_scan(state):
    """Acquire a state-backed gate; a rerun cannot start a second scan concurrently."""
    if not state.get("monitor_active") or state.get("monitor_scan_in_progress"):
        return False
    state["monitor_scan_in_progress"] = True
    return True


def finish_monitor_scan(state):
    state["monitor_scan_in_progress"] = False


def record_monitor_error(state, error, timestamp=None):
    """Track an error message and its UTC occurrence time for presentation."""
    state["monitor_last_error_at"] = timestamp or datetime.now(timezone.utc).isoformat()
    state["monitor_last_error"] = str(error)


def _identity(device):
    mac = str(device.get("mac") or "").strip().casefold()
    if mac:
        return "mac:" + mac
    ip = str(device.get("ip") or "").strip()
    return "ip:" + ip if ip else None


def record_monitor_result(state, result, store):
    """Persist a scan, then update events only after successful observations."""
    store.save(result)
    if result.status != "success":
        record_monitor_error(state, result.error or "Scan failed without an error message.", result.finished_at)
        return []
    state["monitor_last_success"] = result.finished_at
    state["monitor_last_error_at"] = None
    state["monitor_last_error"] = None
    previous = state.get("monitor_previous", {})
    seen = state.get("monitor_seen", set())
    current = {}
    for device in result.devices:
        identity = _identity(device)
        if identity:
            current[identity] = device
    events = []
    for identity, device in current.items():
        if identity in previous:
            continue
        kind = "returning_observed" if identity in seen else "newly_observed"
        events.append({"time": result.finished_at, "kind": kind, "ip": device.get("ip"),
                       "mac": device.get("mac"), "detail": "Observed in this scan; identifier association is tentative."})
    for identity, device in previous.items():
        if identity not in current:
            events.append({"time": result.finished_at, "kind": "not_observed_in_scan",
                           "ip": device.get("ip"), "mac": device.get("mac"),
                           "detail": "Absent from this scan; this does not prove the device is offline."})
    store.record_events(events)
    state["monitor_previous"] = current
    state["monitor_seen"] = seen | set(current)
    return events
