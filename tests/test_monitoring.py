import pytest

from lanwatch.monitoring import (begin_monitor_scan, finish_monitor_scan, record_monitor_result,
                                 start_monitoring, stop_monitoring, validate_interval)
from lanwatch.scanner import ScanResult


class Store:
    def __init__(self): self.saved=[]; self.events=[]
    def save(self,result): self.saved.append(result)
    def record_events(self,events): self.events.extend(events)


def scan(status, devices=(), error=None, time="t"):
    return ScanResult(status,time,time,{"network":"10.0.0.0/24"},list(devices),error)


def test_interval_minimum_and_start_stop_controls():
    assert validate_interval(60)==60
    with pytest.raises(ValueError): validate_interval(59)
    state={}; start_monitoring(state,60)
    assert state["monitor_active"] is True
    stop_monitoring(state)
    assert state["monitor_active"] is False
    assert begin_monitor_scan(state) is False


def test_scan_gate_prevents_overlapping_runs():
    state={"monitor_active":True}
    assert begin_monitor_scan(state) is True
    assert begin_monitor_scan(state) is False
    finish_monitor_scan(state)
    assert begin_monitor_scan(state) is True


def test_success_change_events_and_returning_observation():
    state={}; start_monitoring(state,60); store=Store()
    device={"ip":"10.0.0.2","mac":"AA:BB:CC:00:00:02"}
    events=record_monitor_result(state,scan("success",[device],time="one"),store)
    assert [event["kind"] for event in events]==["newly_observed"]
    events=record_monitor_result(state,scan("success",[],time="two"),store)
    assert [event["kind"] for event in events]==["not_observed_in_scan"]
    events=record_monitor_result(state,scan("success",[device],time="three"),store)
    assert [event["kind"] for event in events]==["returning_observed"]
    assert len(store.saved)==3


def test_failure_is_persisted_but_does_not_replace_last_success_or_presence():
    state={}; start_monitoring(state,60); store=Store()
    device={"ip":"10.0.0.2","mac":"aa:bb:cc:00:00:02"}
    record_monitor_result(state,scan("success",[device],time="one"),store)
    events=record_monitor_result(state,scan("error",error="Npcap denied",time="two"),store)
    assert events==[]
    assert state["monitor_last_success"]=="one"
    assert state["monitor_last_error"]=="Npcap denied"
    assert state["monitor_last_error_at"]=="two"
    assert state["monitor_previous"]
