#!/usr/bin/env python3
"""LAN Watch lightweight command-line scanner."""
import argparse
import asyncio
import json
import sys
import time

from lanwatch.network import InterfaceSelectionError, select_network
from lanwatch.scanner import arp_scan, scan_ssids
from lanwatch.ble import scan_ble
from lanwatch.storage import HistoryStore
from lanwatch.time_formatting import format_timestamp


def build_parser():
    p=argparse.ArgumentParser(description="Discover devices on the configured local IPv4 LAN.")
    p.add_argument("--version", action="version", version="LAN Watch 1.0")
    p.add_argument("--interface", help="Interface alias/name override (auto-select active Wi-Fi otherwise).")
    p.add_argument("--timeout", type=float, default=3, help="ARP response timeout in seconds (default: 3).")
    p.add_argument("--json", action="store_true", help="Write scan result as JSON.")
    p.add_argument("--ssids", action="store_true", help="Also list nearby Wi-Fi SSIDs (Windows only).")
    p.add_argument("--ble", action="store_true", help="Also perform optional BLE discovery.")
    p.add_argument("--monitor", action="store_true", help="Repeat scans and persist observations until Ctrl+C.")
    p.add_argument("--interval", type=int, default=60, help="Monitoring interval in seconds (minimum 60).")
    p.add_argument("--history", action="store_true", help="Show local scan history without scanning.")
    p.add_argument("--db", help="Optional SQLite history path.")
    return p


def main(argv=None):
    args=build_parser().parse_args(argv)
    store=HistoryStore(args.db)
    if args.history:
        for row in store.scans():
            print(json.dumps({"id":row[0],"started_utc":row[1],"started_ist":format_timestamp(row[1]),"time_zone":"IST",
                              "status":row[3],"network":row[4],"error":row[5]}))
        return 0
    if args.timeout <= 0:
        print("Error: --timeout must be positive.",file=sys.stderr); return 2
    if args.monitor and args.interval < 60:
        print("Error: monitoring interval must be at least 60 seconds.",file=sys.stderr); return 2
    try:
        import scapy.all as scapy
        config=select_network(interface=args.interface,scapy_conf=scapy.conf)
    except (ImportError, InterfaceSelectionError) as exc:
        print(f"Network configuration error: {exc}",file=sys.stderr); return 2
    print(f"Interface: {config.name} ({config.address}/{config.prefix}); network {config.network}; gateway {config.gateway or 'unavailable'}", flush=True)
    if args.ssids:
        ssids,error=scan_ssids(); print("Nearby SSIDs: "+(", ".join(ssids) if ssids else (error or "none observed")))
    try:
        previous_macs=set()
        while True:
            try:
                result=arp_scan(config,scapy=scapy,timeout=args.timeout)
            except Exception as exc:
                print(f"Scan failed: {exc}",file=sys.stderr,flush=True)
                return 1
            if args.monitor:
                store.save(result)
                if result.status == "success":
                    current={d.get("mac") for d in result.devices if d.get("mac")}
                    events=[]
                    for device in result.devices:
                        if device.get("mac") not in previous_macs:
                            events.append({"time":result.finished_at,"kind":"newly_observed","ip":device.get("ip"),"mac":device.get("mac"),"detail":"First observation during this monitoring session."})
                    for mac in previous_macs-current:
                        events.append({"time":result.finished_at,"kind":"not_observed_in_scan","ip":None,"mac":mac,"detail":"Absent from this scan; not proof of offline status."})
                    store.record_events(events)
                    previous_macs=current
                    for event in events: print(f"[{event['kind']}] {event['ip'] or event['mac']}: {event['detail']}")
            if args.json: print(json.dumps(result.__dict__,default=str),flush=True)
            elif result.status == "error": print(f"Scan failed: {result.error}",file=sys.stderr,flush=True)
            else:
                print(f"ARP scan {result.status}: {len(result.devices)} device(s) observed on {config.network}")
                print(f"{'IP':<16} {'MAC':<18} {'HOSTNAME':<32} {'ROLE'}")
                for d in result.devices:
                    role="local" if d["is_local"] else "gateway" if d["is_gateway"] else "device"
                    print(f"{d['ip']:<16} {d['mac']:<18} {(d['hostname'] or 'unavailable'):<32} {role}")
            if not args.monitor:
                print(f"Scan complete: status={result.status}; observed={len(result.devices)}; network={config.network}",flush=True)
                break
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("Monitoring stopped by user.",flush=True)
        return 0
    if args.ble:
        results,error=asyncio.run(scan_ble())
        print(json.dumps({"ble_observations":results,"error":error},ensure_ascii=False))
    return 0 if result.status == "success" else 1


if __name__ == "__main__":
    raise SystemExit(main())
