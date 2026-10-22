#!/usr/bin/env python3
"""Streamlit presentation layer for shared LAN Watch services."""
import asyncio
import json
import streamlit as st
import pandas as pd

from lanwatch.network import InterfaceSelectionError, select_network
from lanwatch.scanner import arp_scan, scan_ssids
from lanwatch.ble import scan_ble
from lanwatch.diagnostics import dns_lookup, measure_connectivity, ping, traceroute
from lanwatch.health import WEIGHTS, health_score
from lanwatch.monitoring import begin_monitor_scan, finish_monitor_scan, record_monitor_error, record_monitor_result, start_monitoring, stop_monitoring
from lanwatch.storage import HistoryStore
from lanwatch.topology import build_topology, topology_to_dot
from lanwatch.time_formatting import format_timestamp, format_timestamp_record

st.set_page_config(page_title="LAN Watch", page_icon="📡", layout="wide")
st.title("LAN Watch")
st.caption("LAN ARP discovery, nearby SSID discovery, and BLE advertisements are separate observations.")

page=st.sidebar.radio("Navigate", ["Overview", "Devices", "Network topology", "Diagnostics", "Monitoring", "Bluetooth", "History and exports", "Network configuration and health"])
if "scan_result" not in st.session_state: st.session_state.scan_result=None
if "ble_result" not in st.session_state: st.session_state.ble_result=[]

try:
    import scapy.all as scapy
    config=select_network(interface=st.sidebar.text_input("Interface override (optional)") or None, scapy_conf=scapy.conf)
except (ImportError, InterfaceSelectionError) as exc:
    scapy=None; config=None
    st.error(f"Network configuration unavailable: {exc}")

if config:
    st.sidebar.markdown(f"**Selected interface:** {config.name}  \n**Address:** {config.address}/{config.prefix}  \n**Network:** {config.network}  \n**Gateway:** {config.gateway or 'unavailable'}")
    if st.sidebar.button("Scan LAN", type="primary", disabled=scapy is None):
        with st.spinner(f"Scanning {config.network} through {config.name}…"):
            st.session_state.scan_result=arp_scan(config,scapy=scapy)
    if st.sidebar.button("Scan BLE"):
        with st.spinner("Listening for BLE advertisements…"):
            st.session_state.ble_result,error=asyncio.run(scan_ble())
        if error: st.warning(f"BLE unavailable: {error}")

result=st.session_state.scan_result
if result and result.status == "error": st.error(f"Last scan failed: {result.error}")
elif result and config and result.network.get("network") != str(config.network): st.warning("Showing stale results from a previous network configuration.")

if page == "Overview":
    st.subheader("Current network scan")
    if result and result.status == "success":
        a,b,c=st.columns(3); a.metric("Observed devices",len(result.devices)); b.metric("Network",result.network["network"]); c.metric("Last completed (IST)",format_timestamp(result.finished_at))
        st.info("Devices absent from an ARP scan may be asleep, filtered, or isolated; absence does not prove they are offline.")
    else: st.info("Run a LAN scan from the sidebar. A successful empty scan is distinct from a failed scan.")
    if st.button("Discover nearby Wi-Fi SSIDs"):
        names,error=scan_ssids(); st.session_state.ssids=names
        if error: st.warning(error)
    if st.session_state.get("ssids") is not None: st.write("Nearby SSIDs",st.session_state.ssids or "No SSIDs observed")
elif page == "Devices":
    st.subheader("LAN device observations")
    if result and result.status == "success" and result.devices:
        devices=[format_timestamp_record(d,("first_observed","last_observed")) for d in result.devices]
        frame=pd.DataFrame(devices); term=st.text_input("Filter IP, MAC, hostname, or vendor")
        if term: frame=frame[frame.astype(str).apply(lambda col: col.str.contains(term,case=False,na=False)).any(axis=1)]
        st.dataframe(frame,width="stretch",hide_index=True)
    elif not result: st.info("No scan results yet.")
    elif result.status == "success": st.info("The scan succeeded and observed no responding devices.")
elif page == "Network topology":
    st.subheader("Observed LAN topology")
    if result and result.status == "success":
        graph=build_topology(result.network,result.devices)
        st.graphviz_chart(topology_to_dot(graph),width="stretch")
        st.caption(graph["semantics"])
        st.markdown("**Legend:** green = local interface address; gold = configured gateway; gray = ARP-observed device; blue = selected subnet.")
        if result.devices:
            st.dataframe(pd.DataFrame([format_timestamp_record(d,("first_observed","last_observed")) for d in result.devices]),width="stretch",hide_index=True)
        else:
            st.info("The scan succeeded with no ARP responses; the graph shows configured local and gateway information only.")
    elif result and result.status == "error": st.info("No graph is rendered because the most recent scan failed.")
    else: st.info("Run a successful LAN scan to display observed nodes.")
elif page == "Diagnostics":
    host=st.text_input("Destination IP or hostname",value=config.gateway if config and config.gateway else "")
    x,y,z=st.columns(3)
    if x.button("Ping",disabled=not host): st.json(ping(host))
    if y.button("Traceroute",disabled=not host): st.json(traceroute(host))
    if z.button("DNS lookup",disabled=not host): st.json(dns_lookup(host))
    st.caption("ICMP probes may be blocked. A failed ping does not establish that a host is offline.")
elif page == "Monitoring":
    st.subheader("Continuous monitoring")
    interval=st.number_input("Interval in seconds",min_value=60,max_value=3600,value=int(st.session_state.get("monitor_interval",60)),step=30,key="monitor_interval_input")
    start_col,stop_col=st.columns(2)
    if start_col.button("Start monitoring",disabled=not config or st.session_state.get("monitor_active",False)):
        try:
            start_monitoring(st.session_state,int(interval))
        except ValueError as exc:
            st.error(str(exc))
    if stop_col.button("Stop monitoring",disabled=not st.session_state.get("monitor_active",False)):
        stop_monitoring(st.session_state)
    if st.session_state.get("monitor_active") and config:
        st.success(f"Monitoring active. Sequential scans run every {st.session_state['monitor_interval']} seconds while this page is open.")

        @st.fragment(run_every=int(st.session_state["monitor_interval"]))
        def monitoring_tick():
            if not begin_monitor_scan(st.session_state):
                return
            try:
                sample=arp_scan(config,scapy=scapy,enrich=False,timeout=3)
                events=record_monitor_result(st.session_state,sample,HistoryStore())
                if sample.status=="success":
                    st.write(f"Most recent successful sample: {format_timestamp(sample.finished_at)} · {len(sample.devices)} devices observed")
                    if events:
                        display_events=[format_timestamp_record(event,("time",)) for event in events]
                        st.dataframe(pd.DataFrame(display_events),width="stretch",hide_index=True)
                    else:
                        st.caption("No observation changes in this scan.")
                else:
                    st.error(f"Monitoring scan failed: {sample.error or 'unknown error'}")
            except Exception as exc:
                record_monitor_error(st.session_state,exc,getattr(locals().get("sample"),"finished_at",None))
                st.error(f"Monitoring error: {exc}")
            finally:
                finish_monitor_scan(st.session_state)
            if st.session_state.get("monitor_last_success"):
                st.caption(f"Last successful scan (IST): {format_timestamp(st.session_state['monitor_last_success'])}")
            if st.session_state.get("monitor_last_error"):
                error_time=st.session_state.get("monitor_last_error_at")
                time_label=f" at {format_timestamp(error_time)}" if error_time else ""
                st.error(f"Most recent error{time_label}: {st.session_state['monitor_last_error']}")

        monitoring_tick()
    elif not config:
        st.info("Select a usable Wi-Fi interface before starting monitoring.")
    else:
        st.info("Monitoring is stopped.")
        if st.session_state.get("monitor_last_success"):
            st.write(f"Last successful scan (IST): {format_timestamp(st.session_state['monitor_last_success'])}")
        if st.session_state.get("monitor_last_error"):
            error_time=st.session_state.get("monitor_last_error_at")
            time_label=f" at {format_timestamp(error_time)}" if error_time else ""
            st.error(f"Most recent error{time_label}: {st.session_state['monitor_last_error']}")
    st.caption("The fragment reruns sequentially and uses a minimum 60-second interval; it creates no background thread. Stop takes effect after any bounded in-flight ARP scan returns. Devices missing from one scan are only marked ‘not observed in this scan.’ Monitoring pauses if you navigate away from this page.")
elif page == "Bluetooth":
    st.subheader("BLE advertisements")
    if st.session_state.ble_result:
        ble_rows=[format_timestamp_record(item,("observed_at",)) for item in st.session_state.ble_result]
        st.dataframe(pd.DataFrame(ble_rows),width="stretch",hide_index=True)
    else: st.info("No BLE observations in this session. BLE identifiers may be randomized and are not permanent identities.")
elif page == "History and exports":
    st.subheader("Local scan history")
    store=HistoryStore()
    if st.button("Load history"):
        st.session_state.history=store.scans()
    if "history" in st.session_state:
        rows=st.session_state.history
        history_rows=[{"ID":r[0],"Started (IST)":format_timestamp(r[1]),"Finished (IST)":format_timestamp(r[2]),"Status":r[3],"Network":r[4],"Error":r[5]} for r in rows]
        st.dataframe(pd.DataFrame(history_rows),width="stretch",hide_index=True)
        if rows:
            ids=[r[0] for r in rows]
            if len(ids)>1:
                left,right=st.columns(2)
                first=left.selectbox("Compare earlier scan",ids,key="compare_first")
                second=right.selectbox("Compare later scan",ids,key="compare_second")
                if first != second: st.json(store.compare(first,second))
            sid=st.selectbox("Export scan ID",[r[0] for r in rows]); fmt=st.selectbox("Format",["json","csv"])
            fields=["ip","mac","hostname","vendor","observed","source","local","gateway"]
            records=[dict(zip(fields,row)) for row in store.observations(sid)]
            display_records=[format_timestamp_record(record,("observed",)) for record in records]
            st.caption("Preview timestamps are shown in IST. Downloaded CSV/JSON retains UTC ISO timestamps.")
            st.dataframe(pd.DataFrame(display_records),width="stretch",hide_index=True)
            st.download_button("Download export",data=(json.dumps(records,indent=2) if fmt=="json" else pd.DataFrame(records).to_csv(index=False)),file_name=f"lan-watch-{sid}.{fmt}",mime="application/json" if fmt=="json" else "text/csv")
        events=store.events()
        if events:
            st.subheader("Monitoring events")
            event_rows=[{"Time (IST)":format_timestamp(row[0]),"Event":row[1],"IP":row[2],"MAC":row[3],"Detail":row[4]} for row in events]
            st.dataframe(pd.DataFrame(event_rows),width="stretch",hide_index=True)
    else: st.info("History initializes local SQLite storage only when requested.")
elif page == "Network configuration and health":
    st.subheader("Subnet configuration")
    if config:
        st.json(config.as_dict())
        net=config.network
        st.write({"first_usable":str(net.network_address+1) if net.num_addresses>2 else None,"last_usable":str(net.broadcast_address-1) if net.num_addresses>2 else None,"total_addresses":net.num_addresses,"usable_hosts":max(0,net.num_addresses-2)})
        st.caption("Configuration describes the selected adapter. It does not prove that the network or its devices are reachable.")
    st.subheader("Connectivity health")
    probe_count=st.number_input("ICMP probe count",min_value=1,max_value=5,value=4)
    probe_timeout=st.number_input("Per-probe timeout (seconds)",min_value=0.2,max_value=5.0,value=1.0,step=0.2)
    if st.button("Measure connectivity",disabled=not config):
        with st.spinner("Running bounded gateway and DNS probes…"):
            st.session_state.health_measurements=measure_connectivity(config.gateway,probe_count=int(probe_count),timeout=float(probe_timeout))
    measurements=st.session_state.get("health_measurements")
    if measurements:
        gw=measurements["gateway_reachability"]["value"]
        latency=measurements["latency"]["value_ms"]
        loss=measurements["packet_loss"]["value_pct"]
        dnsok=measurements["dns"]["responsive"]
        score=health_score(gateway_reachable=gw,latency_ms=latency,packet_loss_pct=loss,dns_responsive=dnsok)
        inputs={"gateway":(gw,measurements["gateway_reachability"]["status"]),
                "latency_ms":(latency,measurements["latency"]["status"]),
                "packet_loss_pct":(loss,measurements["packet_loss"]["status"]),
                "dns_responsive":(dnsok,measurements["dns"]["status"])}
        cols=st.columns(4)
        labels=[("gateway","Gateway"),("latency_ms","Latency"),("packet_loss_pct","Packet loss"),("dns_responsive","DNS")]
        for col,(key,label) in zip(cols,labels):
            value,status=inputs[key]
            weight_key={"latency_ms":"latency","packet_loss_pct":"packet_loss","dns_responsive":"dns"}.get(key,key)
            display=(f"{value:.1f} ms" if key=="latency_ms" and value is not None else
                     f"{value:.1f}%" if key=="packet_loss_pct" and value is not None else
                     str(value) if value is not None else "Unavailable")
            col.metric(label,display,help=f"Weight: {WEIGHTS[weight_key]:.0%}; status: {status}")
        measurement_rows=[]
        for key,label in labels:
            value,status=inputs[key]
            weight_key={"latency_ms":"latency","packet_loss_pct":"packet_loss","dns_responsive":"dns"}.get(key,key)
            measurement_rows.append({"measurement":label,"value":value,"status":status,
                                    "weight":WEIGHTS[weight_key],
                                    "score contribution":score.get("contributions",{}).get(weight_key)})
        st.dataframe(pd.DataFrame(measurement_rows),width="stretch",hide_index=True)
        st.write("Health score",score["score"] if score["score"] is not None else "Insufficient measurements")
        st.write("Score calculation",score)
        st.write("Measurement details",measurements)
        missing=[key for key,(value,_) in inputs.items() if value is None]
        st.write("Unavailable inputs",missing or "None")
    else:
        st.info("Click Measure connectivity to run at most five gateway pings and one DNS lookup. Reruns do not repeat probes.")
    with st.expander("Inspect score calculation with sample measurements"):
        st.json(health_score(gateway_reachable=True,latency_ms=25,packet_loss_pct=0,dns_responsive=True))
    st.caption("ICMP may be filtered; packet loss is estimated from the bounded probe batch. DNS uses one nslookup. Unsupported tools, timeouts, and failed answers remain distinct. This is a connectivity indicator, not a security score.")
