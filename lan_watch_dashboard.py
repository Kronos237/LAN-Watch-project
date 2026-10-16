#!/usr/bin/env python3

"""
LAN Watch: Advanced Network Scanner (Streamlit Dashboard)
Version 5.5 (Glassmorphism UI - Final State/Layout Fix)

This script combines all our scanning logic (Wi-Fi, Bluetooth, Hostnames)
into a simple, interactive web dashboard using Streamlit with a custom UI
and session state for a multi-step workflow.
"""

# --- Core Imports ---
import sys
import subprocess
import re
import ipaddress
import ctypes
import asyncio
import socket
import platform
import streamlit as st  # <-- The new UI library
import pandas as pd     # <-- For displaying tables

# --- Scapy/Bleak Imports ---
# (We add a try-except block here for the UI in case modules aren't installed)
try:
    import scapy.all as scp
except ImportError:
    st.error("Scapy library not found. Please run: pip install scapy")
    st.stop()

try:
    import bleak
except ImportError:
    st.error("Bleak library not found. Please run: pip install bleak")
    st.stop()

# --- 1. Administrator Check (Backend Logic) ---

def is_admin():
    """
    Checks if the script is running with administrator privileges.
    """
    try:
        if platform.system() == "Windows":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            import os
            return os.geteuid() == 0
    except Exception:
        return False

# --- 2. Wi-Fi Scan Functions (Backend Logic) ---

@st.cache_data(ttl=600)  # Cache the result for 10 minutes
def get_local_network_range_windows():
    """
    Finds the active network range by running 'ipconfig' and parsing it.
    """
    try:
        output = subprocess.run(["ipconfig"], capture_output=True, text=True, check=True).stdout
        matches = re.finditer(
            r"IPv4 Address[.\s]+:\s*(?P<ip>\d+\.\d+\.\d+\.\d+)\s+"
            r"Subnet Mask[.\s]+:\s*(?P<mask>\d+\.\d+\.\d+\.\d+)",
            output
        )
        for match in matches:
            ip_str = match.group('ip')
            mask_str = match.group('mask')
            if ip_str and mask_str and not ip_str.startswith("169.254"):
                ip_interface = ipaddress.ip_interface(f"{ip_str}/{mask_str}")
                return str(ip_interface.network)
        raise RuntimeError("Could not find an active IPv4 adapter.")
    except Exception as e:
        # We don't want the UI to crash, just show the error in the UI
        st.error(f"Error finding network range: {e}")
        return None

def scan_wifi_network(ip_range):
    """
    Performs the ARP scan on the given IP range using Scapy.
    """
    try:
        arp_request = scp.ARP(pdst=ip_range)
        broadcast_frame = scp.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast_frame / arp_request
        
        answered_list = scp.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
        
        clients_list = []
        for element in answered_list:
            client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
            clients_list.append(client_dict)
        return clients_list
    except Exception as e:
        st.error(f"Wi-Fi Scan Error: {e}")
        return []

def enrich_wifi_devices_with_hostname(clients_list, progress_placeholder):
    """
    Goes through the list of Wi-Fi devices and tries to find their hostname.
    """
    if not clients_list:
        return []
    
    socket.setdefaulttimeout(0.5)
    
    # We use st.progress to show a nice progress bar in the UI
    progress_bar = progress_placeholder.progress(0, text="Looking up hostnames...")
    
    for i, client in enumerate(clients_list):
        try:
            hostname, _, _ = socket.gethostbyaddr(client['ip'])
            client['name'] = hostname
        except (socket.herror, Exception):
            client['name'] = "N/A"
        
        # Update the progress bar
        progress_bar.progress((i + 1) / len(clients_list), text=f"Looking up: {client['ip']}")
    
    # We don't empty the bar, we just let the status box close.
    return clients_list

# --- 3. Bluetooth Scan Function (Backend Logic) ---

async def scan_bluetooth_devices():
    """
    Uses the 'bleak' library to scan for nearby Bluetooth LE devices.
    """
    devices_list = []
    try:
        discovered_devices = await bleak.BleakScanner.discover(timeout=5.0)
        for d in discovered_devices:
            if d.name and d.name != "Unknown":
                devices_list.append({
                    "name": d.name,
                    "mac": d.address
                })
    except bleak.exc.BleakError as e:
        st.error(f"Bluetooth Scan Error: {e}. Please ensure Bluetooth is ON.")
    
    return devices_list

# --- 4. Streamlit UI ---

st.set_page_config(page_title="LAN Watch", page_icon="📡", layout="wide")

# --- CUSTOM CSS FOR "MIRRORGLASS" & "OMBRE" UI ---
page_style = """
<style>
/* Import Poppins font */
@import url('https://fonts.googleapis.com/css2?family=Poppins:wght@400;600;700&display=swap');

/* Main page background ("Ombre") */
[data-testid="stAppViewContainer"] {
    background-image: linear-gradient(to top right, #0a0a2a, #1a0a3a, #0a0a2a);
    font-family: 'Poppins', 'Segoe UI', 'Roboto', sans-serif;
    color: #ffffff;
}

/* Main content area - This is the parent container */
.main .block-container {
    padding-top: 2rem;
    padding-bottom: 2rem;
    padding-left: 2rem;
    padding-right: 2rem;
}

/* --- THIS IS THE KEY FIX --- */
/* This targets the main vertical layout block that Streamlit creates 
   and forces all of its direct children (the title, button, info box, etc.) 
   to be center-aligned. */
[data-testid="stVerticalBlock"] > [data-testid="stVerticalBlock"] > [data-testid="stVerticalBlock"] {
    max-width: 1000px; /* Set a max width for content */
    align-items: center; /* Center all elements */
    margin: auto; /* Center the block itself */
}

/* Make all text content centered by default */
h1, h2, h3, h4, h5, h6, p, label, .stMarkdown, [data-testid="stText"] {
    color: #ffffff !important;
    text-align: center !important;
}

h1 {
    width: 100%; 
    margin: 0 auto 0.5rem auto; 
    font-size: 3.0rem !important; 
    font-weight: 700 !important;
}

h2, h3 {
    width: 100%;
    font-weight: 600 !important;
}

/* Increase subtitle font size */
.stMarkdown p {
    font-size: 1.25rem !important;
    opacity: 0.8;
    max-width: 800px;
    margin: 0 auto 1.5rem auto;
}

/* Glassmorphism ("Mirrorglass") effect for containers */
[data-testid="stStatus"],
[data-testid="stDataFrame"],
[data-testid="stInfo"],
[data-testid="stSuccess"],
[data-testid="stWarning"],
[data-testid="stError"] {
    background: rgba(255, 255, 255, 0.05) !important;
    backdrop-filter: blur(10px) !important;
    -webkit-backdrop-filter: blur(10px) !important;
    border-radius: 15px !important;
    border: 1px solid rgba(255, 255, 255, 0.1) !important;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1) !important;
    color: #ffffff !important;
    
    /* Set width for centered containers */
    width: 100%; /* Make it fill the 1000px max-width parent */
    margin: 1rem auto; /* Center the block containers */
}

/* Make status/info box text white and centered */
[data-testid="stStatus"] p,
[data-testid="stInfo"] p,
[data-testid="stSuccess"] p,
[data-testid="stWarning"] p,
[data-testid="stError"] p {
    color: #ffffff !important;
    text-align: center !important;
    font-size: 1.15rem !important;
    font-family: 'Poppins', sans-serif;
}

/* Style the main button */
[data-testid="stButton"] {
    display: flex; /* Use flex to center the button itself */
    justify-content: center;
    width: 100%;
    margin-top: 1.5rem;
    margin-bottom: 1.5rem;
}

[data-testid="stButton"] button {
    background: linear-gradient(145deg, #5a4fcf, #7b68ee) !important;
    color: white !important;
    border: none !important;
    border-radius: 10px !important;
    padding: 12px 28px !important;
    font-weight: 600 !important;
    font-size: 1.25rem !important; /* Made button font larger */
    font-family: 'Poppins', sans-serif;
    transition: all 0.3s ease !important;
    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2) !important;
    
    /* --- NEW RULES TO MAKE BUTTON WIDE --- */
    width: 100%;
    max-width: 600px; /* Don't let it get *too* wide, but make it wide */
}

[data-testid="stButton"] button:hover {
    box-shadow: 0 6px 20px rgba(0, 0, 0, 0.3) !important;
    transform: translateY(-2px) !important;
    filter: brightness(1.1) !important;
}

/* Style the "Scan Again" (secondary) button */
[data-testid="stButton"] button[kind="secondary"] {
    background: rgba(255, 255, 255, 0.1) !important;
    border: 1px solid rgba(255, 255, 255, 0.2) !important;
    max-width: 250px; /* Make it smaller */
}

[data-testid="stButton"] button[kind="secondary"]:hover {
    background: rgba(255, 255, 255, 0.2) !important;
    border: 1px solid rgba(255, 255, 255, 0.3) !important;
}


/* Style the DataFrames (tables) */
[data-testid="stDataFrame"] .col-header {
    background-color: rgba(90, 79, 207, 0.3) !important;
    color: white !important;
    font-size: 1.1rem; /* Increased table header font */
    font-weight: 600;
    text-align: left; /* Keep table headers left-aligned for readability */
    font-family: 'Poppins', sans-serif;
}

[data-testid="stDataFrame"] .cell-container {
    background-color: transparent !important;
    color: white !important;
    border-bottom: 1px solid rgba(255, 255, 255, 0.1) !important;
    text-align: left; /* Keep table data left-aligned */
    font-family: 'Poppins', sans-serif;
    font-size: 1.05rem;
}

/* Hide the "View fullscreen" button on tables */
[data-testid="stDataFrame"] button[title="View fullscreen"] {
    display: none;
}

</style>
"""
st.markdown(page_style, unsafe_allow_html=True)
# --- END OF CUSTOM CSS ---

# --- Initialize Session State ---
# This manages the app's state (has scan run? what are results?)
if 'scan_run' not in st.session_state:
    st.session_state.scan_run = False
if 'wifi_results' not in st.session_state:
    st.session_state.wifi_results = []
if 'bt_results' not in st.session_state:
    st.session_state.bt_results = []

# --- Main App Title ---
st.title("📡 LAN Watch Dashboard")
st.write("A simple dashboard to scan your Wi-Fi and Bluetooth networks.")


# --- State 1: Before Scan (Button not clicked yet) ---
if not st.session_state.scan_run:
    
    # Show the info bar *first*
    st.info("Click the 'Start Full Network Scan' button to begin.")
    
    # Show the "Start" button *below* the info bar
    if st.button("Start Full Network Scan", type="primary"):
        st.session_state.scan_run = True  # Set the state to "scan has run"
        
        # --- CRITICAL: ADMIN CHECK ---
        if not is_admin():
            st.error("This app must be run as Administrator (or with sudo) to perform scans.")
            st.warning("Please close this window and re-launch your terminal as Administrator.")
            st.session_state.scan_run = False # Reset state
            st.stop() # Stop the script
        
        # --- Run all the scans ---
        with st.spinner("Scanning... Please wait."):
            
            # We need a placeholder for the progress bar inside the status
            wifi_progress_placeholder = st.empty()
            
            with st.status("Scanning Wi-Fi...", expanded=True) as status:
                st.write("Finding network range...")
                target_range = get_local_network_range_windows()
                if not target_range:
                    status.update(label="Wi-Fi Scan Failed", state="error", expanded=True)
                    st.error("Could not find network range.")
                    st.stop()
                
                st.write(f"Found network: {target_range}")
                st.write("Running ARP scan...")
                wifi_devices = scan_wifi_network(target_range)
                st.write(f"Found {len(wifi_devices)} devices.")
                
                # Pass the placeholder to the enrich function
                enriched_wifi = enrich_wifi_devices_with_hostname(wifi_devices, wifi_progress_placeholder)
                
                # Save results to session state
                st.session_state.wifi_results = enriched_wifi
                status.update(label=f"Wi-Fi Scan Complete ({len(enriched_wifi)} devices found)", state="complete", expanded=False)
            
            with st.status("Scanning Bluetooth...", expanded=True) as status:
                st.write("Looking for discoverable Bluetooth devices...")
                bluetooth_devices = asyncio.run(scan_bluetooth_devices())
                
                # Save results to session state
                st.session_state.bt_results = bluetooth_devices
                status.update(label=f"Bluetooth Scan Complete ({len(bluetooth_devices)} devices found)", state="complete", expanded=False)

        # Rerun the script to show results (will now enter the 'if scan_run' block)
        st.rerun()


# --- State 2: After Scan (Button has been clicked) ---
if st.session_state.scan_run:
    st.success("Scan Complete!")

    # --- Display the Results in Tables ---
    st.subheader("Wi-Fi Network Devices")
    if st.session_state.wifi_results:
        wifi_df = pd.DataFrame(st.session_state.wifi_results)
        wifi_df = wifi_df.reindex(columns=['ip', 'mac', 'name'])
        wifi_df.columns = ["IP Address", "MAC Address", "Device Name (Hostname)"]
        st.dataframe(wifi_df, use_container_width=True)
    else:
        st.info("No Wi-Fi devices found.")

    st.subheader("Discoverable Bluetooth Devices")
    if st.session_state.bt_results:
        bt_df = pd.DataFrame(st.session_state.bt_results)
        bt_df = bt_df.reindex(columns=['name', 'mac'])
        bt_df.columns = ["Device Name", "MAC Address"]
        st.dataframe(bt_df, use_container_width=True)
    else:
        st.info("No discoverable Bluetooth devices found.")

    # --- Add a "Scan Again" button ---
    if st.button("Scan Again", type="secondary"):
        # Reset the state and rerun the script
        st.session_state.scan_run = False
        st.session_state.wifi_results = []
        st.session_state.bt_results = []
        st.rerun()