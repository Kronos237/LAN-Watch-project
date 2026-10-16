#!/usr/bin/env python3

"""
LAN Watch: Advanced Network Scanner
Version 3.0
Scans for Wi-Fi (ARP) and Bluetooth (BLE) devices.
Tries to find the Wi-Fi device Hostname using a Reverse DNS Lookup.
"""

# We need these libraries for the script to work
import sys
import subprocess
import re
import ipaddress
import ctypes
import asyncio  # Required for the Bluetooth scan
import socket   # For Reverse DNS (Hostname) Lookup
import platform # To check for OS

# We use 'scapy' for our Wi-Fi ARP scan
try:
    import scapy.all as scp
except ImportError:
    print("Error: Scapy library not found. Please run: pip install scapy")
    sys.exit(1)

# We use 'bleak' for our Bluetooth scan
try:
    import bleak
except ImportError:
    print("Error: Bleak library not found. Please run: pip install bleak")
    sys.exit(1)

# --- 1. Administrator Check ---

def is_admin():
    """
    Checks if the script is running with administrator privileges.
    This is required for ARP scanning and (on some OS) Bluetooth scanning.
    """
    try:
        if platform.system() == "Windows":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            # On Linux/macOS, check for root (UID 0)
            import os
            return os.geteuid() == 0
    except Exception as e:
        print(f"[!] Could not check admin status: {e}")
        return False

# --- 2. Wi-Fi Scan Functions ---

def get_local_network_range_windows():
    """
    Finds the active network range by running 'ipconfig' and parsing it.
    This is the most reliable method for Windows.
    """
    try:
        # Run ipconfig and capture the output
        output = subprocess.run(["ipconfig"], capture_output=True, text=True, check=True).stdout
        
        # Use regex to find all IPv4 and Subnet Mask lines
        matches = re.finditer(
            r"IPv4 Address[.\s]+:\s*(?P<ip>\d+\.\d+\.\d+\.\d+)\s+"
            r"Subnet Mask[.\s]+:\s*(?P<mask>\d+\.\d+\.\d+\.\d+)",
            output
        )
        
        for match in matches:
            ip_str = match.group('ip')
            mask_str = match.group('mask')
            
            # We found an active adapter, calculate its network
            if ip_str and mask_str and not ip_str.startswith("169.254"):
                # Use ipaddress library to calculate the network range in CIDR notation
                ip_interface = ipaddress.ip_interface(f"{ip_str}/{mask_str}")
                network_range = str(ip_interface.network)
                return network_range
                
        # If no match was found
        raise RuntimeError("Could not find an active IPv4 adapter (non-169.254) in 'ipconfig' output.")
        
    except Exception as e:
        print(f"Error parsing ipconfig: {e}")
        return None

def scan_wifi_network(ip_range):
    """
    Performs the ARP scan on the given IP range using Scapy.
    """
    print(f"[*] Starting Wi-Fi Scan (ARP) on {ip_range}...")
    try:
        # 1. Build the ARP request packet
        arp_request = scp.ARP(pdst=ip_range)
        
        # 2. Build the Ethernet broadcast frame
        broadcast_frame = scp.Ether(dst="ff:ff:ff:ff:ff:ff")
        
        # 3. Combine them
        arp_request_broadcast = broadcast_frame / arp_request
        
        # 4. Send and receive (srp) packets, with a 2-second timeout
        answered_list = scp.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
        
        clients_list = []
        for element in answered_list:
            # element[1] is the response packet
            client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
            clients_list.append(client_dict)
            
        print(f"[*] Wi-Fi scan complete. Found {len(clients_list)} devices.")
        return clients_list
        
    except Exception as e:
        print(f"\n[!] An error occurred during the Wi-Fi scan: {e}")
        print("[!] Please ensure Npcap is installed (on Windows) and the script is run as Administrator.")
        return []

def get_device_hostname(ip_address, results_dict):
    """
    Tries to find the hostname of a device using a reverse DNS lookup.
    This function is designed to be run in a separate thread.
    """
    try:
        # This is the core lookup. It asks the network for the name.
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        results_dict[ip_address] = hostname
    except socket.herror:
        # 'Host not found' or other error
        results_dict[ip_address] = "N/A"
    except Exception:
        results_dict[ip_address] = "Error"


def enrich_wifi_devices_with_hostname(clients_list):
    """
    Goes through the list of Wi-Fi devices and tries to find their hostname.
    
    This is complex because socket.gethostbyaddr can be VERY slow if a
    device doesn't respond. We can't do this one-by-one.
    
    We will use a simple (non-async) approach for this script.
    A true high-performance scanner would use an async DNS resolver.
    """
    if not clients_list:
        return []
        
    print("[*] Starting Hostname Lookup (Reverse DNS)...")
    
    # We will use this to store results
    hostname_results = {}
    
    # We set a *global* timeout for all socket operations
    # If a lookup takes longer than 0.5 sec, it will fail
    # This is CRITICAL to make the scan fast.
    socket.setdefaulttimeout(0.5)

    print(f"[+] Looking up hostname 1 of {len(clients_list)}...", end="\r")
    
    # Loop over all clients and try to get their hostname
    for i, client in enumerate(clients_list):
        print(f"[+] Looking up hostname {i+1} of {len(clients_list)}...", end="\r")
        try:
            hostname, _, _ = socket.gethostbyaddr(client['ip'])
            client['name'] = hostname
        except socket.herror:
            client['name'] = "N/A" # Hostname not found
        except Exception:
            client['name'] = "N/A" # Other error (e.g., timeout)

    print("\n[*] Hostname lookup complete.")
    return clients_list


# --- 3. Bluetooth Scan Function ---

async def scan_bluetooth_devices():
    """
    Uses the 'bleak' library to scan for nearby Bluetooth LE devices.
    'async' means this function runs asynchronously.
    """
    print("[*] Starting Bluetooth Scan (5 seconds)...")
    devices_list = []
    try:
        # Discover devices for 5 seconds
        discovered_devices = await bleak.BleakScanner.discover(timeout=5.0)
        
        for d in discovered_devices:
            # We only care about devices that have a name
            if d.name and d.name != "Unknown":
                devices_list.append({
                    "name": d.name,
                    "mac": d.address
                })
                
        print(f"[*] Bluetooth scan complete. Found {len(devices_list)} named devices.")
        
    except bleak.exc.BleakError as e:
        print(f"\n[!] An error occurred during the Bluetooth scan: {e}")
        print("[!] Please ensure your computer's Bluetooth is turned ON.")
    
    return devices_list

# --- 4. Display Functions ---

def display_wifi_results(clients_list):
    """
    Prints a "neat table" of all discovered Wi-Fi devices.
    (Updated to show Hostname)
    """
    # Define column content widths
    idx_width = 5
    ip_width = 18
    mac_width = 17
    name_width = 28 # This column is now Hostname
    
    # Box-drawing characters
    h, v = "═", "║"
    tl, tr, bl, br = "╔", "╗", "╚", "╝"
    tc, bc, lc, rc, c = "╦", "╩", "╠", "╣", "╬"
    
    # --- Create the table structure ---
    top_border = f"{tl}{h*(idx_width+2)}{tc}{h*(ip_width+2)}{tc}{h*(mac_width+2)}{tc}{h*(name_width+2)}{tr}"
    title = f" LAN Watch: Wi-Fi Network ({len(clients_list)} Devices) "
    total_inner_width = len(top_border) - 2
    title_row = f"{v}{title:^{total_inner_width}}{v}"
    header_sep = f"{lc}{h*(idx_width+2)}{c}{h*(ip_width+2)}{c}{h*(mac_width+2)}{c}{h*(name_width+2)}{rc}"
    
    header_idx = f" {'#':^{idx_width}} "
    header_ip = f" {'IP Address':^{ip_width}} "
    header_mac = f" {'MAC Address':^{mac_width}} "
    header_name = f" {'Device Name (Hostname)':^{name_width}} " # Updated Header
    header_row = f"{v}{header_idx}{v}{header_ip}{v}{header_mac}{v}{header_name}{v}"
    
    bottom_border = f"{bl}{h*(idx_width+2)}{bc}{h*(ip_width+2)}{bc}{h*(mac_width+2)}{bc}{h*(name_width+2)}{br}"

    # --- Print the table ---
    print("\n" + top_border)
    print(title_row)
    print(header_sep)
    print(header_row)
    print(header_sep)

    if not clients_list:
        no_devices_msg = "No devices found on the network."
        print(f"{v}{no_devices_msg:^{total_inner_width}}{v}")
    else:
        # Sort the list by IP address
        try:
            sorted_clients = sorted(clients_list, key=lambda x: ipaddress.ip_address(x['ip']))
        except ValueError:
            sorted_clients = clients_list # Fallback if IP is invalid

        for i, client in enumerate(sorted_clients):
            # Truncate long names to fit the column
            name = (client.get('name', "N/A"))[:name_width] # Use .get() for safety
            
            # Left-align content
            idx_str = f" {i+1:<{idx_width}} "
            ip_str = f" {client['ip']:<{ip_width}} "
            mac_str = f" {client['mac']:<{mac_width}} "
            name_str = f" {name:<{name_width}} "
            
            print(f"{v}{idx_str}{v}{ip_str}{v}{mac_str}{v}{name_str}{v}")
            
    print(bottom_border)

def display_bluetooth_results(clients_list):
    """
    Prints a "neat table" of all discovered Bluetooth devices.
    """
    # Define column content widths
    idx_width = 5
    name_width = 28
    mac_width = 17
    
    # Box-drawing characters
    h, v = "═", "║"
    tl, tr, bl, br = "╔", "╗", "╚", "╝"
    tc, bc, lc, rc, c = "╦", "╩", "╠", "╣", "╬"
    
    # --- Create the table structure ---
    top_border = f"{tl}{h*(idx_width+2)}{tc}{h*(name_width+2)}{tc}{h*(mac_width+2)}{tr}"
    title = f" LAN Watch: Bluetooth ({len(clients_list)} Devices) "
    total_inner_width = len(top_border) - 2
    title_row = f"{v}{title:^{total_inner_width}}{v}"
    header_sep = f"{lc}{h*(idx_width+2)}{c}{h*(name_width+2)}{c}{h*(mac_width+2)}{rc}"
    
    header_idx = f" {'#':^{idx_width}} "
    header_name = f" {'Device Name':^{name_width}} "
    header_mac = f" {'MAC Address':^{mac_width}} "
    header_row = f"{v}{header_idx}{v}{header_name}{v}{header_mac}{v}"
    
    bottom_border = f"{bl}{h*(idx_width+2)}{bc}{h*(name_width+2)}{bc}{h*(mac_width+2)}{br}"

    # --- Print the table ---
    print("\n" + top_border)
    print(title_row)
    print(header_sep)
    print(header_row)
    print(header_sep)

    if not clients_list:
        no_devices_msg = "No devices found."
        print(f"{v}{no_devices_msg:^{total_inner_width}}{v}")
    else:
        # Sort the list by name
        sorted_clients = sorted(clients_list, key=lambda x: x['name'])

        for i, client in enumerate(sorted_clients):
            # Truncate long names to fit the column
            name = (client['name'] or "N/A")[:name_width]
            
            # Left-align content
            idx_str = f" {i+1:<{idx_width}} "
            name_str = f" {name:<{name_width}} "
            mac_str = f" {client['mac']:<{mac_width}} "
            
            print(f"{v}{idx_str}{v}{name_str}{v}{mac_str}{v}")
            
    print(bottom_border)


# --- 5. Main Function ---

async def main():
    """
    The main function that runs our entire script.
    """
    # --- Step 1: Admin Check ---
    if not is_admin():
        print("[ERROR] This script requires administrator/root privileges to run.")
        print("[INFO] Please close this window and re-launch as Administrator.")
        sys.exit(1)
    else:
        print("[+] Administrator check passed.")
        
    # --- Step 2: Find Wi-Fi Network ---
    print("[+] Attempting to find network range automatically...")
    
    if platform.system() == "Windows":
        target_range = get_local_network_range_windows()
    else:
        print("[!] Automatic range finding for Linux/macOS not implemented in this script.")
        target_range = None # You could hard-code "192.168.1.0/24" here for testing
    
    if not target_range:
        print("[-] Could not automatically determine network range.")
        sys.exit(1)
    
    print(f"[+] Automatically detected network range: {target_range}")
    
    # --- Step 3: Run Wi-Fi Scan ---
    wifi_devices = scan_wifi_network(target_range)
    
    # --- Step 4: Enrich Wi-Fi Data (NEW: Hostname Lookup) ---
    enriched_wifi_devices = enrich_wifi_devices_with_hostname(wifi_devices)
    
    # --- Step 5: Run Bluetooth Scan ---
    # This is an async function, so we 'await' it
    bluetooth_devices = await scan_bluetooth_devices()
    
    # --- Step 6: Display All Results ---
    display_wifi_results(enriched_wifi_devices)
    display_bluetooth_results(bluetooth_devices)
    
    print("\n[+] Full scan complete.")
    input("\nPress Enter to close the scanner...")

if __name__ == "__main__":
    # This is how we run our 'async' main function
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user. Exiting.")
        sys.exit(0)