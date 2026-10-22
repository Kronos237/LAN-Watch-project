# LAN Watch

LAN Watch is a small Computer Networks learning project for observing devices on the configured IPv4 LAN, nearby Wi-Fi SSIDs, and Bluetooth Low Energy advertisements. It includes a lightweight CLI and a Streamlit dashboard backed by shared Python services.

## Architecture

- `lanwatch/network.py`: Windows adapter discovery, selection, subnet calculation, and Scapy interface mapping.
- `lanwatch/scanner.py`: ARP discovery, hostname/vendor enrichment hooks, and nearby SSID listing.
- `lanwatch/diagnostics.py`: bounded ping, traceroute, and DNS lookups.
- `lanwatch/ble.py`: optional BLE advertisements, kept separate from IP observations.
- `lanwatch/storage.py`: lazy local SQLite history and CSV/JSON export.
- `lanwatch/health.py`: explainable connectivity score.
- `lanwatch/time_formatting.py`: UTC timestamp parsing and IST presentation formatting.
- `lan_watch_scanner.py` and `lan_watch_dashboard.py`: CLI and Streamlit presentation layers.
- `DECISIONS.md`: architecture decisions, rationale, staged plan, and verification notes.

## Install

Use Python 3.10 or newer. Install the pinned packages with:

```powershell
python -m pip install -r requirements.txt
```

On Windows, install Npcap with its WinPcap-compatible API option for Scapy Ethernet ARP. Windows adapter selection uses PowerShell `Get-NetAdapter` and `Get-NetIPConfiguration`; supported Windows PowerShell networking cmdlets are required. Raw packet access can require an elevated terminal depending on Npcap configuration. The dashboard still opens when a scan cannot run and reports the failure.

## CLI

The no-argument one-shot workflow remains available. It prints a final summary and returns to the shell normally; run it from an existing terminal to keep that terminal open. A double-clicked console may close when the process exits, which is standard console behavior. LAN Watch does not pause unconditionally, so scripts and redirected output work:

```powershell
python .\lan_watch_scanner.py
```

Linux/macOS syntax is shown for invoking Python, but automatic adapter discovery and ARP interface selection are currently implemented for Windows only. On those systems the command reports that limitation rather than guessing an interface. `sudo` is a Unix privilege command, not a PowerShell command:

```bash
python3 lan_watch_scanner.py
```

Choose an adapter explicitly when there are multiple Wi-Fi candidates, emit JSON, or enable optional observations:

```powershell
python .\lan_watch_scanner.py --interface "WiFi"
python .\lan_watch_scanner.py --json
python .\lan_watch_scanner.py --ssids --ble
python .\lan_watch_scanner.py --monitor --interval 60
python .\lan_watch_scanner.py --history
python .\lan_watch_scanner.py --help
python .\lan_watch_scanner.py --version
```

With `--ble` and without `--json`, BLE results are shown in a separate aligned terminal table with name, identifier, RSSI, advertised service UUIDs, and observation time in IST. Missing names display as `Unknown`; empty service lists display as `None`. Long values are shortened only for terminal display. A successful scan with no advertisements is reported as an empty result, separately from a scan error. Use `--json --ble` to retain JSON output for both the LAN scan and BLE observations (printed as separate JSON records); the `--json` option does not change BLE discovery.

Monitoring runs sequential scans until Ctrl+C and saves local history. The default interval is 60 seconds; shorter intervals are rejected. A one-shot scan does not initialize SQLite. Use `--db PATH` to choose a history database location.

Scan timestamps and timestamps in SQLite and CSV/JSON data remain ISO-formatted UTC values. Human-readable timestamps in the dashboard and CLI history output are converted to **IST (Asia/Kolkata)** and labelled `IST`. Naive timestamps left by legacy data are consistently interpreted as UTC. The dashboard export preview uses IST; downloaded files keep UTC timestamps for reliable machine comparisons.

## Dashboard

```powershell
streamlit run lan_watch_dashboard.py
```

Use the sidebar to select an interface override and start LAN or BLE scans. Pages cover overview, devices, topology, diagnostics, monitoring, BLE, local history/exports, and network configuration/health.

## Discovery layers and limitations

- **SSID discovery** lists nearby wireless network names through Windows WLAN (`netsh`). It does not discover devices on those networks.
- **LAN ARP discovery** probes the selected adapter's calculated IPv4 subnet and explicitly binds Scapy to the matching interface. Windows auto-selection looks for active Wi-Fi adapter metadata; when multiple candidates exist, provide `--interface` or the dashboard override. Other operating systems currently report that automatic interface selection is unavailable.
- **BLE discovery** listens for BLE advertisements. BLE identifiers may be randomized and do not imply IP connectivity.

The subnet calculation describes adapter configuration, not reachability. Managed Wi-Fi networks commonly use client isolation, firewalls, sleeping clients, or VLAN separation, so LAN Watch may observe only some devices. A missing hostname/vendor is unavailable enrichment, not a failed device. A device missing from one scan is “not observed in this scan,” not proven offline. Ping may be blocked; traceroute hops may not reply.

The topology graph contains the selected subnet, local interface address, configured gateway, and ARP-observed LAN devices. ARP responses are direct observations; subnet membership edges are inferred from the configured subnet. A configured gateway is not necessarily reachable, and the graph does not claim physical links or verified packet paths between remote devices. Duplicate observations are merged by IP where possible; unavailable metadata appears as such. The device inventory table remains available on the Devices page.

History is stored locally in `~/.lan-watch/history.sqlite3` by default and retains at most 500 scans. It may contain local addresses and observed MACs; do not share exports without reviewing them. CSV/JSON exports are available from dashboard history. Vendor lookup is currently an optional local lookup hook; no OUI database ships with the project.

All user-facing timestamps are displayed in IST (`Asia/Kolkata`). Stored timestamps, scan JSON, and downloaded CSV/JSON exports remain UTC; legacy naive ISO timestamps are interpreted as UTC when formatted.

Select **Measure connectivity** on the Network configuration and health page to run bounded measurements. LAN Watch sends at most four ICMP echo probes by default (adjustable from 1 to 5), with a one-second timeout per probe (adjustable from 0.2 to 5 seconds), to the configured gateway. It invokes one `nslookup example.com` with the same timeout. Missing tools, timeout, failed lookup, and unsupported/missing gateway conditions are displayed separately; unavailable measurements are omitted from the score. The dashboard stores results in session state and does not repeat probes on ordinary reruns.

The rule-based connectivity score uses gateway reachability 40%, latency 25% (0 ms=100, 500 ms or more=0), packet loss 20% (0%=100), and DNS responsiveness 15%. Available weights are renormalized; fewer than two measured inputs yield no score. ICMP filtering, system ping output differences, and resolver behavior affect measurements. This is a connectivity indicator, not a cybersecurity rating.

Dashboard monitoring has explicit Start and Stop controls and a minimum 60-second interval. It runs sequentially in a Streamlit fragment only while the Monitoring page is open, creates no worker thread, and persists scans/events locally. Stop takes effect after an in-flight bounded ARP scan returns. Events describe newly/returning observed identifiers and devices “not observed in this scan”; they do not prove permanent offline status. CLI monitoring continues until Ctrl+C.

Vendor lookup is unavailable unless the caller supplies a local prefix mapping to `arp_scan(..., oui_db={"AABBCC": "Vendor"})`; keys are the first six hexadecimal MAC digits. There is no runtime download and no MAC address is sent to a lookup service. Locally administered/randomized addresses are not reliable vendor evidence. IEEE publishes downloadable MAC registration listings, but this repository does not redistribute that data because its redistribution terms and refresh procedure have not been established. See the [IEEE Registration Authority listings](https://standards.ieee.org/products-programs/regauth/) for source data and registry scope.

## Tests

The offline regression tests use mocked adapter records, Scapy responses, DNS, and BLE behavior; they do not require the campus/hostel network:

```powershell
python -m pip install pytest
python -m pytest -q
```

Live scans should only be run on networks where discovery is authorized. No live network is required for unit tests.
