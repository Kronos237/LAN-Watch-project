# LAN Watch Decisions and Implementation Plan

This file records the decisions made during the repository audit and implementation. Statuses describe the current decision; update an entry if implementation evidence changes it.

## Audit baseline — 2026-10-22

- The repository contains only `lan_watch_scanner.py`, `lan_watch_dashboard.py`, `README.md`, `requirements.txt`, and `.gitignore`; there are no tests, package metadata, or existing `DECISIONS.md`.
- The CLI's Windows fix runs PowerShell `Get-NetIPAddress` for the literal alias `WiFi`, excludes APIPA, converts address/prefix with `ip_interface`, then maps the selected IP to a Scapy interface and passes it to `srp(iface=...)`. This works for one adapter alias but is not configurable or shared.
- The dashboard separately parses localized `ipconfig` output, takes the first non-APIPA address (which can be VirtualBox/VPN), and runs `srp` without an interface. Its subnet and packet route can therefore disagree.
- Both scripts duplicate SSID discovery, hostname lookup, BLE discovery, and ARP presentation/logic. Both stop on missing Scapy/Bleak imports; BLE is not actually optional. Both require administrator/root for the whole workflow. Scan errors are converted to empty lists in places.
- Dependencies are pinned in `requirements.txt`; direct relevant packages include Scapy 2.6.1, Bleak 1.1.1, Streamlit 1.51.0, and pandas 2.3.3. The file also pins a broad environment including unrelated plotting/ML packages. No changes to dependencies are currently justified.
- README claims are broader than implementation: platform-independent automatic detection, vendor roadmap, and no explicit permission/managed Wi-Fi limitations. Text appears mojibake in this environment.
- `git status --short` returned no changes at audit time.

## Decisions

### D-01 — Shared network core, separate interfaces
- **Status:** accepted
- **Context/problem:** CLI and dashboard duplicate networking code and currently select different networks.
- **Decision:** put reusable interface selection, subnet calculation, ARP discovery, enrichment, diagnostics, BLE, history, and monitoring services in importable core modules; keep CLI and Streamlit as presentation/entry-point layers.
- **Rationale:** one behavior path can be tested with mocks and used consistently by both interfaces.
- **Alternatives considered:** keep duplicated scripts; replace the project with a framework/package. The former preserves divergence; the latter is unnecessary for this student project.
- **Consequences and trade-offs:** initial refactor touches both scripts and adds a small core package. Existing no-argument CLI remains supported.
- **Verification:** unit tests for the service and integration tests of both entry points.

### D-02 — Select configured Wi-Fi interface dynamically
- **Status:** accepted
- **Context/problem:** hard-coded alias is machine-specific; selecting the first address can choose VirtualBox/VPN.
- **Decision:** discover Windows adapter/address configuration via structured PowerShell output; rank active Wi-Fi interface(s) using adapter type/status/configuration, exclude unusable/APIPA addresses, surface ambiguity, and permit explicit interface override. Derive network from address/prefix.
- **Rationale:** interface identity must come from adapter configuration, not address ordering or fixed reference values.
- **Alternatives considered:** parse localized `ipconfig`; always choose a named alias; choose the first private address. Each is brittle or wrong in multi-adapter setups.
- **Consequences and trade-offs:** Windows auto-detection is implemented. Other platforms currently report automatic interface discovery as unsupported rather than guess; this is the current behavior and is documented in the README.
- **Verification:** mocked VirtualBox-first, multiple candidates, malformed/missing config, and reference `/21` tests.

### D-03 — Explicit Scapy interface for ARP
- **Status:** accepted
- **Context/problem:** Scapy routing defaults may select a different interface than the configured subnet.
- **Decision:** map selected OS interface to the corresponding Scapy interface and always pass it to `srp`; fail with actionable diagnostic if mapping is unavailable.
- **Rationale:** target range and Ethernet interface must match.
- **Alternatives considered:** rely on Scapy route selection. Rejected because it reproduced the class of bug under audit.
- **Consequences and trade-offs:** Scapy interface naming differs by platform; mapping failures are reported rather than silently falling back.
- **Verification:** mock Scapy interfaces and assert matching interface reaches `srp`.

### D-04 — Enrichment is optional evidence
- **Status:** accepted
- **Context/problem:** reverse DNS and vendor lookup can fail independently of device discovery.
- **Decision:** represent hostname/vendor as unavailable (`None` or explicit unavailable status); never fail a scan because enrichment failed. Keep OUI data local and optional if a suitable source is available.
- **Rationale:** missing enrichment is not evidence that a device or service is absent.
- **Alternatives considered:** label all failures `N/A`/`Error`; require external vendor API. Rejected as ambiguous or privacy/network dependent.
- **Consequences and trade-offs:** tables need honest unavailable labels; an OUI database may have coverage gaps.
- **Verification:** mocked reverse DNS failure and missing vendor record.

### D-05 — Device identity and randomized MACs
- **Status:** accepted
- **Context/problem:** IP addresses and randomized/local MAC addresses are not durable identities.
- **Decision:** store observations with scan/time/source metadata; treat IP/MAC as observed attributes and use cautious association rules, never claim either is a permanent identity. Mark locally administered MACs.
- **Rationale:** address reuse and MAC randomization are common, particularly on Wi-Fi.
- **Alternatives considered:** use IP or MAC as a permanent primary identity. Rejected as misleading.
- **Consequences and trade-offs:** inventory comparisons report tentative new/returning observations and may split/merge identities.
- **Verification:** change-detection tests for consecutive scans and randomized addresses.

### D-06 — Lazy local SQLite history
- **Status:** accepted
- **Context/problem:** basic CLI scan must not need persistence setup.
- **Decision:** initialize SQLite only for history, exports, monitoring persistence, or comparisons; keep data local and provide bounded retention.
- **Rationale:** one-shot workflow stays light and storage is opt-in by feature use.
- **Alternatives considered:** initialize DB on import/startup; external database. Rejected as unnecessary coupling.
- **Consequences and trade-offs:** storage schema and migrations need explicit handling; default path must be documented.
- **Verification:** test that ordinary scan does not create DB and persistence workflows do.

### D-07 — Monitoring pacing and overlap
- **Status:** accepted
- **Context/problem:** Streamlit reruns and short scan loops can duplicate scans or create runaway work.
- **Decision:** use a configurable conservative interval (default at least 60 seconds), sequential scans with overlap prevention, explicit stop control, and separately tracked last success/error. Missing from one scan means “not observed in this scan.”
- **Rationale:** ARP is active probing and monitoring should be bounded and explainable.
- **Alternatives considered:** background daemon or rapid polling. Rejected due lifecycle and network load concerns.
- **Consequences and trade-offs:** Streamlit monitoring uses a sequential fragment while its page is open, with no worker thread; Stop takes effect after the current bounded scan returns. CLI monitoring can run until interrupted.
- **Verification:** mocked clock/scan tests for overlap, event labels, and stop behavior.

### D-08 — Explainable health score
- **Status:** accepted
- **Context/problem:** a composite score can imply unsupported certainty.
- **Decision:** score only when enough measurements exist, with initial contributions: gateway reachability 40%, latency 25%, packet loss 20%, DNS responsiveness 15%; normalize each measured component to 0–100 and renormalize over available components. Show contributions and unavailable inputs. This measures observed connectivity only, not security.
- **Rationale:** weights privilege basic connectivity and remain visible and testable.
- **Alternatives considered:** opaque ML score; treat unavailable as zero. Rejected as unexplainable/misleading.
- **Consequences and trade-offs:** scores vary by probe availability; formula and limitations must be shown in UI/docs.
- **Verification:** component, unavailable-input, and insufficient-data tests.

### D-09 — BLE observations remain separate
- **Status:** accepted
- **Context/problem:** BLE devices do not necessarily have IP connectivity or stable identifiers.
- **Decision:** model BLE advertisements separately, preserving optional name/address/RSSI/services/timestamps and errors without failing LAN scans.
- **Rationale:** different discovery layer and identifier semantics.
- **Alternatives considered:** merge BLE devices into LAN IP inventory. Rejected as false equivalence.
- **Consequences and trade-offs:** separate tables/history/export grouping; platform support depends on Bleak and adapter.
- **Verification:** mocked BLE success/failure and LAN continuation tests.

### D-10 — Mock-first network validation
- **Status:** accepted
- **Context/problem:** live hostel/campus Wi-Fi is variable and may isolate clients.
- **Decision:** unit tests mock OS utilities, Scapy, DNS, and Bleak; optional live integration checks are separate and never required for the suite.
- **Rationale:** deterministic regression coverage without relying on network policy.
- **Alternatives considered:** rely on manual scans on the current LAN. Rejected as non-repeatable.
- **Consequences and trade-offs:** mocks validate our decisions and calls, not network reachability; report live test limitations honestly.
- **Verification:** run the offline suite; document optional manual checks.

## Staged implementation plan

1. **Phase 1 — Core correctness:** shared interface/network service; Windows adapter discovery and explicit Scapy mapping; CLI and dashboard consume it; regression tests for VirtualBox-first, `/21`, ambiguity, no adapter, and Scapy interface selection.
2. **Phase 2 — Data and inventory:** shared models, resilient enrichment, local/gateway marking, subnet analyzer and safe diagnostics; unit tests with mocked network dependencies.
3. **Phase 3 — Persistence and monitoring:** lazy SQLite, retention, comparisons, CSV/JSON, sequential monitor/events and tests.
4. **Phase 4 — Dashboard and topology:** clear navigation, state-safe scan controls, shared service integration, filters, topology and history displays.
5. **Phase 5 — BLE and health:** optional enriched BLE observations and transparent health calculation, tests and UI.
6. **Phase 6 — Verification/docs:** run available tests and static checks, review diff, update README and decisions.

**Risks:** PowerShell cmdlet/localized behavior, Scapy adapter naming/Npcap availability, Streamlit rerun semantics, and the scope of a substantial feature list relative to a two-script baseline. Adapter discovery errors must remain explicit; no live scan is required for tests. No new runtime dependency is planned.

**Acceptance criteria:** both entry points share the same dynamic selection and explicit Scapy interface; `/21` regression passes; scan failure is distinct from empty success; optional BLE/enrichment cannot abort LAN discovery; ordinary CLI scan initializes no database; requested features have offline tests; README and this file match actual behavior.

## Initial implementation report — 2026-10-22 (historical; verification superseded below)

- Implemented the shared `lanwatch` modules and changed both entry points to use them. The Windows selection path recognizes Wi-Fi adapter descriptions/status, calculates the subnet from address/prefix, surfaces multiple candidates, honors a name/alias/description override, and maps Scapy by the selected IPv4 address. The dashboard has no separate subnet or ARP implementation now.
- Added mocked regression tests in `tests/test_core.py` covering VirtualBox-first ordering, the reference `/21`, missing/multiple Wi-Fi candidates, matching Scapy interface, ARP response handling, scan error versus empty success, enrichment absence, multiple subnet sizes, lazy storage, exports/comparison, score behavior, input validation, and BLE failure containment.
- Implemented minimal diagnostics, BLE advertisement fields, lazy SQLite (500-scan retention), JSON/CSV export, connectivity score, and eight dashboard sections. CLI monitor mode serializes scans, defaults to 60 seconds, and stops on Ctrl+C.
- **Initial scope limitations:** interface auto-detection supports Windows only; there is no bundled OUI database; dashboard monitoring was a one-sample action; topology was a grouped node/detail view; health values were manually entered. The next-phase entries below supersede the topology, measurement, and dashboard monitoring limitations. Windows-only selection and no bundled OUI database remain.
- Verification at that point: `python -m compileall -q lanwatch lan_watch_scanner.py lan_watch_dashboard.py tests` passed; `python lan_watch_scanner.py --help` passed; direct offline adapter/subnet and health smoke assertions passed; `git diff --check` passed. Pytest was unavailable in that earlier environment. These results are historical and are superseded by the later completed pytest runs and final integration review below. No live network scan was run.
- Dependency decision remains unchanged: no new runtime dependency added. The tests use pytest and installation is documented as a development step.

## Next implementation phase — 2026-10-22

### D-11 — One-shot CLI completion returns to caller
- **Status:** accepted
- **Context/problem:** users reported that a finished CLI run closes; the code completes one scan, breaks, returns a status, and exits with `SystemExit`. There is no pause, and no evidence in this control flow of a hidden exception. A console launched as a short-lived child (for example, a double-click launcher) closes when its process exits.
- **Decision:** preserve normal one-shot return, print and flush a final status/count/subnet summary, return nonzero on scan or setup failure, support `--help` and `--version`, and handle monitoring Ctrl+C as a clean stop. Do not add an unconditional pause.
- **Rationale:** keeps automation and terminal pipelines usable; users who want a persistent prompt should run the command from an existing shell.
- **Alternatives considered:** always call `input()`; keep the process alive after normal completion. Both break unattended invocations or create a misleading hang.
- **Consequences and trade-offs:** a double-click console can still close after the summary; PowerShell/Terminal remains open when the command runs in that shell.
- **Verification:** mocked one-shot success/failure, unexpected scan exception, monitor interruption, plus help/version.

### D-12 — Topology graph encodes evidence, not physical paths
- **Status:** accepted
- **Context/problem:** the previous dashboard page listed device details but did not draw a graph; ARP does not show remote physical links or end-to-end paths.
- **Decision:** build a testable graph model with selected subnet, local configured address, configured gateway, and deduplicated ARP observations. Edges originate at the subnet and state configured interface/gateway facts or inferred subnet membership. Render through Streamlit Graphviz DOT support.
- **Rationale:** provides a real graph without suggesting that ARP proves a topology beyond observations and configuration.
- **Alternatives considered:** connect every device to the gateway; add a separate graph framework. The former invents paths; the latter is unnecessary for this graph size.
- **Consequences and trade-offs:** no added runtime dependency; graph is appropriate for small LANs and includes hover detail and inventory table fallback.
- **Verification:** offline tests for empty scans, duplicate records, missing metadata, edge evidence, and non-direct device relationships.

### D-13 — Bounded automatic health measurements
- **Status:** accepted
- **Context/problem:** health inputs were manually entered, and a score without controlled measurements can be misleading.
- **Decision:** collect up to five (default four) system ping probes to the configured gateway with bounded per-probe timeout, parse latency/loss only where supported, and make one bounded `nslookup` request to `example.com`. Keep collection in diagnostics separate from the established score formula (gateway 40%, latency 25%, packet loss 20%, DNS 15%; available weights renormalized; at least two measurements required).
- **Rationale:** uses existing platform tools, bounded workload, and no new dependency or third-party MAC/network service.
- **Alternatives considered:** socket TCP probes, indefinite resolver calls, or always mapping unavailable to zero. Rejected as service-specific, unbounded, or misleading.
- **Consequences and trade-offs:** command output and ICMP/DNS policy differ by platform; unparsable or unavailable measurements remain unavailable, and dashboard only runs probes on explicit click.
- **Verification:** mocked platform ping outputs, DNS answers, missing tools, and input bounds; score remains independently testable.

### D-14 — Streamlit monitoring runs sequentially in a page fragment
- **Status:** accepted
- **Context/problem:** a background thread/daemon would complicate Streamlit reruns, overlap prevention, and stop lifecycle.
- **Decision:** use Streamlit fragment reruns with explicit Start/Stop, 60-second minimum, a session-state scan gate, local SQLite persistence, and events based on consecutive successful observations. Skip reverse DNS during monitor samples to keep scans bounded. Monitoring runs only while its page is open; Stop applies after an in-flight ARP operation returns.
- **Rationale:** fragment reruns provide recurring UI work without an unmanaged worker. The gate makes the sequential assumption explicit and testable.
- **Alternatives considered:** unbounded daemon or fast rerun polling; manual sample-only control. Rejected due lifecycle risk or failure to provide recurring monitoring.
- **Consequences and trade-offs:** leaving the Monitoring page pauses automatic fragment ticks. MAC/IP event associations are tentative; absence from one scan means only not observed in that scan.
- **Verification:** interval, start/stop, overlap gate, failure persistence, and new/missing/return event tests.

### D-15 — Do not bundle an OUI registry without redistribution basis
- **Status:** accepted
- **Context/problem:** automatic vendor attribution requires local data, but the project has no vetted database or update path.
- **Decision:** keep vendor attribution optional through caller-supplied local OUI-prefix mappings; do not download at runtime or transmit MACs. Do not copy IEEE registry data into the repo until redistribution terms and refresh procedure are established.
- **Rationale:** avoids licensing ambiguity, stale bundled data, and third-party disclosure. IEEE publishes MAC registration listings, but the checked pages describe registry availability and do not establish a clear project redistribution grant.
- **Alternatives considered:** bundle a third-party OUI package/database; query an external API. Rejected for dependency/license/maintenance or privacy reasons.
- **Consequences and trade-offs:** vendor is unavailable by default. Locally administered/randomized MACs should not be treated as reliable vendor evidence.
- **Verification:** existing local `oui_db` hook remains isolated from discovery; missing vendor mapping is non-fatal.

- **Verification for this phase:** CLI completion/version behavior and topology/measurement/monitor helpers are covered by automated mocks. Final phase checks and exact results are recorded below. No live scan is part of automated verification.

### Next-phase verification — 2026-10-22 (superseded by final integration review below)

- `python -m pytest -q`: **31 passed** at the end of the next implementation phase. Because the sandbox denied pytest temporary-directory traversal under its default ACL, the suite was executed with elevated filesystem access; test contents remained offline/mocked.
- `python -m compileall -q lanwatch lan_watch_scanner.py lan_watch_dashboard.py tests`: **passed**.
- `python lan_watch_scanner.py --help`: **passed** and printed CLI options.
- `python lan_watch_scanner.py --version`: **passed**, output `LAN Watch 1.0` (run during the CLI stage).
- `git diff --check`: **passed**; Git emitted only line-ending conversion warnings for the existing edited Markdown/Python files.
- No live network scan was run. No runtime dependency was added.
- Remaining limitations: interface auto-detection is Windows-only; dashboard monitoring pauses when leaving the Monitoring page and Stop waits for the bounded in-flight scan; system ICMP/DNS output and filtering affect measurement availability; topology shows subnet membership/configuration rather than physical links; vendor lookup requires a supplied local OUI mapping and has no bundled registry; an OUI/MAC prefix is not reliable for locally administered/randomized addresses.

### Final integration review — 2026-10-22

- Reviewed the current CLI/dashboard/shared-core source, README, decisions, requirements, test files, and Git status/diff. No generated database, credential, or vendor-data files were present.
- Fixed a Windows ping command formatting defect: `ping -w` now receives integer milliseconds (for example, `500` instead of `500.0`). Added an offline command assertion. Added coverage for blocked gateway replies and DNS timeout statuses.
- Updated Streamlit dataframe and graph sizing from deprecated `use_container_width=True` to `width="stretch"` after AppTest surfaced the deprecation warning.
- Streamlit `AppTest` exercised all eight pages without app exceptions; topology rendered with empty, incomplete, and failed scan results; mocked monitoring Start/Stop performed one persisted scan and no extra scan on Stop; missing ping/DNS tools rendered unavailable without exceptions. This is app-level testing, not browser automation.
- Exact checks: `python -m pytest -q`: **33 passed**; `python -m compileall -q lanwatch lan_watch_scanner.py lan_watch_dashboard.py tests`: **passed**; `python lan_watch_scanner.py --help`: **passed**; `python lan_watch_scanner.py --version`: **passed** (`LAN Watch 1.0`); `git diff --check`: **passed**. Pytest used elevated filesystem access because of the sandbox temp-directory ACL. No live LAN scan was run and no runtime dependency was added.
- Remaining limitations: automatic interface discovery is Windows-only; no browser-level test was run; monitoring pauses when its page is inactive and waits for the bounded in-flight ARP scan before Stop takes effect; system ping/DNS behavior can vary; graph edges do not claim physical paths; vendor enrichment requires a caller-supplied local prefix mapping and skips locally administered addresses.

### D-16 — Store timestamps in UTC and display in IST
- **Status:** accepted
- **Date:** 2026-10-22
- **Context/problem:** UTC timestamps are appropriate for persistence and ordering, while project users need local readable times in the dashboard and CLI history output.
- **Decision:** keep timestamps and serialized exports in UTC without schema changes. Format user-visible timestamps through `lanwatch.time_formatting` using `zoneinfo.ZoneInfo("Asia/Kolkata")`; label them IST. Interpret naive legacy ISO timestamps as UTC, matching the historic UTC writer. Invalid or missing timestamp values display as `Unavailable`.
- **Rationale:** conversion preserves the represented instant and avoids mutating storage, comparison behavior, or event times. `Asia/Kolkata` has no daylight-saving offset changes.
- **Alternatives considered:** add 5:30 to timestamp strings; rewrite stored history; infer a timezone for naive values. Rejected because these can change instants or make legacy interpretation inconsistent.
- **Consequences and trade-offs:** dashboard tables/previews and CLI history output are human-readable IST, while SQLite, scan JSON, and downloaded CSV/JSON retain UTC. Legacy naive values are assumed UTC; this convention is documented.
- **Verification:** offline tests cover aware datetime and ISO UTC forms, the +05:30 offset, winter/summer consistency, naive legacy values, invalid/missing values, and monitoring/history record formatting. On 2026-10-22, `python -m pytest -q` passed (**38 passed**); `python -m compileall -q lanwatch lan_watch_scanner.py lan_watch_dashboard.py tests` passed; `python lan_watch_scanner.py --help` and `python lan_watch_scanner.py --version` passed (`LAN Watch 1.0`); `git diff --check` passed with only Git line-ending conversion warnings. The first sandbox pytest attempt had 37 passed and one fixture setup error because Windows temp-folder ACL blocked pytest; the exact suite then passed using elevated filesystem access. No live network scan was run.

### D-17 — Format default CLI BLE output as a readable table
- **Status:** accepted
- **Date:** 2026-10-22
- **Context/problem:** the default CLI BLE path emitted all observation dictionaries as one JSON line, which was difficult to read in a terminal.
- **Decision:** reuse the existing `scan_ble` observations and `format_timestamp` helper to render a separate aligned table by default. Display name, identifier, RSSI, service UUIDs, and IST observation time; shorten long values only in the terminal. Preserve `--json --ble` as JSON output and report zero-result success separately from scan failure.
- **Rationale:** improves readability without changing BLE discovery, the observation model, or full values held by the caller.
- **Alternatives considered:** change Bleak scanning or its data model; add a new output option; truncate stored observations. Rejected because presentation alone needs to change and existing `--json` already expresses the output preference.
- **Consequences and trade-offs:** default terminal values may be shortened to fit aligned columns; JSON output retains full observation data. BLE failures remain optional and do not change a successful LAN scan's exit status.
- **Verification:** offline CLI tests cover populated observations and IST formatting, missing name/RSSI, empty service UUIDs, long display values, empty success, BLE failure, LAN success despite BLE failure, separate section headings, and preservation of JSON output. On 2026-10-22, `python -m pytest -q` passed (**45 passed**); `python -m compileall -q lanwatch lan_watch_scanner.py lan_watch_dashboard.py tests` passed; `python lan_watch_scanner.py --help` passed; `git diff --check` passed with Git line-ending conversion warnings. No live network scan was run.
