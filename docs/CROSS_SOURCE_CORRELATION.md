# Cross-Source Telemetry Correlation & Unified Incident Reconstruction

## 1. Architectural Overview

Phase 6 transitions the SOC platform from siloed single-source detection engines into a multi-layered, cross-source telemetry correlation and unified incident reconstruction architecture. The pipeline correlates telemetry across three independent data planes:

```
[ Application Plane ]          [ Network Plane ]           [ Endpoint Plane ]
   Web / Auth Logs              Zeek Telemetry               Windows Sysmon
   (SQLi, XSS, Auth)         (conn, dns, http, ssl)      (EID 1, 3, 7, 8, 22)
          │                            │                           │
          ▼                            ▼                           ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │                    Unified Normalization Engine                        │
 │           (Deterministic Schema: NormalizedEvent, RawLog)              │
 └────────────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │                      Detection Engine (Rules V1 & V2)                  │
 │      Single-Source Detection Alerts Generated (Rule, Severity, Entity)  │
 └────────────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │             Cross-Source Correlation Engine (Phase 6 Core)             │
 │  - Deterministic Entity Resolution                                     │
 │  - Configurable Temporal Correlation Windows (±30s, ±120s, ±300s, ±600s)│
 │  - Explicit Correlation Rules (CORR-001 .. CORR-004)                   │
 │  - Explainable 4-Factor Correlation Scoring Formula                    │
 └────────────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │                       Unified Incident Model                           │
 │  - Primary & Related Entities                                          │
 │  - Multi-Source Provenance (WEB, ZEEK, SYSMON)                         │
 │  - Chronological Telemetry Timeline (Relative Delta t)                 │
 │  - Telemetry-Backed Attack Graph (Nodes & Typed Edges)                 │
 │  - Cryptographic Evidence Linkage & Tamper-Evident SHA-256 Hashes     │
 │  - Risk & Triage Score Assignment                                      │
 └────────────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │                     Analyst Investigation UI                           │
 │     - Unified Incidents Table with Status Triage                       │
 │     - Interactive SVG Attack Graph with Filtering & Node Expansion     │
 │     - Chronological Timeline with Per-Step Delta Inspection             │
 └────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Deterministic Entity Resolution

The correlation engine utilizes deterministic matching across explicit fields present in telemetry. In accordance with zero-trust SOC research standards, **no entity identity is inferred when underlying telemetry does not substantiate it**.

| Entity Attribute | Canonical Field | Telemetry Source Support | Resolution Behavior |
| :--- | :--- | :--- | :--- |
| `source_ip` | `NormalizedEvent.source_ip` | Web, Zeek, Sysmon EID 3 | Case-insensitive IPv4/IPv6 string matching. Loopbacks (`127.0.0.1`, `::1`) and unspecified IPs (`0.0.0.0`) are excluded from cross-correlation. |
| `destination_ip` | `NormalizedEvent.destination_ip` | Web, Zeek, Sysmon EID 3 | Bidirectional relationship matching (e.g. Zeek flow `id.resp_h` matched to Sysmon outbound `DestinationIp`). |
| `hostname` | `NormalizedEvent.hostname` | Web, Zeek (DHCP/DNS), Sysmon | Normalized lowercase FQDN or NetBIOS string comparison. |
| `username` | `NormalizedEvent.username` | Auth, Sysmon EID 1/3 | Domain-stripped username normalization (`DOMAIN\user` $\rightarrow$ `user`). |
| `process` | `NormalizedEvent.process` | Sysmon EID 1, 3, 7, 8 | Lowercase basename comparison (`powershell.exe`, `rundll32.exe`). |
| `process_id` | `NormalizedEvent.process_id` | Sysmon EID 1, 3 | Strict scoped comparison: `(hostname, process_id)` compound key. |
| `parent_process_id`| `NormalizedEvent.parent_process_id` | Sysmon EID 1 | Parent-child process hierarchy linking on identical host. |
| `dns_query` | `NormalizedEvent.dns_query` | Zeek dns.log, Sysmon EID 22 | Normalized domain query matching (`beacon.evilcorp.net`). |
| `raw_reference` | `NormalizedEvent.raw_reference` | Zeek UID (`uid`), Sysmon GUID | Exact string match on unique connection / process GUIDs. |

---

## 3. Configurable Temporal Correlation Windows

Temporal proximity is an indispensable dimension of security correlation. To prevent arbitrary fixed-window bias, the engine natively supports configurable correlation windows:

- **±30 seconds** (`window_seconds=30`): Ultra-tight window suited for immediate command-and-control socket establishment or direct web exploit execution.
- **±120 seconds** (`window_seconds=120`): Balanced window for multi-stage reconnaissance followed by lateral pivot.
- **±300 seconds** (`window_seconds=300` - **SOC Default**): Production default providing sufficient coverage for realistic attacker dwell time between probe and payload execution while minimizing NAT collisions.
- **±600 seconds** (`window_seconds=600`): Extended investigation window for slow-and-low attack campaign reconstruction.

### Temporal Decay Function
Temporal proximity factor $F_{time}$ decays linearly as the time delta between the earliest and latest telemetry events approaches the configured window boundary:
$$F_{time} = \max\left(0.0, \, 1.0 - \frac{\Delta t}{W_{sec}}\right)$$
where $\Delta t = |t_{max} - t_{min}|$ and $W_{sec}$ is the active correlation window.

---

## 4. Explicit Correlation Rules

The engine implements four explicit, deterministic correlation rules. Per strict SOC protocol, correlated events are categorized as `CORRELATED ACTIVITY` or `POTENTIAL ATTACK CHAIN` until conclusive evidence validates an active compromise:

### Rule CORR-001: Web Exploit to Network C2 Pivot
- **Antecedent**: High/Critical Web detection alert (`RULE-012`, `RULE-013`, `RULE-014`) AND Zeek network alert (`NETWORK-001`, `NETWORK-002`, `NETWORK-003`).
- **Entity Constraint**: Identical `source_ip` (or Web target = Zeek destination).
- **Time Constraint**: $|t_{web} - t_{zeek}| \le W_{sec}$.
- **Resulting Classification**: `CORRELATED ACTIVITY`.
- **Explanation**: *"Matched source_ip={ip} across Web exploit probe and Zeek network flow within {dt:.1f}s."*

### Rule CORR-002: Web Exploit to Host Process Execution
- **Antecedent**: Web exploit attempt AND Sysmon Process Creation alert (`ENDPOINT-001`, `ENDPOINT-002`).
- **Entity Constraint**: Identical `hostname` (Web server host = Sysmon endpoint host).
- **Time Constraint**: $t_{web} \le t_{sysmon}$ AND $|t_{sysmon} - t_{web}| \le W_{sec}$.
- **Resulting Classification**: `POTENTIAL ATTACK CHAIN`.
- **Explanation**: *"Web application exploit followed by anomalous child process execution ({proc}) on host {host} within {dt:.1f}s."*

### Rule CORR-003: Network Anomaly to Endpoint Socket Correlation
- **Antecedent**: Zeek network beacon/scan alert AND Sysmon Network Connection alert (`ENDPOINT-003`).
- **Entity Constraint**: Matching `(source_ip, destination_ip)` tuple across Zeek flow and Sysmon socket.
- **Time Constraint**: $|t_{zeek} - t_{sysmon}| \le W_{sec}$.
- **Resulting Classification**: `POTENTIAL ATTACK CHAIN`.
- **Explanation**: *"Zeek connection flow correlates directly with endpoint process {proc} establishing outbound socket to {dst_ip}:{dst_port} within {dt:.1f}s."*

### Rule CORR-004: Endpoint DNS Query to Network Traffic Correlation
- **Antecedent**: Sysmon DNS Query alert (`ENDPOINT-004`) AND Zeek DNS/Connection flow (`NETWORK-003` or Zeek dns.log).
- **Entity Constraint**: Matching `dns_query` domain AND matching `hostname` or `source_ip`.
- **Time Constraint**: $|t_{dns} - t_{zeek}| \le W_{sec}$.
- **Resulting Classification**: `POTENTIAL ATTACK CHAIN`.
- **Explanation**: *"Sysmon DNS lookup for {query} matches Zeek network resolution from host {host} within {dt:.1f}s."*

---

## 5. Explainable Correlation Scoring

Correlation confidence is calculated using a mathematically grounded, 4-factor explainable formula. Arbitrary scoring inflation is strictly disallowed:

$$\text{Correlation Score} = (0.35 \times F_{entity}) + (0.25 \times F_{time}) + (0.20 \times F_{source}) + (0.20 \times F_{severity})$$

### Factor Breakdown:
1. **$F_{entity}$ (Entity Match Weight: 0.35)**:
   - $1.0$: $\ge 2$ strong entity matches (`source_ip`, `hostname`, `process`, or `(host, pid)`).
   - $0.70$–$0.85$: Exactly 1 strong entity match.
   - $0.50$: Weak or single-item entity match.
   - $0.10$: Zero deterministic matches.
2. **$F_{time}$ (Temporal Proximity Weight: 0.25)**:
   - Decays linearly from $1.0$ at $\Delta t = 0\text{s}$ down to $0.0$ at $\Delta t \ge W_{sec}$.
3. **$F_{source}$ (Source Diversity Weight: 0.20)**:
   - $1.0$: $\ge 3$ distinct telemetry sources (e.g. Web + Zeek + Sysmon).
   - $0.75$: Exactly 2 distinct sources (e.g. Web + Sysmon).
   - $0.40$: Single source cluster.
4. **$F_{severity}$ (Alert Severity Weight: 0.20)**:
   - Critical: $1.0$, High: $0.8$, Medium: $0.5$, Low: $0.2$.

### Confidence Thresholds:
- $\text{Score} \ge 0.75 \implies \mathbf{HIGH}$ confidence
- $0.50 \le \text{Score} < 0.75 \implies \mathbf{MEDIUM}$ confidence
- $0.35 \le \text{Score} < 0.50 \implies \mathbf{LOW}$ confidence
- $\text{Score} < 0.35 \implies \mathbf{INSUFFICIENT\ CORRELATION\ EVIDENCE}$

Every incident record explicitly includes the computed factors and justification string in its tamper-evident audit record.

---

## 6. Unified Incident Data Model

The `incidents` table encapsulates all multi-source correlation artifacts:

```sql
ALTER TABLE incidents ADD COLUMN primary_entity VARCHAR(128);
ALTER TABLE incidents ADD COLUMN related_entities_json JSON;
ALTER TABLE incidents ADD COLUMN source_types_json JSON;
ALTER TABLE incidents ADD COLUMN correlation_score FLOAT;
ALTER TABLE incidents ADD COLUMN confidence VARCHAR(64);
ALTER TABLE incidents ADD COLUMN risk_score FLOAT;
ALTER TABLE incidents ADD COLUMN attack_chain_status VARCHAR(64);
ALTER TABLE incidents ADD COLUMN timeline_json JSON;
ALTER TABLE incidents ADD COLUMN graph_json JSON;
```

---

## 7. Incident Timeline & Attack Graph Reconstruction

### Chronological Timeline Engine
- Aggregates raw stored normalized events and triggered alerts linked to the incident cluster.
- Enforces strict ascending timestamp order ($t_0 \le t_1 \le t_2 \dots$).
- Automatically calculates relative delta time $\Delta t = t_i - t_0$ in seconds.
- Every timeline step links to actual database records (`event_id`, `alert_id`, `evidence_ref`). **No intermediate attack steps are fabricated.**

### Telemetry-Backed Attack Graph Engine
The graph engine maps all participating telemetry into an undirected typed property graph:
- **Node Types**: `Incident`, `Alert`, `Event`, `IP`, `Host`, `User`, `Process`, `Domain`, `URL`.
- **Edge Types**:
  - `Incident` $\xrightarrow{\text{ASSOCIATED\_WITH}}$ `Alert`
  - `Alert` $\xrightarrow{\text{GENERATED\_FROM}}$ `Event`
  - `Event` $\xrightarrow{\text{ORIGINATED\_AT}}$ `IP`
  - `Event` $\xrightarrow{\text{EXECUTED\_ON}}$ `Host`
  - `Host` $\xrightarrow{\text{EXECUTED}}$ `Process`
  - `Process` $\xrightarrow{\text{SPAWNED}}$ `Process`
  - `Process` $\xrightarrow{\text{CONNECTED\_TO}}$ `IP`
  - `Event` $\xrightarrow{\text{QUERIED}}$ `Domain`
  - `Event` $\xrightarrow{\text{REQUESTED}}$ `URL`
  - `Event` $\xrightarrow{\text{AUTHENTICATED\_AS}}$ `User`

---

## 8. Frontend Investigation Interface

The frontend (`frontend/src/`) provides dedicated views for multi-source triage:
1. **View Mode Switcher**: Seamless toggle between "Alerts Queue" and "Unified Incidents".
2. **Correlation Window Selector**: Dropdown to select 30s, 120s, 300s (Default), or 600s windows.
3. **One-Click Correlation Trigger**: Runs backend correlation with instant UI refresh.
4. **Interactive SVG Attack Graph (`IncidentGraphView.tsx`)**:
   - Draggable, force-spaced radial layout.
   - Source filtering (`ALL`, `WEB`, `ZEEK`, `SYSMON`).
   - Click-to-inspect side panel detailing telemetry properties, raw payloads, and evidence IDs.
5. **Telemetry Timeline (`IncidentTimelineView.tsx`)**:
   - Color-coded source tags (`WEB` in emerald, `ZEEK` in indigo, `SYSMON` in amber, `ALERT` in crimson).
   - Relative second deltas (`+0.0s`, `+12.4s`, `+45.2s`).
   - Deep inspection modal displaying raw JSON logs and entity mappings.

---

## 9. Security, RBAC & Parameterization

- **SQL Injection Prevention**: All entity resolution queries, cluster queries, and evidence inserts use SQLAlchemy parameterized query builders.
- **RBAC Enforcement**: The `/api/incidents/correlate` execution endpoint and detail APIs require authenticated JWT tokens (`ANALYST` or `ADMIN` roles). Viewer roles possess read-only graph access.
- **Cryptographic Evidence Integrity**: Every correlation rule match generates an `Evidence` record containing a deterministic SHA-256 hash of the supporting event IDs and matched entities.
