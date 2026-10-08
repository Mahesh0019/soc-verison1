# Multi-Source Telemetry Foundation & Zeek Integration

**Phase**: Phase 3  
**Status**: Implemented & Verified  
**Date**: October 2026  
**Document Version**: 1.0.0  

---

## 1. Executive Overview

Historically, the Mini SIEM Dashboard ingested web application telemetry (HTTP requests, access logs, and Juice Shop connector events). Phase 3 introduces a unified **Multi-Source Telemetry Architecture**, expanding the SOC engine into network-layer visibility while preserving full backward compatibility with the existing `NormalizedEvent` schema and detection pipeline.

The primary external telemetry engine integrated in this phase is **Zeek Network Telemetry** (`conn.log`, `http.log`, `dns.log`), supporting both standard Zeek tab-separated values (TSV with `#fields` headers) and JSON streaming lines format.

---

## 2. Telemetry Classification & Status Taxonomy

Telemetry sources are strictly classified and differentiated across implementation states:

| Source Type | Category | Status | Ingestion Mechanism | Notes |
| :--- | :--- | :--- | :--- | :--- |
| **WEB** | Application / HTTP | `IMPLEMENTED` | Live API / Connector / Replay | Nginx, Apache, Juice Shop, API |
| **AUTH** | Authentication / PAM | `IMPLEMENTED` | Log Parsing / Replay | SSH, PAM, Linux Auth logs |
| **FIREWALL** | Network Perimeter | `IMPLEMENTED` | Syslog / Replay | UFW, iptables, pfSense |
| **ZEEK** | Network Telemetry | `IMPLEMENTED` | File Replay / API Ingestion | conn.log, http.log, dns.log |
| **SYSMON** | Host / EDR Telemetry | `PLANNED / NOT IMPLEMENTED` | *None* | Explicitly reserved for future Phase |
| **THREAT_INTEL** | Context / Indicators | `IMPLEMENTED` | Feed / IOC Matching | IP/domain/hash blacklists |
| **OTHER** | Generic / Custom | `IMPLEMENTED` | Generic Log Parser | Catch-all fallback |

### Mode Classification
- **`LIVE`**: Live sensor feed ingested directly via active network tap or streaming connector.
- **`REPLAY`**: High-fidelity replay of recorded telemetry sessions (TSV/JSON logs) for reproducible research and benchmarking.
- **`SIMULATED`**: Synthetically generated attack or benign scenarios matching standard Zeek schemas.
- **`PLANNED`**: Reserved for future architectural phases (e.g., Sysmon host telemetry).

---

## 3. NormalizedEvent Schema Extension

Rather than deprecating or replacing `NormalizedEvent`, the schema was extended with backward-compatible, nullable columns. Existing queries and historical research evaluations (Dataset V1, Dataset V2 M0–M6) operate without interruption.

### Schema Fields & Mapping
```
NormalizedEvent
├── id: Integer (PK)
├── raw_log_id: Integer (FK -> raw_logs.id, ON DELETE SET NULL)
├── event_id: String(64)                    [Added in Phase 3 - Zeek UID / Global Event ID]
├── timestamp: DateTime(timezone=True)
│
├── Multi-Source Classification:
│   ├── source_type: String(32)             [Added in Phase 3 - Default 'WEB', 'ZEEK', etc.]
│   └── source_name: String(64)             [Added in Phase 3 - e.g. 'zeek-conn', 'zeek-http']
│
├── Network Telemetry:
│   ├── source_ip: String(64)
│   ├── destination_ip: String(64)
│   ├── source_port: Integer                [Added in Phase 3 - id.orig_p]
│   ├── destination_port: Integer           [Added in Phase 3 - id.resp_p]
│   ├── protocol: String(32)                [Added in Phase 3 - tcp, udp, icmp]
│   ├── connection_state: String(32)        [Added in Phase 3 - SF, REJ, S0, etc.]
│   ├── bytes_in: Integer                   [Added in Phase 3 - orig_bytes / req_bytes]
│   ├── bytes_out: Integer                  [Added in Phase 3 - resp_bytes / resp_len]
│   └── response_time_ms: Float             [Added in Phase 3 - duration * 1000]
│
├── DNS Telemetry:
│   ├── dns_query: String(512)              [Added in Phase 3 - query name]
│   └── dns_response: Text                  [Added in Phase 3 - answer IPs, rcode]
│
├── Identity, Host & EDR Telemetry:
│   ├── username: String(128)
│   ├── hostname: String(255)
│   ├── process: String(255)                [Added in Phase 3 - EDR placeholder]
│   └── parent_process: String(255)         [Added in Phase 3 - EDR placeholder]
│
├── Web Telemetry:
│   ├── http_method: String(16)
│   ├── request_path: String(2048)
│   ├── status_code: Integer
│   ├── user_agent: Text
│   └── geo_country: String(80)
│
└── Provenance & Raw Log:
    ├── raw_reference: String(128)          [Added in Phase 3 - Tracking UID / provenance]
    ├── raw_log: Text                       [Bounded to 8192 characters]
    ├── event_type: String(80)
    ├── event_category: String(80)
    ├── severity: String(32)
    └── message: Text                       [Bounded to 4000 characters]
```

---

## 4. Zeek Telemetry Parsers

The parser engine (`backend/app/parsers/zeek_parser.py`) natively supports both standard Zeek TSV (with `#fields` and `#types` header directives) and Zeek streaming JSON lines.

### 4.1 `conn.log`
Normalizes transport-layer connection records:
- `ts` -> `timestamp` (epoch float or ISO)
- `uid` -> `event_id` and `raw_reference`
- `id.orig_h` -> `source_ip`
- `id.orig_p` -> `source_port`
- `id.resp_h` -> `destination_ip`
- `id.resp_p` -> `destination_port`
- `proto` -> `protocol` (e.g. `tcp`, `udp`)
- `duration` -> `response_time_ms` (duration in seconds converted to milliseconds)
- `orig_bytes` -> `bytes_in` (safely mapped; `-` maps to `None`)
- `resp_bytes` -> `bytes_out` (safely mapped; `-` maps to `None`)
- `conn_state` -> `connection_state` (`SF`, `REJ`, `S0`, `RSTO`, etc.)
- Event classification:
  - Rejected connections (`REJ`, `RSTO`, `RSTR`) -> `event_type = zeek_conn_rejected`, `severity = medium`
  - Suspicious destination ports (`1337`, `31337`, `4444`, `6667`) -> `event_type = zeek_suspicious_port`, `severity = high`
  - Normal connections -> `event_type = zeek_connection`, `severity = low`

### 4.2 `http.log`
Normalizes application-layer HTTP transactions:
- `method` -> `http_method` (`GET`, `POST`, `PUT`, `DELETE`, etc.)
- `host` -> `hostname`
- `uri` -> `request_path`
- `user_agent` -> `user_agent`
- `status_code` -> `status_code`
- `request_body_len` -> `bytes_in`
- `response_body_len` -> `bytes_out`
- `id.orig_h` / `id.resp_h` -> `source_ip` / `destination_ip`
- Event classification:
  - Sensitive paths (`/admin`, `/login`, `/.env`, `/config`) -> `event_type = sensitive_path_access`, `severity = medium`
  - 404 responses -> `event_type = http_404`, `severity = low`
  - 5xx responses -> `event_type = http_server_error`, `severity = medium`
  - Standard transactions -> `event_type = zeek_http`, `severity = low`

### 4.3 `dns.log`
Normalizes network name resolution:
- `query` -> `dns_query`
- `qtype_name` / `qtype` -> extracted for message formatting
- `rcode_name` / `rcode` -> status tracking (`NOERROR`, `NXDOMAIN`, `SERVFAIL`, etc.)
- `answers` -> `dns_response` (comma-delimited list of returned IP addresses or aliases)
- `id.orig_h` / `id.resp_h` -> `source_ip` / `destination_ip` (client IP / DNS resolver IP)
- Event classification:
  - `NXDOMAIN` / `REFUSED` -> `event_type = zeek_dns_nxdomain`, `severity = medium`
  - Standard queries -> `event_type = zeek_dns`, `severity = low`

---

## 5. Replay & Ingestion Architecture

### Replay Service (`backend/app/services/zeek_service.py`)
Provides an end-to-end replay engine for security researchers and SOC operators:
1. **Provenance Tracking**: Every replay generates a `RawLog` record with `source_type = ZEEK_<TYPE>_<MODE>` and stores the raw upload content.
2. **Streaming Normalization**: Automatically differentiates TSV vs JSON.
3. **Deduplication Tracking**: Monitors duplicate UIDs (`raw_reference`) and updates the `duplicated` counter without halting ingestion.
4. **Resilient Error Containment**: Malformed lines are caught, recorded in `errors`, and counted under `rejected` without raising fatal exceptions.
5. **Detection Integration**: Invokes `evaluate_rules_for_events(db, events)` naturally for all accepted events.
6. **Telemetry Benchmarking**: Measures and returns `throughput_eps`, `average_latency_ms`, and `maximum_latency_ms`.

### API Endpoints
- `GET /api/telemetry/sources`: Returns source catalog and implementation status map.
- `POST /api/telemetry/zeek/replay`: Accepts raw TSV or JSON log payloads for replay benchmarking.
- `POST /api/telemetry/zeek/upload`: Accepts multipart file uploads of Zeek log files.
- `GET /api/events?source_type=ZEEK`: Filters event log to Zeek telemetry.

---

## 6. Security Hardening & Robustness

1. **Crash Prevention**: All token conversions use `safe_int`, `safe_float`, and `safe_str` with explicit exception trapping. Missing Zeek fields (`-`, `(empty)`) cleanly translate to `None`.
2. **Bounded Field Sizes**: String lengths are strictly capped before database insertion:
   - `message`: 4,000 chars
   - `raw_log`: 8,192 chars
   - `request_path`: 2,048 chars
   - `user_agent`: 1,024 chars
   - `dns_query`: 512 chars
   - `hostname`: 255 chars
   - `source_ip` / `destination_ip`: 64 chars
3. **SQL Injection Immunity**: All database queries use parameterized SQLAlchemy ORM statements; no raw SQL string concatenation exists.
4. **Role-Based Access Control**: Replay and upload endpoints require authenticated users with `admin` or `analyst` roles.
5. **Sanitization**: Raw log inputs are scrubbed of null bytes and hazardous control characters via `sanitize_text`.

---

## 7. Empirical Performance Baseline

Benchmarking was executed across the complete Zeek test fixture suite using `scripts/benchmark_zeek.py`:

| Fixture File | Format | Type | Processed | Accepted | Rejected | Duplicated | Throughput (eps) | Avg Latency (ms) | Max Latency (ms) | Errors Encountered |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `conn.log` | TSV | conn | 7 | 6 | 1 | 1 | 36.59 | 0.131 | 0.257 | Line 15 syntax error |
| `conn.json` | JSON | conn | 5 | 4 | 1 | 1 | 637.56 | 0.118 | 0.158 | Line 5 unterminated JSON |
| `http.log` | TSV | http | 5 | 4 | 1 | 0 | 971.91 | 0.131 | 0.193 | Line 13 delimiter mismatch |
| `http.json` | JSON | http | 3 | 3 | 0 | 0 | 652.76 | 0.118 | 0.151 | None |
| `dns.log` | TSV | dns | 4 | 3 | 1 | 0 | 636.25 | 0.122 | 0.187 | Line 12 malformed row |
| `dns.json` | JSON | dns | 2 | 2 | 0 | 0 | 582.41 | 0.124 | 0.147 | None |
| **TOTAL / AGGREGATE** | — | — | **26** | **22** | **4** | **2** | **586.25 eps** | **0.124 ms** | **0.257 ms** | **4 handled safely** |

*Note: All rejections and malformed lines were captured gracefully without crashing the ingestion engine.*

---

## 8. Limitations & Future Scope

### Limitations in Phase 3
- Network detection rules in this phase evaluate individual network records; cross-source correlation (e.g., tying a Zeek connection to an Apache access log or host PID) is not implemented.
- Zeek SSL/x509 certificates and SMB/files log formats are not yet parsed.
- Zeek packet capture (`.pcap`) extraction is outside scope; input is structured log telemetry (`.log` or `.json`).

### Future Sysmon Integration (Phase 4 / Planned)
- Sysmon host telemetry fields (`process`, `parent_process`, command line, image hashes) are mapped in the `NormalizedEvent` schema as nullable placeholders.
- Real Sysmon ingestion remains strictly `PLANNED / NOT IMPLEMENTED`. No mock or synthetic Sysmon ingestion will be created until Phase 4 approval.

### Future Cross-Source Correlation (Phase 5 / Planned)
- Establishing temporal graph joins between Network (`ZEEK`), Host (`SYSMON`), and Application (`WEB`) sources is reserved for multi-source correlation.
