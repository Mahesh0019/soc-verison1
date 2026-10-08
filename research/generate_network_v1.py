"""
research/generate_network_v1.py

Generates the Phase 4 Network Benchmark Dataset (Network V1):
- Total: 60 balanced scenarios (30 ATTACK, 30 BENIGN)
- Split:
  - 50% Development (30 scenarios: 15 ATTACK, 15 BENIGN)
  - 20% Validation  (12 scenarios: 6 ATTACK, 6 BENIGN)
  - 30% Test        (18 scenarios: 9 ATTACK, 9 BENIGN - Held-out!)
- Coverage:
  BENIGN:
  - normal web connection (port 80/443 TCP, SF)
  - normal DNS (port 53 UDP, query="example.com", NOERROR)
  - normal HTTP (GET /index.html, 200 OK)
  - normal rejected connection (1-2 REJ connections, below threshold 5)
  - normal high-volume but legitimate traffic (6-8 connections, below threshold 15)
  - normal repeated DNS queries (2 lookups, NOERROR)
  ATTACK / SUSPICIOUS:
  - suspicious destination port (e.g. 1337, 31337, 4444, 6667)
  - connection burst (16+ connections in 5 min)
  - reconnaissance-like connection sequence (multiple ports, REJ)
  - repeated rejected connections (5+ REJ connections)
  - suspicious HTTP path (3+ requests to /.env, /admin)
  - DNS anomaly (3+ NXDOMAIN responses)
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path


def generate_network_dataset():
    base_time = datetime(2026, 10, 8, 9, 0, 0, tzinfo=UTC)
    scenarios = []

    # -------------------------------------------------------------
    # Helper to construct Zeek events
    # -------------------------------------------------------------
    def make_conn_event(ts, src_ip, dst_ip, src_p, dst_p, proto="tcp", state="SF", duration_s=0.05, bytes_in=200, bytes_out=1000, uid=None):
        dur_ms = round(duration_s * 1000.0, 2)
        is_rej = state in ("REJ", "RSTO", "RSTR")
        is_susp = dst_p in (1337, 31337, 4444, 6667)
        if is_rej:
            ev_type = "zeek_conn_rejected"
            sev = "medium"
        elif is_susp:
            ev_type = "zeek_suspicious_port"
            sev = "high"
        else:
            ev_type = "zeek_connection"
            sev = "low"
        u = uid or f"C_NET_{src_p}"
        return {
            "timestamp": ts.isoformat(),
            "source_type": "ZEEK",
            "source_name": "zeek-conn",
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "source_port": src_p,
            "destination_port": dst_p,
            "protocol": proto.lower(),
            "connection_state": state,
            "bytes_in": bytes_in,
            "bytes_out": bytes_out,
            "response_time_ms": dur_ms,
            "event_type": ev_type,
            "event_category": "network",
            "severity": sev,
            "message": f"Zeek conn: {proto.upper()} {src_ip}:{src_p} -> {dst_ip}:{dst_p} [{state}]",
            "raw_reference": u,
            "raw_log": f"{ts.timestamp()}\t{u}\t{src_ip}\t{src_p}\t{dst_ip}\t{dst_p}\t{proto}\t-\t{duration_s}\t{bytes_in or '-'}\t{bytes_out or '-'}\t{state}",
        }

    def make_http_event(ts, src_ip, dst_ip, src_p, dst_p, method="GET", host="example.com", uri="/", status=200, req_len=0, resp_len=500, ua="Mozilla/5.0", uid=None):
        u = uid or f"H_NET_{src_p}"
        is_sens = any(uri.lower().startswith(p) for p in ("/admin", "/login", "/.env", "/config", "/wp-admin"))
        if is_sens:
            ev_type = "sensitive_path_access"
            sev = "medium"
        elif status == 404:
            ev_type = "http_404"
            sev = "low"
        else:
            ev_type = "zeek_http"
            sev = "low"
        return {
            "timestamp": ts.isoformat(),
            "source_type": "ZEEK",
            "source_name": "zeek-http",
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "source_port": src_p,
            "destination_port": dst_p,
            "protocol": "tcp",
            "hostname": host,
            "http_method": method,
            "request_path": uri,
            "user_agent": ua,
            "status_code": status,
            "bytes_in": req_len,
            "bytes_out": resp_len,
            "event_type": ev_type,
            "event_category": "web",
            "severity": sev,
            "message": f"Zeek HTTP: {method} {host}{uri} -> {status}",
            "raw_reference": u,
            "raw_log": f"{ts.timestamp()}\t{u}\t{src_ip}\t{src_p}\t{dst_ip}\t{dst_p}\t1\t{method}\t{host}\t{uri}\t-\t1.1\t{ua}\t-\t{req_len}\t{resp_len}\t{status}",
        }

    def make_dns_event(ts, src_ip, dst_ip, src_p, dst_p=53, query="example.com", rcode="NOERROR", answers="93.184.216.34", uid=None):
        u = uid or f"D_NET_{src_p}"
        is_nx = rcode in ("NXDOMAIN", "REFUSED")
        ev_type = "zeek_dns_nxdomain" if is_nx else "zeek_dns"
        sev = "medium" if is_nx else "low"
        return {
            "timestamp": ts.isoformat(),
            "source_type": "ZEEK",
            "source_name": "zeek-dns",
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "source_port": src_p,
            "destination_port": dst_p,
            "protocol": "udp",
            "dns_query": query,
            "dns_response": answers or rcode,
            "event_type": ev_type,
            "event_category": "network",
            "severity": sev,
            "message": f"Zeek DNS: query {query} (A) -> {rcode} [{answers or ''}]",
            "raw_reference": u,
            "raw_log": f"{ts.timestamp()}\t{u}\t{src_ip}\t{src_p}\t{dst_ip}\t{dst_p}\tudp\t100\t0.002\t{query}\t1\tC_INTERNET\t1\tA\t0\t{rcode}\tF\tF\tT\tT\t0\t{answers}\t300\tF",
        }

    # -------------------------------------------------------------
    # Scenario Generation Templates (Interleaved 50/50)
    # -------------------------------------------------------------
    categories = [
        ("normal_web", "BENIGN", False, "none", "T1071"),
        ("suspicious_port", "ATTACK", True, "high", "T1571"),
        ("normal_dns", "BENIGN", False, "none", "T1071.004"),
        ("connection_burst", "ATTACK", True, "medium", "T1499.001"),
        ("normal_http", "BENIGN", False, "none", "T1071.001"),
        ("reconnaissance_seq", "ATTACK", True, "high", "T1595"),
        ("normal_rejected", "BENIGN", False, "none", None),
        ("repeated_rejected", "ATTACK", True, "medium", "T1046"),
        ("normal_high_volume", "BENIGN", False, "none", None),
        ("suspicious_http", "ATTACK", True, "high", "T1595.002"),
        ("normal_repeated_dns", "BENIGN", False, "none", "T1071.004"),
        ("dns_anomaly", "ATTACK", True, "medium", "T1568"),
    ]

    scenario_idx = 1
    # 60 total scenarios: 30 DEV, 12 VAL, 18 TEST
    # Splits plan:
    # DEV: 15 ATTACK, 15 BENIGN (scenarios 1..30)
    # VAL: 6 ATTACK, 6 BENIGN   (scenarios 31..42)
    # TEST: 9 ATTACK, 9 BENIGN  (scenarios 43..60)

    for i in range(60):
        s_id_num = i + 1
        if s_id_num <= 30:
            split = "development"
            cat_pick = categories[(i % 12)]
        elif s_id_num <= 42:
            split = "validation"
            cat_pick = categories[((i - 30) % 12)]
        else:
            split = "test"
            cat_pick = categories[((i - 42) % 12)]

        cat_name, g_truth, exp_detect, exp_sev, mitre = cat_pick
        s_time = base_time + timedelta(minutes=i * 10)
        src_ip = f"192.168.1.{100 + (i % 50)}"
        dst_ip = f"10.0.0.{10 + (i % 10)}"

        events = []
        if cat_name == "normal_web":
            # 1-2 standard web connections
            events.append(make_conn_event(s_time, src_ip, dst_ip, 40000 + i, 443, proto="tcp", state="SF", bytes_in=1500, bytes_out=8000))
            name = f"Normal HTTPS Web Session #{s_id_num}"
            desc = "Standard TLS connection to corporate web server over port 443."
        elif cat_name == "normal_dns":
            # 1 benign DNS lookup
            events.append(make_dns_event(s_time, src_ip, "10.0.0.53", 50000 + i, 53, query="corp.internal.example", rcode="NOERROR", answers="10.0.0.12"))
            name = f"Normal Corporate DNS Resolution #{s_id_num}"
            desc = "Legitimate client DNS query resolving internal corporate domain."
        elif cat_name == "normal_http":
            # 1-2 benign HTTP requests
            events.append(make_http_event(s_time, src_ip, dst_ip, 41000 + i, 80, method="GET", host="portal.example.com", uri="/index.html", status=200))
            name = f"Normal HTTP Portal Navigation #{s_id_num}"
            desc = "Routine user HTTP request to portal index page."
        elif cat_name == "normal_rejected":
            # 1-2 isolated rejected connections (below threshold of 5)
            events.append(make_conn_event(s_time, src_ip, dst_ip, 42000 + i, 22, proto="tcp", state="REJ", duration_s=0.001, bytes_in=None, bytes_out=None))
            events.append(make_conn_event(s_time + timedelta(seconds=2), src_ip, dst_ip, 42001 + i, 22, proto="tcp", state="REJ", duration_s=0.001, bytes_in=None, bytes_out=None))
            name = f"Isolated Service Connection Failure #{s_id_num}"
            desc = "Sporadic connection rejection to SSH daemon (under threshold)."
        elif cat_name == "normal_high_volume":
            # 7 connections over 4 minutes (under threshold of 15)
            for k in range(7):
                events.append(make_conn_event(s_time + timedelta(seconds=k * 20), src_ip, dst_ip, 43000 + (i * 10) + k, 443, state="SF", bytes_in=500, bytes_out=2000))
            name = f"Legitimate High Volume Traffic #{s_id_num}"
            desc = "Burst of legitimate web requests below threshold of 15."
        elif cat_name == "normal_repeated_dns":
            # 2 DNS queries for CDN hostnames
            events.append(make_dns_event(s_time, src_ip, "10.0.0.53", 51000 + i, 53, query="cdn.example.com", rcode="NOERROR", answers="104.16.1.1"))
            events.append(make_dns_event(s_time + timedelta(seconds=5), src_ip, "10.0.0.53", 51001 + i, 53, query="static.example.com", rcode="NOERROR", answers="104.16.1.2"))
            name = f"Legitimate CDN DNS Query Sequence #{s_id_num}"
            desc = "Multiple successful DNS resolutions for web assets."
        elif cat_name == "suspicious_port":
            # Connection to port 31337 or 1337
            port = 31337 if (i % 2 == 0) else 1337
            events.append(make_conn_event(s_time, src_ip, dst_ip, 44000 + i, port, state="SF", duration_s=0.02, bytes_in=64, bytes_out=64))
            name = f"Backdoor Port Connection Attempt #{s_id_num}"
            desc = f"Direct TCP handshake to suspicious destination port {port}."
        elif cat_name == "connection_burst":
            # 16 connections within 2 minutes (exceeding threshold of 15)
            for k in range(16):
                events.append(make_conn_event(s_time + timedelta(seconds=k * 4), src_ip, dst_ip, 45000 + (i * 20) + k, 80, state="SF", bytes_in=100, bytes_out=500))
            name = f"High Frequency Connection Burst #{s_id_num}"
            desc = "Sudden traffic flood of 16 connections from single host within 2 minutes."
        elif cat_name == "reconnaissance_seq":
            # 5 sequential connections across ports with rejected states
            ports = [21, 22, 23, 25, 31337]
            for k, p in enumerate(ports):
                st = "REJ" if p != 31337 else "SF"
                events.append(make_conn_event(s_time + timedelta(seconds=k * 10), src_ip, dst_ip, 46000 + (i * 10) + k, p, state=st, duration_s=0.01))
            name = f"Reconnaissance Port Sweep Sequence #{s_id_num}"
            desc = "Sequential probing of standard service ports and suspicious backdoor port."
        elif cat_name == "repeated_rejected":
            # 6 rejected connections (exceeding threshold of 5)
            for k in range(6):
                events.append(make_conn_event(s_time + timedelta(seconds=k * 15), src_ip, dst_ip, 47000 + (i * 10) + k, 22, state="REJ", duration_s=0.001))
            name = f"Repeated Rejected Connection Probing #{s_id_num}"
            desc = "6 consecutive connection rejections to destination host."
        elif cat_name == "suspicious_http":
            # 4 requests to sensitive paths (exceeding threshold of 3)
            paths = ["/.env", "/admin/config", "/wp-admin/setup.php", "/config/database.yml"]
            for k, path in enumerate(paths):
                events.append(make_http_event(s_time + timedelta(seconds=k * 10), src_ip, dst_ip, 48000 + (i * 10) + k, 80, method="GET", uri=path, status=403))
            name = f"Zeek Sensitive Path Reconnaissance #{s_id_num}"
            desc = "Multiple probes targeting sensitive configuration and admin endpoints."
        elif cat_name == "dns_anomaly":
            # 4 NXDOMAIN DNS queries (exceeding threshold of 3)
            dga_domains = [f"dga-{k}-{i}.malicious-c2.invalid" for k in range(4)]
            for k, domain in enumerate(dga_domains):
                events.append(make_dns_event(s_time + timedelta(seconds=k * 8), src_ip, "10.0.0.53", 52000 + (i * 10) + k, 53, query=domain, rcode="NXDOMAIN", answers=""))
            name = f"DGA NXDOMAIN DNS Resolution Anomaly #{s_id_num}"
            desc = "Multiple failed DNS resolutions for algorithmic C2 domains."

        scenario_obj = {
            "scenario_id": f"NET-SCEN-{split[:3].upper()}-{s_id_num:03d}",
            "scenario_version": "v1.0",
            "split": split,
            "ground_truth": g_truth,
            "attack_category": cat_name.replace("_", " ").title(),
            "name": name,
            "description": desc,
            "source": "zeek_telemetry",
            "timestamp": s_time.isoformat(),
            "expected_detection": exp_detect,
            "expected_severity": exp_sev,
            "difficulty": "benign_baseline" if g_truth == "BENIGN" else "controlled_attack",
            "mitre_technique": mitre,
            "events_count": len(events),
            "events": events,
        }
        scenarios.append(scenario_obj)

    # -------------------------------------------------------------
    # Output and Partition Writing
    # -------------------------------------------------------------
    out_dir = Path(__file__).resolve().parent / "datasets" / "network_v1"
    out_dir.mkdir(parents=True, exist_ok=True)

    dev_scenarios = [s for s in scenarios if s["split"] == "development"]
    val_scenarios = [s for s in scenarios if s["split"] == "validation"]
    test_scenarios = [s for s in scenarios if s["split"] == "test"]

    def write_json(path, data):
        content = json.dumps(data, indent=2)
        path.write_text(content, encoding="utf-8")
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    full_sha = write_json(out_dir / "network_v1.json", scenarios)
    dev_sha = write_json(out_dir / "dev_set.json", dev_scenarios)
    val_sha = write_json(out_dir / "val_set.json", val_scenarios)
    test_sha = write_json(out_dir / "test_set.json", test_scenarios)

    manifest = {
        "dataset_name": "RESEARCH_NETWORK_DATASET_V1",
        "dataset_version": "v1.0",
        "created_at": datetime.now(UTC).isoformat(),
        "total_scenarios": len(scenarios),
        "attack_count": sum(1 for s in scenarios if s["ground_truth"] == "ATTACK"),
        "benign_count": sum(1 for s in scenarios if s["ground_truth"] == "BENIGN"),
        "total_telemetry_events": sum(s["events_count"] for s in scenarios),
        "split_distribution": {
            "development": {
                "total": len(dev_scenarios),
                "attack": sum(1 for s in dev_scenarios if s["ground_truth"] == "ATTACK"),
                "benign": sum(1 for s in dev_scenarios if s["ground_truth"] == "BENIGN"),
                "sha256": dev_sha,
            },
            "validation": {
                "total": len(val_scenarios),
                "attack": sum(1 for s in val_scenarios if s["ground_truth"] == "ATTACK"),
                "benign": sum(1 for s in val_scenarios if s["ground_truth"] == "BENIGN"),
                "sha256": val_sha,
            },
            "test": {
                "total": len(test_scenarios),
                "attack": sum(1 for s in test_scenarios if s["ground_truth"] == "ATTACK"),
                "benign": sum(1 for s in test_scenarios if s["ground_truth"] == "BENIGN"),
                "sha256": test_sha,
                "status": "HELD_OUT_UNTOUCHED",
            },
        },
        "full_dataset_sha256": full_sha,
    }
    write_json(out_dir / "network_v1_manifest.json", manifest)

    print("=== NETWORK V1 BENCHMARK DATASET GENERATED ===")
    print(f"Total scenarios: {len(scenarios)}")
    print(f"  Dev split: {len(dev_scenarios)} (Attack: {manifest['split_distribution']['development']['attack']}, Benign: {manifest['split_distribution']['development']['benign']})")
    print(f"  Val split: {len(val_scenarios)} (Attack: {manifest['split_distribution']['validation']['attack']}, Benign: {manifest['split_distribution']['validation']['benign']})")
    print(f"  Test split: {len(test_scenarios)} (Attack: {manifest['split_distribution']['test']['attack']}, Benign: {manifest['split_distribution']['test']['benign']}) [UNTOUCHED]")
    print(f"Full Dataset SHA-256: {full_sha}")


if __name__ == "__main__":
    generate_network_dataset()
