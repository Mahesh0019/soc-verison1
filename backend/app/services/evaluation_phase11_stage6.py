"""
backend/app/services/evaluation_phase11_stage6.py

Phase 11 Stage 6: Offline Distributed-Activity and Identity-Aware Detection Evaluation Engine.
Evaluates 24 versioned scenarios partitioned into:
- Development Set (8 scenarios: 4 benign, 4 attack)
- Validation Set (8 scenarios: 4 benign, 4 attack)
- Held-Out Test Set (8 scenarios: 4 benign, 4 attack)

Compares 5 isolated configurations:
1. Baseline Sequential (Production Builtin Rules)
2. Candidate Source-IP Dual-Threshold (Stage 5 Architecture)
3. Candidate Identity-Aware (Per-User Thresholding + Unauthenticated Fallback)
4. Candidate Endpoint-Aggregate (Cross-Source Sensitive Endpoint Aggregation)
5. Candidate Hybrid Integrated (Multi-Layer Identity + Endpoint + IP + Correlation)
"""

from __future__ import annotations

import copy
import json
import platform
import random
import statistics
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.database.base import Base
from app.models import (
    Alert,
    AlertEvent,
    DetectionRule,
    Evidence,
    Incident,
    IncidentAlert,
    NormalizedEvent,
    ThreatIndicator,
)
from app.rules.builtin import builtin_rules
from app.rules.correlation import correlate_incidents
from app.rules.engine import evaluate_rules_for_events
from app.services.evaluation_phase11 import (
    LabeledScenario,
    ScenarioEvent,
)
from app.services.evidence_service import build_evidence_package
from app.services.seed import ensure_builtin_rules, ensure_indicators


# ---------------------------------------------------------------------------
# Stage 6 Development Scenarios (8 Scenarios: 4 Benign, 4 Attack)
# ---------------------------------------------------------------------------

def generate_stg6_dev_01() -> LabeledScenario:
    """STG6-DEV-01: Corporate NAT - 3 Benign Authenticated Users (75 total reqs)"""
    ip = "203.0.113.10"
    events: List[ScenarioEvent] = []
    users = ["alice", "bob", "charlie"]
    for u_idx, user in enumerate(users):
        for i in range(25):
            events.append(
                ScenarioEvent(
                    offset_seconds=i * 11.0 + (u_idx * 3.0),
                    source_ip=ip,
                    method="GET",
                    path=f"/rest/products/{i}",
                    username=user,
                    user_agent=f"Mozilla/5.0 ({user}-workstation)",
                )
            )
    events.sort(key=lambda e: e.offset_seconds)
    return LabeledScenario(
        scenario_id="STG6-DEV-01",
        name="Corporate NAT - 3 Benign Users (75 reqs total)",
        category="benign",
        duration_seconds=300.0,
        description="3 legitimate users sharing public gateway IP 203.0.113.10, sending 25 reqs each. Must NOT alert under identity-aware rules.",
        expected_rule_ids=[],
        should_alert=False,
        events=events,
    )


def generate_stg6_dev_02() -> LabeledScenario:
    """STG6-DEV-02: Noisy Attacker Behind Corporate NAT (105 total reqs)"""
    ip = "203.0.113.10"
    events: List[ScenarioEvent] = []
    # Benign users: alice (15), bob (15)
    for i in range(15):
        events.append(ScenarioEvent(offset_seconds=i * 18.0, source_ip=ip, method="GET", path=f"/rest/products/{i}", username="alice"))
        events.append(ScenarioEvent(offset_seconds=i * 18.0 + 5.0, source_ip=ip, method="GET", path=f"/rest/basket/{i}", username="bob"))
    # Malicious user: mallory (75 aggressive scraping requests)
    for i in range(75):
        events.append(ScenarioEvent(offset_seconds=i * 3.5, source_ip=ip, method="GET", path=f"/rest/products/{i}", username="mallory"))
    events.sort(key=lambda e: e.offset_seconds)
    return LabeledScenario(
        scenario_id="STG6-DEV-02",
        name="Noisy Attacker Behind Corporate NAT (mallory 75 reqs)",
        category="attack",
        duration_seconds=280.0,
        description="Malicious user mallory behind NAT sends 75 requests exceeding threshold 60, alongside benign peers. MUST alert on mallory.",
        expected_rule_ids=["RULE-008-USER", "RULE-008"],
        should_alert=True,
        events=events,
    )


def generate_stg6_dev_03() -> LabeledScenario:
    """STG6-DEV-03: Distributed Botnet Product Scraper (5 IPs, 125 total reqs)"""
    events: List[ScenarioEvent] = []
    for ip_idx in range(1, 6):
        ip = f"198.51.100.{10 + ip_idx}"
        for i in range(25):
            events.append(
                ScenarioEvent(
                    offset_seconds=i * 10.0 + ip_idx,
                    source_ip=ip,
                    method="GET",
                    path=f"/rest/products/search?q=item_{i}",
                    username=None,  # Unauthenticated public search
                    user_agent=f"BotScraper/1.0 (node-{ip_idx})",
                )
            )
    events.sort(key=lambda e: e.offset_seconds)
    return LabeledScenario(
        scenario_id="STG6-DEV-03",
        name="Distributed Botnet Scraper (5 IPs, 125 reqs to /rest/products)",
        category="attack",
        duration_seconds=270.0,
        description="5 botnet nodes scraping /rest/products, each sending 25 reqs (<60). Aggregate endpoint volume = 125. MUST alert under endpoint aggregation.",
        expected_rule_ids=["RULE-015"],
        should_alert=True,
        events=events,
    )


def generate_stg6_dev_04() -> LabeledScenario:
    """STG6-DEV-04: Synchronized Benign Polling Burst (4 Clients, 120 socket reqs)"""
    events: List[ScenarioEvent] = []
    for client_idx in range(1, 5):
        ip = f"198.51.100.{20 + client_idx}"
        for i in range(30):
            events.append(
                ScenarioEvent(
                    offset_seconds=i * 9.0 + (client_idx * 0.5),
                    source_ip=ip,
                    method="GET",
                    path=f"/health/socket.io/?EIO=4&transport=polling&t={i}",
                    username=None,
                    status_code=200,
                )
            )
    events.sort(key=lambda e: e.offset_seconds)
    return LabeledScenario(
        scenario_id="STG6-DEV-04",
        name="Synchronized Polling Burst (4 Clients, 120 socket reqs)",
        category="benign",
        duration_seconds=280.0,
        description="4 legitimate web app clients polling Socket.IO simultaneously. Must NOT alert on volumetric attack.",
        expected_rule_ids=[],
        should_alert=False,
        events=events,
    )


def generate_stg6_dev_05() -> LabeledScenario:
    """STG6-DEV-05: Anonymous Public API Browsing (45 reqs, username=None)"""
    ip = "198.51.100.31"
    events = [
        ScenarioEvent(offset_seconds=i * 6.2, source_ip=ip, method="GET", path=f"/rest/products/{i}", username=None)
        for i in range(45)
    ]
    return LabeledScenario(
        scenario_id="STG6-DEV-05",
        name="Anonymous Public API Browsing (45 reqs, no identity)",
        category="benign",
        duration_seconds=290.0,
        description="Benign unauthenticated user browsing public store (username=None). Tests missing identity handling. Must NOT alert.",
        expected_rule_ids=[],
        should_alert=False,
        events=events,
    )


def generate_stg6_dev_06() -> LabeledScenario:
    """STG6-DEV-06: Spoofed User-Agent Scraper (80 reqs rotating UA)"""
    ip = "198.51.100.32"
    uas = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15",
        "curl/8.4.0",
    ]
    events = [
        ScenarioEvent(
            offset_seconds=i * 2.5,
            source_ip=ip,
            method="GET",
            path=f"/rest/products/{i}",
            username=None,
            user_agent=uas[i % len(uas)],
        )
        for i in range(80)
    ]
    return LabeledScenario(
        scenario_id="STG6-DEV-06",
        name="Spoofed User-Agent Scraper (80 reqs, randomized UA)",
        category="attack",
        duration_seconds=210.0,
        description="Attacker scraping API while rotating User-Agent headers to evade fingerprinting. Must alert on source-IP threshold.",
        expected_rule_ids=["RULE-008"],
        should_alert=True,
        events=events,
    )


def generate_stg6_dev_07() -> LabeledScenario:
    """STG6-DEV-07: Sensitive Endpoint Brute Force on Login (3 IPs, 45 login POSTs)"""
    events: List[ScenarioEvent] = []
    for ip_idx in range(1, 4):
        ip = f"198.51.100.{40 + ip_idx}"
        for i in range(15):
            events.append(
                ScenarioEvent(
                    offset_seconds=i * 15.0 + ip_idx,
                    source_ip=ip,
                    method="POST",
                    path="/rest/user/login",
                    username="admin",
                    event_type="failed_login",
                    status_code=401,
                )
            )
    events.sort(key=lambda e: e.offset_seconds)
    return LabeledScenario(
        scenario_id="STG6-DEV-07",
        name="Sensitive Endpoint Brute Force on Login (3 IPs, 45 POSTs)",
        category="attack",
        duration_seconds=240.0,
        description="Distributed login brute force across 3 IPs targeting admin account. Handled by authentication and endpoint rules.",
        expected_rule_ids=["RULE-001"],
        should_alert=True,
        events=events,
    )


def generate_stg6_dev_08() -> LabeledScenario:
    """STG6-DEV-08: Flash Crowd Product Launch (10 IPs, 80 total reqs)"""
    events: List[ScenarioEvent] = []
    for ip_idx in range(1, 11):
        ip = f"198.51.100.{50 + ip_idx}"
        for i in range(8):
            events.append(
                ScenarioEvent(
                    offset_seconds=i * 30.0 + ip_idx,
                    source_ip=ip,
                    method="GET",
                    path=f"/rest/products/{i}",
                    username=f"shopper_{ip_idx}",
                )
            )
    events.sort(key=lambda e: e.offset_seconds)
    return LabeledScenario(
        scenario_id="STG6-DEV-08",
        name="Flash Crowd Product Launch (10 IPs, 80 reqs total)",
        category="benign",
        duration_seconds=260.0,
        description="10 independent legitimate shoppers browsing product catalog concurrently. Must NOT alert.",
        expected_rule_ids=[],
        should_alert=False,
        events=events,
    )


# ---------------------------------------------------------------------------
# Stage 6 Validation Scenarios (8 Scenarios: 4 Benign, 4 Attack)
# ---------------------------------------------------------------------------

def generate_stg6_val_01() -> LabeledScenario:
    """STG6-VAL-01: Corporate NAT - 4 Benign Workstation Sessions (80 total reqs)"""
    ip = "203.0.113.20"
    events: List[ScenarioEvent] = []
    users = ["dev1", "dev2", "dev3", "dev4"]
    for u_idx, user in enumerate(users):
        for i in range(20):
            events.append(
                ScenarioEvent(
                    offset_seconds=i * 12.0 + (u_idx * 2.5),
                    source_ip=ip,
                    method="GET",
                    path=f"/rest/products/{i}",
                    username=user,
                )
            )
    events.sort(key=lambda e: e.offset_seconds)
    return LabeledScenario(
        scenario_id="STG6-VAL-01",
        name="Corporate NAT - 4 Benign Sessions (80 reqs total)",
        category="benign",
        duration_seconds=270.0,
        description="4 legitimate workstations behind 203.0.113.20 sending 20 reqs each. Must NOT alert under identity-aware candidate.",
        expected_rule_ids=[],
        should_alert=False,
        events=events,
    )


def generate_stg6_val_02() -> LabeledScenario:
    """STG6-VAL-02: Compromised Account Behind Corporate NAT (90 reqs on victim_acc)"""
    ip = "203.0.113.20"
    events: List[ScenarioEvent] = []
    # 2 benign coworkers (15 reqs each)
    for i in range(15):
        events.append(ScenarioEvent(offset_seconds=i * 18.0, source_ip=ip, method="GET", path=f"/rest/products/{i}", username="worker1"))
        events.append(ScenarioEvent(offset_seconds=i * 18.0 + 4.0, source_ip=ip, method="GET", path=f"/rest/basket/{i}", username="worker2"))
    # Compromised account: victim_acc (90 rapid API requests)
    for i in range(90):
        events.append(ScenarioEvent(offset_seconds=i * 2.8, source_ip=ip, method="GET", path=f"/rest/products/export/{i}", username="victim_acc"))
    events.sort(key=lambda e: e.offset_seconds)
    return LabeledScenario(
        scenario_id="STG6-VAL-02",
        name="Compromised Account Behind NAT (victim_acc 90 reqs)",
        category="attack",
        duration_seconds=260.0,
        description="Compromised account dumping product records from within corporate NAT. MUST alert on victim_acc.",
        expected_rule_ids=["RULE-008-USER", "RULE-008"],
        should_alert=True,
        events=events,
    )


def generate_stg6_val_03() -> LabeledScenario:
    """STG6-VAL-03: Distributed Botnet Scraper (8 IPs, 160 total reqs)"""
    events: List[ScenarioEvent] = []
    for ip_idx in range(1, 9):
        ip = f"198.51.100.{60 + ip_idx}"
        for i in range(20):
            events.append(
                ScenarioEvent(
                    offset_seconds=i * 12.0 + ip_idx,
                    source_ip=ip,
                    method="GET",
                    path=f"/rest/products/items/{i}",
                    username=None,
                )
            )
    events.sort(key=lambda e: e.offset_seconds)
    return LabeledScenario(
        scenario_id="STG6-VAL-03",
        name="Distributed Botnet Scraper (8 IPs, 160 reqs to /rest/products)",
        category="attack",
        duration_seconds=260.0,
        description="8 botnet nodes scraping /rest/products items (20 reqs each). Aggregate volume = 160. MUST alert on endpoint aggregation.",
        expected_rule_ids=["RULE-015"],
        should_alert=True,
        events=events,
    )


def generate_stg6_val_04() -> LabeledScenario:
    """STG6-VAL-04: Scheduled Dashboard Telemetry Polling (50 socket reqs)"""
    ip = "198.51.100.70"
    events = [
        ScenarioEvent(
            offset_seconds=i * 5.5,
            source_ip=ip,
            method="GET",
            path=f"/health/socket.io/?EIO=4&transport=polling&t={i}",
            username="ops-dashboard",
        )
        for i in range(50)
    ]
    return LabeledScenario(
        scenario_id="STG6-VAL-04",
        name="Scheduled Dashboard Polling (50 socket reqs)",
        category="benign",
        duration_seconds=280.0,
        description="Internal ops dashboard polling status over Socket.IO. Must NOT alert.",
        expected_rule_ids=[],
        should_alert=False,
        events=events,
    )


def generate_stg6_val_05() -> LabeledScenario:
    """STG6-VAL-05: Unauthenticated Traversal Flood with Missing Identity (70 reqs)"""
    ip = "198.51.100.71"
    events = [
        ScenarioEvent(
            offset_seconds=i * 3.5,
            source_ip=ip,
            method="GET",
            path=f"/%61ssets/../rest/admin/cfg_{i}",
            username=None,
            status_code=403,
        )
        for i in range(70)
    ]
    return LabeledScenario(
        scenario_id="STG6-VAL-05",
        name="Unauthenticated Traversal Flood (70 reqs, username=None)",
        category="attack",
        duration_seconds=250.0,
        description="Attacker executing path traversal flood without authentication. Path normalization strips traversal. Must alert.",
        expected_rule_ids=["RULE-008", "RULE-006"],
        should_alert=True,
        events=events,
    )


def generate_stg6_val_06() -> LabeledScenario:
    """STG6-VAL-06: Rotated Header Identity Spoofing (75 reqs, fake_user_x)"""
    ip = "198.51.100.72"
    events = [
        ScenarioEvent(
            offset_seconds=i * 2.8,
            source_ip=ip,
            method="GET",
            path=f"/rest/products/{i}",
            username=f"fake_user_{i}",  # Attacker rotating client-supplied header
        )
        for i in range(75)
    ]
    return LabeledScenario(
        scenario_id="STG6-VAL-06",
        name="Rotated Header Identity Spoofing (75 reqs, fake usernames)",
        category="attack",
        duration_seconds=220.0,
        description="Attacker rotating forged username headers to evade per-user thresholding. Must alert on source-IP fallback.",
        expected_rule_ids=["RULE-008"],
        should_alert=True,
        events=events,
    )


def generate_stg6_val_07() -> LabeledScenario:
    """STG6-VAL-07: Distributed Multi-Stage Probing (4 IPs, 24 sensitive probes)"""
    events: List[ScenarioEvent] = []
    paths = ["/admin", "/.env", "/wp-admin", "/config"]
    for ip_idx in range(1, 5):
        ip = f"198.51.100.{80 + ip_idx}"
        for i in range(6):
            events.append(
                ScenarioEvent(
                    offset_seconds=i * 35.0 + ip_idx,
                    source_ip=ip,
                    method="GET",
                    path=paths[i % len(paths)],
                    status_code=404,
                )
            )
    events.sort(key=lambda e: e.offset_seconds)
    return LabeledScenario(
        scenario_id="STG6-VAL-07",
        name="Distributed Multi-Stage Probing (4 IPs, 24 sensitive probes)",
        category="attack",
        duration_seconds=240.0,
        description="4 coordinated IPs probing sensitive paths (.env, admin). Handled by sensitive path and reconnaissance rules.",
        expected_rule_ids=["RULE-007"],
        should_alert=True,
        events=events,
    )


def generate_stg6_val_08() -> LabeledScenario:
    """STG6-VAL-08: Mobile App Concurrent Preloading (55 asset & product reqs)"""
    ip = "198.51.100.85"
    events = [
        ScenarioEvent(
            offset_seconds=i * 3.2,
            source_ip=ip,
            method="GET",
            path=f"/assets/icons/cat_{i % 10}.png" if i % 2 == 0 else f"/rest/products/{i}",
            username="mobile_user",
        )
        for i in range(55)
    ]
    return LabeledScenario(
        scenario_id="STG6-VAL-08",
        name="Mobile App Concurrent Preloading (55 asset/product reqs)",
        category="benign",
        duration_seconds=180.0,
        description="Legitimate mobile app preloading catalog assets on cold start. Must NOT alert.",
        expected_rule_ids=[],
        should_alert=False,
        events=events,
    )


# ---------------------------------------------------------------------------
# Stage 6 Held-Out Test Scenarios (8 Scenarios: 4 Benign, 4 Attack)
# Strictly held-out; zero threshold tuning performed on this set.
# ---------------------------------------------------------------------------

def generate_stg6_test_01() -> LabeledScenario:
    """STG6-TEST-01: Enterprise Office Gateway Multi-User Traffic (5 Users, 110 total reqs)"""
    ip = "203.0.113.30"
    events: List[ScenarioEvent] = []
    users = ["eng1", "eng2", "eng3", "eng4", "eng5"]
    for u_idx, user in enumerate(users):
        for i in range(22):
            events.append(
                ScenarioEvent(
                    offset_seconds=i * 12.0 + (u_idx * 2.0),
                    source_ip=ip,
                    method="GET",
                    path=f"/rest/products/{i}",
                    username=user,
                )
            )
    events.sort(key=lambda e: e.offset_seconds)
    return LabeledScenario(
        scenario_id="STG6-TEST-01",
        name="Enterprise Gateway Traffic (5 Users, 110 reqs total)",
        category="benign",
        duration_seconds=280.0,
        description="Held-out validation: 5 engineers sharing enterprise proxy IP. Total reqs = 110, but each user = 22 (<60). Must NOT alert under identity-aware rules.",
        expected_rule_ids=[],
        should_alert=False,
        events=events,
    )


def generate_stg6_test_02() -> LabeledScenario:
    """STG6-TEST-02: Rogue Insider Volumetric Data Exfiltration Behind NAT (85 reqs)"""
    ip = "203.0.113.30"
    events: List[ScenarioEvent] = []
    # 4 normal coworkers (10 reqs each)
    for u_idx in range(1, 5):
        for i in range(10):
            events.append(ScenarioEvent(offset_seconds=i * 25.0 + u_idx, source_ip=ip, method="GET", path=f"/rest/products/{i}", username=f"eng{u_idx}"))
    # Rogue insider: insider_threat (85 bulk export API requests in 3 minutes)
    for i in range(85):
        events.append(ScenarioEvent(offset_seconds=i * 2.1, source_ip=ip, method="GET", path=f"/rest/products/dump/{i}", username="insider_threat"))
    events.sort(key=lambda e: e.offset_seconds)
    return LabeledScenario(
        scenario_id="STG6-TEST-02",
        name="Rogue Insider Exfiltration Behind NAT (insider_threat 85 reqs)",
        category="attack",
        duration_seconds=200.0,
        description="Held-out validation: Malicious insider executing automated API data dump. MUST alert on insider_threat.",
        expected_rule_ids=["RULE-008-USER", "RULE-008"],
        should_alert=True,
        events=events,
    )


def generate_stg6_test_03() -> LabeledScenario:
    """STG6-TEST-03: Distributed Low-and-Slow Botnet (10 IPs, 180 total reqs)"""
    events: List[ScenarioEvent] = []
    for ip_idx in range(1, 11):
        ip = f"198.51.100.{90 + ip_idx}"
        for i in range(18):
            events.append(
                ScenarioEvent(
                    offset_seconds=i * 15.0 + ip_idx,
                    source_ip=ip,
                    method="GET",
                    path=f"/rest/products/reviews/{i}",
                    username=None,
                )
            )
    events.sort(key=lambda e: e.offset_seconds)
    return LabeledScenario(
        scenario_id="STG6-TEST-03",
        name="Distributed Low-and-Slow Botnet (10 IPs, 180 reqs to /rest/products)",
        category="attack",
        duration_seconds=280.0,
        description="Held-out validation: 10 botnet nodes scraping /rest/products (18 reqs/IP, well under 60). Endpoint total = 180. MUST alert on endpoint aggregation.",
        expected_rule_ids=["RULE-015"],
        should_alert=True,
        events=events,
    )


def generate_stg6_test_04() -> LabeledScenario:
    """STG6-TEST-04: Synchronized Asset Preload on Tab Re-focus (48 reqs)"""
    ip = "198.51.100.101"
    events = [
        ScenarioEvent(
            offset_seconds=i * 2.2,
            source_ip=ip,
            method="GET",
            path=f"/assets/bundle_{i % 5}.js" if i % 2 == 0 else f"/health/socket.io/?t={i}",
            username="desktop_analyst",
        )
        for i in range(48)
    ]
    return LabeledScenario(
        scenario_id="STG6-TEST-04",
        name="Synchronized Asset Preload (48 asset/socket reqs)",
        category="benign",
        duration_seconds=120.0,
        description="Held-out validation: Legitimate browser re-validating cache assets on tab focus. Must NOT alert.",
        expected_rule_ids=[],
        should_alert=False,
        events=events,
    )


def generate_stg6_test_05() -> LabeledScenario:
    """STG6-TEST-05: Anonymous Distributed Login Spray (5 IPs, 60 total login POSTs)"""
    events: List[ScenarioEvent] = []
    for ip_idx in range(1, 6):
        ip = f"198.51.100.{101 + ip_idx}"
        for i in range(12):
            events.append(
                ScenarioEvent(
                    offset_seconds=i * 20.0 + ip_idx,
                    source_ip=ip,
                    method="POST",
                    path="/rest/user/login",
                    username=None,  # Missing identity in unauthenticated spray
                    event_type="failed_login",
                    status_code=401,
                )
            )
    events.sort(key=lambda e: e.offset_seconds)
    return LabeledScenario(
        scenario_id="STG6-TEST-05",
        name="Anonymous Distributed Login Spray (5 IPs, 60 POSTs)",
        category="attack",
        duration_seconds=250.0,
        description="Held-out validation: 5 IPs spraying credentials on /rest/user/login with username=None in log. Handled by endpoint aggregation.",
        expected_rule_ids=["RULE-015"],
        should_alert=True,
        events=events,
    )


def generate_stg6_test_06() -> LabeledScenario:
    """STG6-TEST-06: Spoofed Mobile User-Agent Fleet Scraping (3 IPs, 95 reqs)"""
    events: List[ScenarioEvent] = []
    mobile_uas = [
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/120.0.6099.43 Mobile Safari/537.36",
        "Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    ]
    for ip_idx in range(1, 4):
        ip = f"198.51.100.{110 + ip_idx}"
        # Node 1 sends 65 reqs (>60), Nodes 2 & 3 send 15 reqs each
        req_count = 65 if ip_idx == 1 else 15
        for i in range(req_count):
            events.append(
                ScenarioEvent(
                    offset_seconds=i * 3.5 + ip_idx,
                    source_ip=ip,
                    method="GET",
                    path=f"/rest/products/items/{i}",
                    username=None,
                    user_agent=mobile_uas[ip_idx - 1],
                )
            )
    events.sort(key=lambda e: e.offset_seconds)
    return LabeledScenario(
        scenario_id="STG6-TEST-06",
        name="Spoofed Mobile UA Fleet (3 IPs, Node 1 = 65 reqs)",
        category="attack",
        duration_seconds=240.0,
        description="Held-out validation: Scraper fleet spoofing mobile browsers. Primary node exceeds 60 reqs. MUST alert on Node 1.",
        expected_rule_ids=["RULE-008"],
        should_alert=True,
        events=events,
    )


def generate_stg6_test_07() -> LabeledScenario:
    """STG6-TEST-07: Distributed Multi-Stage Reconnaissance & Exploit (3 IPs)"""
    events: List[ScenarioEvent] = []
    for ip_idx in range(1, 4):
        ip = f"198.51.100.{120 + ip_idx}"
        # 6 sensitive path probes (404)
        for i in range(6):
            events.append(ScenarioEvent(offset_seconds=i * 20.0, source_ip=ip, method="GET", path=f"/admin/stage_{i}", status_code=404))
        # 2 SQL injection probes
        events.append(ScenarioEvent(offset_seconds=130.0 + ip_idx, source_ip=ip, method="GET", path="/rest/products/search?q=' OR 1=1--", status_code=500))
        events.append(ScenarioEvent(offset_seconds=140.0 + ip_idx, source_ip=ip, method="GET", path="/rest/products/search?q=UNION SELECT", status_code=500))
    events.sort(key=lambda e: e.offset_seconds)
    return LabeledScenario(
        scenario_id="STG6-TEST-07",
        name="Distributed Multi-Stage Recon & SQLi (3 IPs)",
        category="attack",
        duration_seconds=220.0,
        description="Held-out validation: 3 coordinated IPs probing /admin and injecting SQL syntax. Handled by sensitive path & SQLi rules.",
        expected_rule_ids=["RULE-007", "RULE-012"],
        should_alert=True,
        events=events,
    )


def generate_stg6_test_08() -> LabeledScenario:
    """STG6-TEST-08: Distributed Public Search Engine Indexing (3 Crawlers, 45 total reqs)"""
    events: List[ScenarioEvent] = []
    for ip_idx in range(1, 4):
        ip = f"198.51.100.{130 + ip_idx}"
        for i in range(15):
            events.append(
                ScenarioEvent(
                    offset_seconds=i * 18.0 + ip_idx,
                    source_ip=ip,
                    method="GET",
                    path=f"/rest/products/{i}",
                    user_agent="Googlebot/2.1 (+http://www.google.com/bot.html)",
                )
            )
    events.sort(key=lambda e: e.offset_seconds)
    return LabeledScenario(
        scenario_id="STG6-TEST-08",
        name="Distributed Search Engine Indexing (3 Crawlers, 45 reqs)",
        category="benign",
        duration_seconds=280.0,
        description="Held-out validation: 3 search engine crawler nodes politely fetching public product pages. Must NOT alert.",
        expected_rule_ids=[],
        should_alert=False,
        events=events,
    )


# ---------------------------------------------------------------------------
# Partition Accessors
# ---------------------------------------------------------------------------

def get_stage6_dev_scenarios() -> List[LabeledScenario]:
    return [
        generate_stg6_dev_01(),
        generate_stg6_dev_02(),
        generate_stg6_dev_03(),
        generate_stg6_dev_04(),
        generate_stg6_dev_05(),
        generate_stg6_dev_06(),
        generate_stg6_dev_07(),
        generate_stg6_dev_08(),
    ]


def get_stage6_val_scenarios() -> List[LabeledScenario]:
    return [
        generate_stg6_val_01(),
        generate_stg6_val_02(),
        generate_stg6_val_03(),
        generate_stg6_val_04(),
        generate_stg6_val_05(),
        generate_stg6_val_06(),
        generate_stg6_val_07(),
        generate_stg6_val_08(),
    ]


def get_stage6_test_scenarios() -> List[LabeledScenario]:
    return [
        generate_stg6_test_01(),
        generate_stg6_test_02(),
        generate_stg6_test_03(),
        generate_stg6_test_04(),
        generate_stg6_test_05(),
        generate_stg6_test_06(),
        generate_stg6_test_07(),
        generate_stg6_test_08(),
    ]


def get_all_stage6_scenarios() -> List[LabeledScenario]:
    return get_stage6_dev_scenarios() + get_stage6_val_scenarios() + get_stage6_test_scenarios()


# ---------------------------------------------------------------------------
# Rule Configurations for Stage 6
# ---------------------------------------------------------------------------

def build_stage6_rules(config_name: str) -> List[dict[str, Any]]:
    raw_rules = copy.deepcopy(builtin_rules())

    if config_name == "baseline":
        # Production Builtin Rules Unmodified
        return raw_rules

    if config_name == "candidate_source_ip_dual":
        # Stage 5 Dual-Threshold: RULE-008 (60) + RULE-008B (110)
        for r in raw_rules:
            if r["rule_id"] == "RULE-008":
                r["conditions_json"]["filters"]["request_path_not_contains_any"] = [
                    "/socket.io", "/assets/", "/media/"
                ]
        companion_rule = {
            "rule_id": "RULE-008B",
            "name": "Excessive request volume on socket/asset endpoints",
            "description": "Detects high-rate volumetric flooding targeting Socket.IO or static assets indicative of connection pool DoS.",
            "category": "traffic_anomaly",
            "severity": "medium",
            "version": "1.0",
            "status": "ACTIVE",
            "source": "candidate_stage6",
            "owner": "secops-team",
            "mitre_technique": "T1499.001",
            "confidence": 0.70,
            "false_positive_notes": "High concurrency CDN cache warming or massive parallel asset preloading.",
            "expected_data_source": "web_telemetry",
            "enabled": True,
            "conditions_json": {
                "type": "threshold",
                "filters": {
                    "event_category": "web",
                    "request_path_contains_any": ["/socket.io", "/assets/", "/media/"],
                },
                "group_by": ["source_ip"],
            },
            "time_window_minutes": 5,
            "threshold": 110,
        }
        raw_rules.append(companion_rule)
        return raw_rules

    if config_name == "candidate_identity_aware":
        # Pure Isolated Identity-Aware Grouping: volumetric rules group strictly by username
        rules: List[dict[str, Any]] = []
        for r in raw_rules:
            if r["rule_id"] == "RULE-008":
                r["name"] = "Excessive request volume from authenticated user identity"
                r["description"] = "Detects high-rate volumetric activity grouped by authenticated username."
                r["conditions_json"]["filters"]["request_path_not_contains_any"] = [
                    "/socket.io", "/assets/", "/media/"
                ]
                r["conditions_json"]["group_by"] = ["username"]
            rules.append(r)
        companion_rule = {
            "rule_id": "RULE-008B",
            "name": "Excessive request volume on socket/asset endpoints",
            "description": "Detects high-rate volumetric flooding targeting Socket.IO or static assets.",
            "category": "traffic_anomaly",
            "severity": "medium",
            "version": "1.0",
            "status": "ACTIVE",
            "source": "candidate_stage6",
            "owner": "secops-team",
            "mitre_technique": "T1499.001",
            "confidence": 0.70,
            "expected_data_source": "web_telemetry",
            "enabled": True,
            "conditions_json": {
                "type": "threshold",
                "filters": {
                    "event_category": "web",
                    "request_path_contains_any": ["/socket.io", "/assets/", "/media/"],
                },
                "group_by": ["username"],
            },
            "time_window_minutes": 5,
            "threshold": 110,
        }
        rules.append(companion_rule)
        return rules

    if config_name == "candidate_endpoint_aggregate":
        # Endpoint-Level Aggregation: RULE-015 aggregates across all source IPs on sensitive paths
        for r in raw_rules:
            if r["rule_id"] == "RULE-008":
                r["conditions_json"]["filters"]["request_path_not_contains_any"] = [
                    "/socket.io", "/assets/", "/media/"
                ]
        endpoint_rule = {
            "rule_id": "RULE-015",
            "name": "Endpoint volumetric surge across distributed sources",
            "description": "Detects coordinated multi-source volumetric bursts targeting sensitive REST endpoints.",
            "category": "traffic_anomaly",
            "severity": "high",
            "version": "1.0",
            "status": "ACTIVE",
            "source": "candidate_stage6",
            "owner": "secops-team",
            "mitre_technique": "T1499.001",
            "confidence": 0.80,
            "false_positive_notes": "Marketing campaign flash crowd or massive unannounced promotion.",
            "expected_data_source": "web_telemetry",
            "enabled": True,
            "conditions_json": {
                "type": "threshold",
                "filters": {
                    "event_category": "web",
                    "request_path_contains_any": ["/rest/products", "/rest/user/login"],
                },
                "group_by": ["event_category"],
            },
            "time_window_minutes": 5,
            "threshold": 100,
        }
        companion_rule = {
            "rule_id": "RULE-008B",
            "name": "Excessive request volume on socket/asset endpoints",
            "description": "Detects high-rate volumetric flooding targeting Socket.IO or static assets.",
            "category": "traffic_anomaly",
            "severity": "medium",
            "version": "1.0",
            "status": "ACTIVE",
            "source": "candidate_stage6",
            "owner": "secops-team",
            "mitre_technique": "T1499.001",
            "confidence": 0.70,
            "expected_data_source": "web_telemetry",
            "enabled": True,
            "conditions_json": {
                "type": "threshold",
                "filters": {
                    "event_category": "web",
                    "request_path_contains_any": ["/socket.io", "/assets/", "/media/"],
                },
                "group_by": ["source_ip"],
            },
            "time_window_minutes": 5,
            "threshold": 110,
        }
        raw_rules.extend([endpoint_rule, companion_rule])
        return raw_rules

    if config_name == "candidate_hybrid_integrated":
        # Hybrid Multi-Layer: Dual-threshold IP + Identity (RULE-008-USER) + Endpoint Aggregation (RULE-015)
        for r in raw_rules:
            if r["rule_id"] == "RULE-008":
                r["conditions_json"]["filters"]["request_path_not_contains_any"] = [
                    "/socket.io", "/assets/", "/media/"
                ]
        user_rule = {
            "rule_id": "RULE-008-USER",
            "name": "Excessive request volume from authenticated user identity",
            "description": "Detects high-rate volumetric activity grouped by authenticated username across any source IP.",
            "category": "traffic_anomaly",
            "severity": "medium",
            "version": "1.0",
            "status": "ACTIVE",
            "source": "candidate_stage6",
            "owner": "secops-team",
            "mitre_technique": "T1499.001",
            "confidence": 0.85,
            "enabled": True,
            "conditions_json": {
                "type": "threshold",
                "filters": {
                    "event_category": "web",
                    "request_path_not_contains_any": ["/socket.io", "/assets/", "/media/"],
                },
                "group_by": ["username"],
            },
            "time_window_minutes": 5,
            "threshold": 60,
        }
        companion_rule = {
            "rule_id": "RULE-008B",
            "name": "Excessive request volume on socket/asset endpoints",
            "description": "Detects high-rate volumetric flooding targeting Socket.IO or static assets.",
            "category": "traffic_anomaly",
            "severity": "medium",
            "version": "1.0",
            "status": "ACTIVE",
            "source": "candidate_stage6",
            "owner": "secops-team",
            "mitre_technique": "T1499.001",
            "confidence": 0.70,
            "enabled": True,
            "conditions_json": {
                "type": "threshold",
                "filters": {
                    "event_category": "web",
                    "request_path_contains_any": ["/socket.io", "/assets/", "/media/"],
                },
                "group_by": ["source_ip"],
            },
            "time_window_minutes": 5,
            "threshold": 110,
        }
        endpoint_rule = {
            "rule_id": "RULE-015",
            "name": "Endpoint volumetric surge across distributed sources",
            "description": "Detects coordinated multi-source volumetric bursts targeting sensitive REST endpoints.",
            "category": "traffic_anomaly",
            "severity": "high",
            "version": "1.0",
            "status": "ACTIVE",
            "source": "candidate_stage6",
            "owner": "secops-team",
            "mitre_technique": "T1499.001",
            "confidence": 0.80,
            "enabled": True,
            "conditions_json": {
                "type": "threshold",
                "filters": {
                    "event_category": "web",
                    "request_path_contains_any": ["/rest/products", "/rest/user/login"],
                },
                "group_by": ["event_category"],
            },
            "time_window_minutes": 5,
            "threshold": 100,
        }
        raw_rules.extend([user_rule, companion_rule, endpoint_rule])
        return raw_rules

    return raw_rules


# ---------------------------------------------------------------------------
# Stage 6 Evaluation Models & Runner
# ---------------------------------------------------------------------------

@dataclass
class Stage6ScenarioResult:
    scenario_id: str
    name: str
    partition: str  # "dev", "val", "test"
    category: str   # "benign", "attack"
    event_count: int
    duration_seconds: float
    fired_rule_ids: List[str]
    alert_count: int
    incident_count: int
    classification: str  # "TP", "FP", "TN", "FN"
    duplicate_alerts: int
    missed_rule_ids: List[str]
    blind_spot_flag: bool
    median_latency_ms: float
    p95_latency_ms: float
    max_latency_ms: float
    per_event_median_ms: float


@dataclass
class Stage6PartitionScorecard:
    partition_name: str
    total_scenarios: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    false_positive_rate: float
    false_negative_rate: float
    f1_score: float
    total_duplicate_alerts: int
    blind_spots_count: int
    median_latency_ms: float


@dataclass
class Stage6ConfigScorecard:
    configuration_name: str
    description: str
    overall: Stage6PartitionScorecard
    dev_set: Stage6PartitionScorecard
    val_set: Stage6PartitionScorecard
    test_set: Stage6PartitionScorecard
    overall_p95_latency_ms: float
    overall_max_latency_ms: float
    small_batch_median_ms: float
    burst_median_ms: float
    scenario_results: List[Stage6ScenarioResult]


class Stage6AuditRunner:
    def __init__(self, config_name: str = "baseline", use_batched_threshold: bool = True):
        self.config_name = config_name
        self.use_batched_threshold = use_batched_threshold

        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        self.SessionLocal = sessionmaker(
            bind=self.engine, autoflush=False, autocommit=False, expire_on_commit=False
        )
        Base.metadata.create_all(bind=self.engine)
        self._init_rules()

    def _init_rules(self):
        db = self.SessionLocal()
        try:
            db.query(AlertEvent).delete()
            db.query(Alert).delete()
            db.query(DetectionRule).delete()
            db.query(ThreatIndicator).delete()

            rule_defs = build_stage6_rules(self.config_name)
            for idx, item in enumerate(rule_defs, start=1):
                rule = DetectionRule(
                    id=idx,
                    name=item["name"],
                    description=item.get("description", ""),
                    category=item.get("category", "generic"),
                    severity=item.get("severity", "medium"),
                    version=item.get("version", "1.0"),
                    status=item.get("status", "ACTIVE"),
                    source=item.get("source", "builtin"),
                    owner=item.get("owner", "secops"),
                    mitre_technique=item.get("mitre_technique"),
                    confidence=item.get("confidence", 0.7),
                    enabled=item.get("enabled", True),
                    conditions_json=item.get("conditions_json", {}),
                    time_window_minutes=item.get("time_window_minutes", 10),
                    threshold=item.get("threshold", 5),
                )
                db.add(rule)

            ensure_indicators(db)
            db.commit()
        finally:
            db.close()

    def reset_data_tables(self):
        db = self.SessionLocal()
        try:
            db.query(IncidentAlert).delete()
            db.query(Incident).delete()
            db.query(Evidence).delete()
            db.query(AlertEvent).delete()
            db.query(Alert).delete()
            db.query(NormalizedEvent).delete()
            db.commit()
        finally:
            db.close()

    def execute_single_run(
        self, scenario: LabeledScenario, base_time: datetime
    ) -> Tuple[List[Alert], List[Incident], float]:
        self.reset_data_tables()
        db = self.SessionLocal()
        try:
            t0 = time.perf_counter()
            norm_events: List[NormalizedEvent] = []
            for ev in scenario.events:
                evt_time = base_time + timedelta(seconds=ev.offset_seconds)
                ne = NormalizedEvent(
                    timestamp=evt_time,
                    source_ip=ev.source_ip,
                    http_method=ev.method,
                    request_path=ev.path,
                    status_code=ev.status_code,
                    user_agent=ev.user_agent,
                    username=ev.username,
                    event_type=ev.event_type,
                    event_category=ev.event_category,
                    severity=ev.severity,
                    message=ev.message or f"{ev.method} {ev.path}",
                    source_type="WEB",
                )
                db.add(ne)
                norm_events.append(ne)
            db.flush()

            evaluate_rules_for_events(
                db,
                norm_events,
                auto_correlate=False,
                use_batched_threshold=self.use_batched_threshold,
            )
            db.flush()

            alerts = db.query(Alert).all()
            touched_ids = {a.id for a in alerts}

            for alert in alerts:
                build_evidence_package(db, alert)
            db.flush()

            if touched_ids:
                correlate_incidents(db, touched_ids)
                db.flush()

            incidents = db.query(Incident).all()
            total_duration_ms = (time.perf_counter() - t0) * 1000.0
            return alerts, incidents, total_duration_ms
        finally:
            db.close()

    def evaluate_scenario(
        self,
        scenario: LabeledScenario,
        partition: str = "dev",
        measured_runs: int = 5,
    ) -> Stage6ScenarioResult:
        t_ref = datetime(2026, 10, 10, 12, 0, 0, tzinfo=UTC)

        # 1. Warm-up run (discarded)
        self.execute_single_run(scenario, t_ref)

        # 2. Measured runs
        durations: List[float] = []
        final_alerts: List[Alert] = []
        final_incidents: List[Incident] = []

        for _ in range(measured_runs):
            alerts, incidents, dur_ms = self.execute_single_run(scenario, t_ref)
            durations.append(dur_ms)
            final_alerts = alerts
            final_incidents = incidents

        ev_count = max(len(scenario.events), 1)
        med_ms = round(statistics.median(durations), 2)
        sorted_lats = sorted(durations)
        p95_idx = int(len(sorted_lats) * 0.95)
        p95_ms = round(sorted_lats[min(p95_idx, len(sorted_lats) - 1)], 2)
        max_ms = round(max(durations), 2)

        rule_defs = build_stage6_rules(self.config_name)
        seen_keys: Set[Tuple[str, str]] = set()
        duplicates = 0
        fired_rules_set: Set[str] = set()

        for a in final_alerts:
            r_name = a.rule.name if a.rule else f"Rule-{a.rule_id}"
            r_id = f"RULE-{a.rule_id:03d}" if a.rule_id else r_name
            for r_item in rule_defs:
                if r_item["name"] == r_name:
                    r_id = r_item["rule_id"]
                    break
            fired_rules_set.add(r_id)
            key = (r_id, a.source_ip or a.affected_user or "")
            if key in seen_keys:
                duplicates += 1
            seen_keys.add(key)

        fired_rules = sorted(list(fired_rules_set))
        has_alert = len(final_alerts) > 0

        if scenario.category == "attack":
            classification = "TP" if has_alert else "FN"
        else:
            classification = "FP" if has_alert else "TN"

        missed = [r for r in scenario.expected_rule_ids if r not in fired_rules]
        is_blind_spot = (scenario.category == "attack" and classification == "FN")

        return Stage6ScenarioResult(
            scenario_id=scenario.scenario_id,
            name=scenario.name,
            partition=partition,
            category=scenario.category,
            event_count=len(scenario.events),
            duration_seconds=scenario.duration_seconds,
            fired_rule_ids=fired_rules,
            alert_count=len(final_alerts),
            incident_count=len(final_incidents),
            classification=classification,
            duplicate_alerts=duplicates,
            missed_rule_ids=missed,
            blind_spot_flag=is_blind_spot,
            median_latency_ms=med_ms,
            p95_latency_ms=p95_ms,
            max_latency_ms=max_ms,
            per_event_median_ms=round(med_ms / ev_count, 3),
        )


def compute_partition_metrics(name: str, results: List[Stage6ScenarioResult]) -> Stage6PartitionScorecard:
    tp = sum(1 for r in results if r.classification == "TP")
    fp = sum(1 for r in results if r.classification == "FP")
    tn = sum(1 for r in results if r.classification == "TN")
    fn = sum(1 for r in results if r.classification == "FN")
    total = len(results)

    precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
    recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
    fpr = round(fp / (fp + tn), 4) if (fp + tn) > 0 else 0.0
    fnr = round(fn / (tp + fn), 4) if (tp + fn) > 0 else 0.0
    f1 = round(2 * (precision * recall) / (precision + recall), 4) if (precision + recall) > 0 else 0.0
    duplicates = sum(r.duplicate_alerts for r in results)
    blind_spots = sum(1 for r in results if r.blind_spot_flag)
    med_lat = round(statistics.median([r.median_latency_ms for r in results]), 2) if results else 0.0

    return Stage6PartitionScorecard(
        partition_name=name,
        total_scenarios=total,
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        precision=precision,
        recall=recall,
        false_positive_rate=fpr,
        false_negative_rate=fnr,
        f1_score=f1,
        total_duplicate_alerts=duplicates,
        blind_spots_count=blind_spots,
        median_latency_ms=med_lat,
    )


def evaluate_stage6_configuration(
    config_name: str,
    description: str,
    use_batched_threshold: bool = True,
    measured_runs: int = 5,
) -> Stage6ConfigScorecard:
    runner = Stage6AuditRunner(
        config_name=config_name, use_batched_threshold=use_batched_threshold
    )

    dev_scenarios = get_stage6_dev_scenarios()
    val_scenarios = get_stage6_val_scenarios()
    test_scenarios = get_stage6_test_scenarios()

    dev_results = [runner.evaluate_scenario(s, partition="dev", measured_runs=measured_runs) for s in dev_scenarios]
    val_results = [runner.evaluate_scenario(s, partition="val", measured_runs=measured_runs) for s in val_scenarios]
    test_results = [runner.evaluate_scenario(s, partition="test", measured_runs=measured_runs) for s in test_scenarios]

    all_results = dev_results + val_results + test_results

    overall_card = compute_partition_metrics("overall", all_results)
    dev_card = compute_partition_metrics("dev", dev_results)
    val_card = compute_partition_metrics("val", val_results)
    test_card = compute_partition_metrics("test", test_results)

    all_p95s = [r.p95_latency_ms for r in all_results]
    overall_p95 = round(max(all_p95s), 2) if all_p95s else 0.0
    all_maxes = [r.max_latency_ms for r in all_results]
    overall_max = round(max(all_maxes), 2) if all_maxes else 0.0

    small_meds = [r.median_latency_ms for r in all_results if r.event_count <= 25]
    burst_meds = [r.median_latency_ms for r in all_results if r.event_count >= 80]
    small_median = round(statistics.median(small_meds), 2) if small_meds else 0.0
    burst_median = round(statistics.median(burst_meds), 2) if burst_meds else 0.0

    return Stage6ConfigScorecard(
        configuration_name=config_name,
        description=description,
        overall=overall_card,
        dev_set=dev_card,
        val_set=val_card,
        test_set=test_card,
        overall_p95_latency_ms=overall_p95,
        overall_max_latency_ms=overall_max,
        small_batch_median_ms=small_median,
        burst_median_ms=burst_median,
        scenario_results=all_results,
    )


def run_full_stage6_audit_suite() -> Dict[str, Any]:
    """Runs the complete Stage 6 distributed and identity-aware audit benchmark."""
    env_metadata = {
        "platform": platform.platform(),
        "python_version": sys.version,
        "processor": platform.processor(),
        "machine": platform.machine(),
        "sqlite_driver": "sqlite3 / StaticPool",
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "baseline_commit": "d4f884b",
        "frozen_checkpoint": "6a153ae17c676e92b7fc7208b374c2646e99b4f6",
        "total_scenarios_evaluated": 24,
        "partitions": {
            "dev_set": 8,
            "val_set": 8,
            "held_out_test_set": 8,
        },
        "latency_methodology": "1 warm-up run (discarded) + 5 measured runs per scenario",
    }

    # 1. Baseline Sequential (Production Builtin Rules)
    base_seq = evaluate_stage6_configuration(
        config_name="baseline",
        description="Production Builtin Rules (Sequential SQL)",
        use_batched_threshold=False,
        measured_runs=5,
    )

    # 2. Candidate Source-IP Dual-Threshold (Stage 5 Architecture Batched)
    cand_ip = evaluate_stage6_configuration(
        config_name="candidate_source_ip_dual",
        description="Candidate Source-IP Dual-Threshold (RULE-008 60 + RULE-008B 110 Batched)",
        use_batched_threshold=True,
        measured_runs=5,
    )

    # 3. Candidate Identity-Aware Grouping (Batched)
    cand_ident = evaluate_stage6_configuration(
        config_name="candidate_identity_aware",
        description="Candidate Identity-Aware Grouping (Per-User Thresholding + IP Fallback Batched)",
        use_batched_threshold=True,
        measured_runs=5,
    )

    # 4. Candidate Endpoint-Level Aggregation (Batched)
    cand_ep = evaluate_stage6_configuration(
        config_name="candidate_endpoint_aggregate",
        description="Candidate Endpoint-Level Aggregation (RULE-015 Cross-Source Sensitive Endpoint Batched)",
        use_batched_threshold=True,
        measured_runs=5,
    )

    # 5. Candidate Hybrid Integrated Architecture (Batched)
    cand_hybrid = evaluate_stage6_configuration(
        config_name="candidate_hybrid_integrated",
        description="Candidate Hybrid Multi-Layer Architecture (IP + User + Endpoint + Correlation Batched)",
        use_batched_threshold=True,
        measured_runs=5,
    )

    return {
        "metadata": env_metadata,
        "total_scenarios": 24,
        "partitions_summary": {
            "dev": {"total": 8, "benign": 4, "attack": 4},
            "val": {"total": 8, "benign": 4, "attack": 4},
            "held_out_test": {"total": 8, "benign": 4, "attack": 4},
        },
        "configurations": {
            "baseline_sequential": asdict(base_seq),
            "candidate_source_ip_dual": asdict(cand_ip),
            "candidate_identity_aware": asdict(cand_ident),
            "candidate_endpoint_aggregate": asdict(cand_ep),
            "candidate_hybrid_integrated": asdict(cand_hybrid),
        },
    }
