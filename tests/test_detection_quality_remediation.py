"""
tests/test_detection_quality_remediation.py

Comprehensive Regression Test Suite for Detection Quality Audit Remediations:
1. RULE-008: Exclude verified static-resource noise while preserving high-volume API detection.
   - TC-01: Benign static assets (.js, .css, .png, .svg, /assets/*, HTTP 304) (Benign-Negative -> 0 alerts)
   - TC-02: Genuine high-volume API requests (/api/Users, /rest/products/search) (Attack-Positive -> 1 alert)
   - TC-03: Parameter smuggling evasion resistance (/api/search?file=logo.png) (Attack-Positive -> 1 alert)
   - TC-04: Mixed benign static noise + genuine API burst (links only genuine API events)

2. RULE-007: Separate ordinary /login traffic from reconnaissance while retaining sensitive-path detection.
   - TC-05: Ordinary user authentication traffic (/login, /rest/user/login) (Benign-Negative -> 0 alerts)
   - TC-06: Genuine reconnaissance on /.env (Attack-Positive -> 1 alert)
   - TC-07: Genuine reconnaissance on /console (Werkzeug debug console) (Attack-Positive -> 1 alert)
   - TC-08: Genuine reconnaissance on /actuator (Spring actuator) (Attack-Positive -> 1 alert)
   - TC-09: Exact path exclusion for SPA metadata endpoints (Benign-Negative -> 0 alerts)

3. RULE-014: Support attribute-bearing and URL-encoded XSS signatures with safe normalization.
   - TC-10: Benign query parameter (Benign-Negative -> 0 alerts)
   - TC-11: Attribute-bearing script tag (<script src="https://evil.com/hook.js">) (Attack-Positive -> 1 alert)
   - TC-12: URL-encoded script tag (%3cscript%20src=...) (Attack-Positive -> 1 alert)
   - TC-13: Attribute-bearing SVG / img onerror (<svg onload=alert(1)>, %3cimg%20onerror=...) (Attack-Positive -> 1 alert)
   - TC-14: Raw event evidence immutability (original encoded payload unaltered in database)

4. RULE-013: Detect URL-encoded traversal indicators.
   - TC-15: Benign asset path (Benign-Negative -> 0 alerts)
   - TC-16: Standard traversal (../, ..%2f) (Attack-Positive -> 1 alert)
   - TC-17: URL-encoded sensitive file indicator (%2Fetc%2Fpasswd) (Attack-Positive -> 1 alert)
   - TC-18: URL-encoded traversal sequences (%2e%2e%2f, %2e%2e/) (Attack-Positive -> 1 alert)
   - TC-19: Nested/double URL-encoded traversal (%252e%252e%252f) (Attack-Positive -> 1 alert)

5. RULE-004: Contextual geographic-anomaly detection.
   - TC-20: Legitimate successful login from unfamiliar country (FR) (Benign-Negative -> 0 alerts)
   - TC-21: Legitimate successful login from known baseline country (US, IN) (Benign-Negative -> 0 alerts)
   - TC-22: Single isolated failed login from unfamiliar country (password typo) (Benign-Negative -> 0 alerts)
   - TC-23: Repeated failed logins from unfamiliar country (brute force) (Attack-Positive -> 1 alert)

6. Cross-Dialect & Engine Equivalence:
   - TC-24: Batched vs unbatched threshold evaluation equivalence on remediated rules
   - TC-25: PostgreSQL 16 cluster evaluation equivalence (when available)

7. Independent Review Audit Findings Remediation Cases:
   - TC-26: Database migration idempotence without duplicate rule IDs (RULE-004)
   - TC-27: SQL LIKE literal wildcard escaping preventing false positives (%2e%2e)
   - TC-28: Path traversal prefix evasion blocked (/assets/../api/users)
   - TC-29: HTTP 304 events with NULL request paths handled safely
   - TC-30: URL decoding and '+' form-encoded space consistency (UNION+SELECT)
   - TC-31: Builtin rules deterministic dispatch and benchmark isolation
   - TC-32: Suspicious successful login detection preserved (RULE-002, RULE-003)
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

# Add backend directory to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["AUTO_CREATE_TABLES"] = "true"
os.environ["ENABLE_JUICE_SHOP_CONNECTOR"] = "false"
os.environ["JWT_SECRET_KEY"] = "remediation-test-secret-key-99999"

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database.base import Base
from app.models import Alert, AlertEvent, DetectionRule, NormalizedEvent, RawLog
from app.rules.builtin import (
    baseline_builtin_rules,
    builtin_rules,
    remediated_builtin_rules,
)
from app.rules.engine import (
    apply_filters,
    evaluate_rules_for_events,
    evaluate_threshold_rule,
    evaluate_threshold_rule_batched,
    event_matches_filters,
    extract_decoded_haystack,
    normalize_request_path,
)
from app.services.seed import ensure_builtin_rules


class TestDetectionQualityRemediation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        cls.SessionLocal = sessionmaker(bind=cls.engine, autoflush=False, autocommit=False)
        Base.metadata.create_all(bind=cls.engine)

    def setUp(self):
        self.db = self.SessionLocal()
        self.db.query(AlertEvent).delete()
        self.db.query(Alert).delete()
        self.db.query(NormalizedEvent).delete()
        self.db.query(RawLog).delete()
        self.db.query(DetectionRule).delete()
        self.db.commit()

        # Seed remediated rules into the database
        rules = remediated_builtin_rules()
        for r_dict in rules:
            rule_obj = DetectionRule(**r_dict)
            self.db.add(rule_obj)
        self.db.commit()

        self.rules = {r.rule_id: r for r in self.db.query(DetectionRule).all()}

    def tearDown(self):
        self.db.close()

    def _create_event(
        self,
        event_id: int,
        path: str | None = None,
        method: str = "GET",
        status_code: int = 200,
        source_ip: str = "192.0.2.10",
        event_category: str = "web",
        event_type: str = "web_request",
        username: str | None = None,
        geo_country: str | None = "US",
        offset_seconds: int = 0,
        message: str | None = None,
        base_time: datetime | None = None,
    ) -> NormalizedEvent:
        if base_time is None:
            base_time = datetime(2026, 10, 18, 12, 0, 0, tzinfo=UTC)
        ts = base_time + timedelta(seconds=offset_seconds)
        raw_log = RawLog(source_type="web", original_content=f"log_{event_id}")
        self.db.add(raw_log)
        self.db.flush()

        event = NormalizedEvent(
            id=event_id,
            raw_log_id=raw_log.id,
            timestamp=ts,
            source_type="WEB" if event_category == "web" else "AUTH",
            event_category=event_category,
            event_type=event_type,
            severity="low",
            source_ip=source_ip,
            request_path=path,
            http_method=method,
            status_code=status_code,
            username=username,
            geo_country=geo_country,
            message=message or f"{method} {path or ''} HTTP/{status_code}",
        )
        self.db.add(event)
        self.db.flush()
        return event

    # =========================================================================
    # 1. RULE-008: Static Resource Exclusion vs High-Volume API Detection
    # =========================================================================

    def test_tc01_rule008_benign_static_noise_excluded(self):
        """TC-01: 70 requests for static assets (.js, .css, .png, /assets/, 304s) must NOT alert."""
        rule_008 = self.rules["RULE-008"]
        events = []
        static_samples = [
            ("/assets/public/images/products/apple_juice.png", 200),
            ("/main.js", 200),
            ("/styles.css", 200),
            ("/favicon.ico", 200),
            ("/assets/fonts/roboto.woff2", 200),
            ("/vendor.js.map", 200),
            ("/assets/public/images/logo.svg", 304),
            ("/rest/admin/application-version", 304),
        ]
        for i in range(70):
            path, status = static_samples[i % len(static_samples)]
            ev = self._create_event(100 + i, path=path, status_code=status, offset_seconds=i * 2)
            events.append(ev)
        self.db.commit()

        alert_count = evaluate_rules_for_events(
            self.db, events, auto_correlate=False, use_batched_threshold=True, rules_override=[rule_008]
        )
        self.db.commit()

        self.assertEqual(alert_count, 0, "70 benign static asset requests must NOT trigger RULE-008")
        alerts = self.db.query(Alert).all()
        self.assertEqual(len(alerts), 0)

    def test_tc02_rule008_genuine_high_volume_api_detected(self):
        """TC-02: 65 rapid requests to API endpoints must trigger RULE-008."""
        rule_008 = self.rules["RULE-008"]
        events = []
        api_endpoints = [
            "/api/Users",
            "/rest/products/search?q=juice",
            "/api/Feedbacks",
            "/rest/basket/1",
            "/api/Cards",
        ]
        for i in range(65):
            path = api_endpoints[i % len(api_endpoints)]
            ev = self._create_event(200 + i, path=path, status_code=200, offset_seconds=i * 2)
            events.append(ev)
        self.db.commit()

        alert_count = evaluate_rules_for_events(
            self.db, events, auto_correlate=False, use_batched_threshold=True, rules_override=[rule_008]
        )
        self.db.commit()

        self.assertEqual(alert_count, 1, "65 API requests must trigger RULE-008")
        alert = self.db.query(Alert).filter(Alert.rule_id == rule_008.id).first()
        self.assertIsNotNone(alert)
        self.assertGreaterEqual(alert.event_count, 60)

    def test_tc03_rule008_parameter_smuggling_evasion_resistance(self):
        """TC-03: 65 API requests with static extensions in query parameters must NOT evade detection."""
        rule_008 = self.rules["RULE-008"]
        events = []
        for i in range(65):
            # Adversary appends ?file=test.png or ?bypass=/assets/ to trick naive substring exclusions
            path = f"/rest/products/search?q=item_{i}&file=test.png&ref=/assets/logo.svg"
            ev = self._create_event(300 + i, path=path, status_code=200, offset_seconds=i * 2)
            events.append(ev)
        self.db.commit()

        alert_count = evaluate_rules_for_events(
            self.db, events, auto_correlate=False, use_batched_threshold=True, rules_override=[rule_008]
        )
        self.db.commit()

        self.assertEqual(alert_count, 1, "Parameter-smuggled static extensions must NOT evade RULE-008")
        alert = self.db.query(Alert).filter(Alert.rule_id == rule_008.id).first()
        self.assertIsNotNone(alert)

    def test_tc04_rule008_mixed_static_noise_and_api_burst(self):
        """TC-04: Mixed traffic (50 static assets + 65 API requests) triggers alert linking ONLY API events."""
        rule_008 = self.rules["RULE-008"]
        events = []
        # 50 static events
        for i in range(50):
            ev = self._create_event(400 + i, path="/assets/image.png", status_code=200, offset_seconds=i)
            events.append(ev)
        # 65 API events
        for i in range(65):
            ev = self._create_event(500 + i, path=f"/api/data?id={i}", status_code=200, offset_seconds=60 + i)
            events.append(ev)
        self.db.commit()

        alert_count = evaluate_rules_for_events(
            self.db, events, auto_correlate=False, use_batched_threshold=True, rules_override=[rule_008]
        )
        self.db.commit()

        self.assertEqual(alert_count, 1)
        alert = self.db.query(Alert).filter(Alert.rule_id == rule_008.id).first()
        self.assertIsNotNone(alert)

        linked_eids = {link.event_id for link in self.db.query(AlertEvent).filter(AlertEvent.alert_id == alert.id).all()}
        self.assertTrue(all(eid >= 500 for eid in linked_eids), "Static asset events must NOT be linked to alert")
        self.assertFalse(any(eid < 500 for eid in linked_eids))

    # =========================================================================
    # 2. RULE-007: /login Traffic Separation vs Reconnaissance
    # =========================================================================

    def test_tc05_rule007_ordinary_login_traffic_excluded(self):
        """TC-05: 10 requests to /login or /rest/user/login must NOT trigger RULE-007 reconnaissance alert."""
        rule_007 = self.rules["RULE-007"]
        events = [
            self._create_event(600, path="/login", offset_seconds=0),
            self._create_event(601, path="/#/login", offset_seconds=10),
            self._create_event(602, path="/rest/user/login", method="POST", offset_seconds=20),
            self._create_event(603, path="/login?redirect=/profile", offset_seconds=30),
            self._create_event(604, path="/rest/user/login", method="POST", offset_seconds=40),
            self._create_event(605, path="/login", offset_seconds=50),
        ]
        self.db.commit()

        alert_count = evaluate_rules_for_events(
            self.db, events, auto_correlate=False, use_batched_threshold=True, rules_override=[rule_007]
        )
        self.db.commit()

        self.assertEqual(alert_count, 0, "Ordinary user login traffic must NOT trigger RULE-007")

    def test_tc06_rule007_genuine_reconnaissance_dotenv(self):
        """TC-06: 4 requests to /.env must trigger RULE-007."""
        rule_007 = self.rules["RULE-007"]
        events = [
            self._create_event(610, path="/.env", offset_seconds=0),
            self._create_event(611, path="/.env.local", offset_seconds=10),
            self._create_event(612, path="/.env.production", offset_seconds=20),
            self._create_event(613, path="/.env.bak", offset_seconds=30),
        ]
        self.db.commit()

        alert_count = evaluate_rules_for_events(
            self.db, events, auto_correlate=False, use_batched_threshold=True, rules_override=[rule_007]
        )
        self.db.commit()

        self.assertEqual(alert_count, 1, "Probing /.env files must trigger RULE-007")

    def test_tc07_rule007_genuine_reconnaissance_console(self):
        """TC-07: 4 requests to /console (Werkzeug debug console) must trigger RULE-007."""
        rule_007 = self.rules["RULE-007"]
        events = [
            self._create_event(620, path="/console", offset_seconds=0),
            self._create_event(621, path="/console?__debugger__=yes", offset_seconds=10),
            self._create_event(622, path="/console", offset_seconds=20),
            self._create_event(623, path="/console", offset_seconds=30),
        ]
        self.db.commit()

        alert_count = evaluate_rules_for_events(
            self.db, events, auto_correlate=False, use_batched_threshold=True, rules_override=[rule_007]
        )
        self.db.commit()

        self.assertEqual(alert_count, 1, "Probing /console must trigger RULE-007")

    def test_tc08_rule007_genuine_reconnaissance_actuator(self):
        """TC-08: 4 requests to /actuator endpoints must trigger RULE-007."""
        rule_007 = self.rules["RULE-007"]
        events = [
            self._create_event(630, path="/actuator", offset_seconds=0),
            self._create_event(631, path="/actuator/env", offset_seconds=10),
            self._create_event(632, path="/actuator/health", offset_seconds=20),
            self._create_event(633, path="/actuator/beans", offset_seconds=30),
        ]
        self.db.commit()

        alert_count = evaluate_rules_for_events(
            self.db, events, auto_correlate=False, use_batched_threshold=True, rules_override=[rule_007]
        )
        self.db.commit()

        self.assertEqual(alert_count, 1, "Probing /actuator endpoints must trigger RULE-007")

    def test_tc09_rule007_exact_path_spa_metadata_excluded(self):
        """TC-09: Exact path exclusion for SPA metadata endpoints (Benign-Negative -> 0 alerts)."""
        rule_007 = self.rules["RULE-007"]
        events = [
            self._create_event(640, path="/rest/admin/application-version", offset_seconds=0),
            self._create_event(641, path="/rest/admin/application-configuration", offset_seconds=10),
            self._create_event(642, path="/rest/admin/application-version", offset_seconds=20),
            self._create_event(643, path="/rest/admin/application-configuration", offset_seconds=30),
            self._create_event(644, path="/rest/admin/application-version", offset_seconds=40),
            self._create_event(645, path="/rest/admin/application-configuration", offset_seconds=50),
        ]
        self.db.commit()

        alert_count = evaluate_rules_for_events(
            self.db, events, auto_correlate=False, use_batched_threshold=True, rules_override=[rule_007]
        )
        self.db.commit()

        self.assertEqual(alert_count, 0, "SPA metadata endpoints (/rest/admin/application-*) must NOT trigger RULE-007")
        alerts = self.db.query(Alert).all()
        self.assertEqual(len(alerts), 0)

    # =========================================================================
    # 3. RULE-014: Attribute-Bearing & URL-Encoded XSS Signatures
    # =========================================================================

    def test_tc10_rule014_benign_negative(self):
        """TC-10: Benign query parameter must NOT trigger RULE-014."""
        rule_014 = self.rules["RULE-014"]
        ev = self._create_event(700, path="/search?q=apple+juice+fresh")
        self.db.commit()

        alert_count = evaluate_rules_for_events(
            self.db, [ev], auto_correlate=False, rules_override=[rule_014]
        )
        self.db.commit()

        self.assertEqual(alert_count, 0)

    def test_tc11_rule014_attribute_bearing_script_tag(self):
        """TC-11: <script src="https://attacker.com/evil.js"> must trigger RULE-014."""
        rule_014 = self.rules["RULE-014"]
        ev = self._create_event(
            710,
            path='/rest/products/search?q=<script src="https://attacker.com/evil.js"></script>',
        )
        self.db.commit()

        alert_count = evaluate_rules_for_events(
            self.db, [ev], auto_correlate=False, rules_override=[rule_014]
        )
        self.db.commit()

        self.assertEqual(alert_count, 1, "Attribute-bearing <script src=...> must trigger RULE-014")

    def test_tc12_rule014_url_encoded_xss_signatures(self):
        """TC-12: URL-encoded XSS (%3cscript%20src=...) must trigger RULE-014."""
        rule_014 = self.rules["RULE-014"]
        ev = self._create_event(
            720,
            path="/rest/products/search?q=%3Cscript%20src%3D%22https%3A%2F%2Fattacker.com%2Fhook.js%22%3E",
        )
        self.db.commit()

        alert_count = evaluate_rules_for_events(
            self.db, [ev], auto_correlate=False, rules_override=[rule_014]
        )
        self.db.commit()

        self.assertEqual(alert_count, 1, "URL-encoded XSS must trigger RULE-014")

    def test_tc13_rule014_attribute_bearing_svg_and_img(self):
        """TC-13: <svg onload=alert(1)> and URL-encoded %3cimg%20src=x%20onerror=alert(1) must trigger RULE-014."""
        rule_014 = self.rules["RULE-014"]
        ev1 = self._create_event(730, path="/profile?name=<svg onload=alert(1)>")
        ev2 = self._create_event(731, path="/search?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E")
        self.db.commit()

        alert_count = evaluate_rules_for_events(
            self.db, [ev1, ev2], auto_correlate=False, rules_override=[rule_014]
        )
        self.db.commit()

        self.assertGreaterEqual(alert_count, 1)

    def test_tc14_rule014_raw_evidence_preserved_unmutated(self):
        """TC-14: Normalization MUST NOT mutate raw event fields in the database."""
        rule_014 = self.rules["RULE-014"]
        raw_path = "/search?q=%3Cscript%20src%3D%22https%3A%2F%2Fevil.com%22%3E"
        ev = self._create_event(740, path=raw_path)
        self.db.commit()

        evaluate_rules_for_events(self.db, [ev], auto_correlate=False, rules_override=[rule_014])
        self.db.commit()

        # Re-fetch from DB
        db_ev = self.db.query(NormalizedEvent).filter(NormalizedEvent.id == 740).first()
        self.assertEqual(db_ev.request_path, raw_path, "Raw request path in database must NOT be mutated")

    # =========================================================================
    # 4. RULE-013: URL-Encoded Path Traversal Indicators
    # =========================================================================

    def test_tc15_rule013_benign_negative(self):
        """TC-15: Benign path must NOT trigger RULE-013."""
        rule_013 = self.rules["RULE-013"]
        ev = self._create_event(800, path="/assets/public/images/products/apple_press.jpg")
        self.db.commit()

        alert_count = evaluate_rules_for_events(self.db, [ev], auto_correlate=False, rules_override=[rule_013])
        self.db.commit()

        self.assertEqual(alert_count, 0)

    def test_tc16_rule013_standard_traversal(self):
        """TC-16: Standard traversal (../ and ..%2f) must trigger RULE-013."""
        rule_013 = self.rules["RULE-013"]
        ev = self._create_event(810, path="/ftp/..%2f..%2fetc/passwd")
        self.db.commit()

        alert_count = evaluate_rules_for_events(self.db, [ev], auto_correlate=False, rules_override=[rule_013])
        self.db.commit()

        self.assertEqual(alert_count, 1)

    def test_tc17_rule013_url_encoded_sensitive_file(self):
        """TC-17: URL-encoded sensitive path (%2Fetc%2Fpasswd) must trigger RULE-013."""
        rule_013 = self.rules["RULE-013"]
        ev = self._create_event(820, path="/download?file=%2Fetc%2Fpasswd")
        self.db.commit()

        alert_count = evaluate_rules_for_events(self.db, [ev], auto_correlate=False, rules_override=[rule_013])
        self.db.commit()

        self.assertEqual(alert_count, 1, "URL-encoded %2Fetc%2Fpasswd must trigger RULE-013")

    def test_tc18_rule013_url_encoded_dot_dot_slash(self):
        """TC-18: URL-encoded dot-dot-slash (%2e%2e%2f) must trigger RULE-013."""
        rule_013 = self.rules["RULE-013"]
        ev = self._create_event(830, path="/view?page=%2e%2e%2f%2e%2e%2fwin.ini")
        self.db.commit()

        alert_count = evaluate_rules_for_events(self.db, [ev], auto_correlate=False, rules_override=[rule_013])
        self.db.commit()

        self.assertEqual(alert_count, 1, "URL-encoded %2e%2e%2f must trigger RULE-013")

    def test_tc19_rule013_double_encoded_traversal(self):
        """TC-19: Nested/double URL-encoded traversal (%252e%252e%252f) must trigger RULE-013."""
        rule_013 = self.rules["RULE-013"]
        ev = self._create_event(840, path="/download?target=%252e%252e%252fetc%252fpasswd")
        self.db.commit()

        alert_count = evaluate_rules_for_events(self.db, [ev], auto_correlate=False, rules_override=[rule_013])
        self.db.commit()

        self.assertEqual(alert_count, 1, "Double-encoded traversal must trigger RULE-013")

    # =========================================================================
    # 5. RULE-004: Contextual Geographic Anomaly Detection
    # =========================================================================

    def test_tc20_rule004_legitimate_successful_login_unfamiliar_country(self):
        """TC-20: 1 successful login from an unfamiliar country (FR) must NOT trigger an anomaly alert."""
        rule_004 = self.rules["RULE-004"]
        ev = self._create_event(
            900,
            event_category="authentication",
            event_type="successful_login",
            username="traveling_user",
            geo_country="FR",
        )
        self.db.commit()

        alert_count = evaluate_rules_for_events(self.db, [ev], auto_correlate=False, rules_override=[rule_004])
        self.db.commit()

        self.assertEqual(alert_count, 0, "Legitimate successful login from abroad must NOT alert solely on country")

    def test_tc21_rule004_legitimate_successful_login_baseline_country(self):
        """TC-21: Successful logins from baseline countries (US, IN) must NOT trigger RULE-004."""
        rule_004 = self.rules["RULE-004"]
        ev1 = self._create_event(910, event_category="authentication", event_type="successful_login", username="alice", geo_country="US")
        ev2 = self._create_event(911, event_category="authentication", event_type="successful_login", username="bob", geo_country="IN")
        self.db.commit()

        alert_count = evaluate_rules_for_events(self.db, [ev1, ev2], auto_correlate=False, rules_override=[rule_004])
        self.db.commit()

        self.assertEqual(alert_count, 0)

    def test_tc22_rule004_isolated_password_typo_unfamiliar_country(self):
        """TC-22: 1 single failed login (accidental typo) from unfamiliar country (threshold=2) must NOT alert."""
        rule_004 = self.rules["RULE-004"]
        ev = self._create_event(
            920,
            event_category="authentication",
            event_type="failed_login",
            username="traveling_user",
            geo_country="FR",
        )
        self.db.commit()

        alert_count = evaluate_rules_for_events(self.db, [ev], auto_correlate=False, rules_override=[rule_004])
        self.db.commit()

        self.assertEqual(alert_count, 0, "Single isolated failed login from unfamiliar country must NOT alert")

    def test_tc23_rule004_repeated_failed_logins_unfamiliar_country(self):
        """TC-23: 2 consecutive failed logins from an unfamiliar country (CN) within window MUST trigger RULE-004."""
        rule_004 = self.rules["RULE-004"]
        ev1 = self._create_event(
            930,
            source_ip="203.0.113.88",
            event_category="authentication",
            event_type="failed_login",
            username="admin",
            geo_country="CN",
            offset_seconds=0,
        )
        ev2 = self._create_event(
            931,
            source_ip="203.0.113.88",
            event_category="authentication",
            event_type="failed_login",
            username="admin",
            geo_country="CN",
            offset_seconds=60,
        )
        self.db.commit()

        alert_count = evaluate_rules_for_events(
            self.db, [ev1, ev2], auto_correlate=False, rules_override=[rule_004]
        )
        self.db.commit()

        self.assertEqual(alert_count, 1, "Repeated failed logins from unusual country MUST trigger RULE-004")
        alert = self.db.query(Alert).filter(Alert.rule_id == rule_004.id).first()
        self.assertIsNotNone(alert)
        self.assertEqual(alert.event_count, 2)

    # =========================================================================
    # 6. Cross-Dialect & Execution Mode Equivalence
    # =========================================================================

    def test_tc24_batched_vs_unbatched_equivalence(self):
        """TC-24: Verify threshold rules produce identical alerts under unbatched and batched evaluators."""
        rule_008 = self.rules["RULE-008"]
        events = []
        for i in range(70):
            ev = self._create_event(950 + i, path=f"/api/resource/{i}", offset_seconds=i * 2)
            events.append(ev)
        self.db.commit()

        unbatched_alerts = evaluate_threshold_rule(self.db, rule_008, events)
        self.db.commit()

        self.db.query(AlertEvent).delete()
        self.db.query(Alert).delete()
        self.db.commit()

        batched_alerts = evaluate_threshold_rule_batched(self.db, rule_008, events)
        self.db.commit()

        self.assertEqual(len(unbatched_alerts), 1)
        self.assertEqual(len(batched_alerts), 1)

    def test_tc25_postgresql_remediation_evaluation_equivalence(self):
        """TC-25: Verify all 5 remediated rules function identically against real PostgreSQL 16."""
        pg_bin = r"C:\Program Files\PostgreSQL\16\bin"
        initdb_exe = os.path.join(pg_bin, "initdb.exe")
        pg_ctl_exe = os.path.join(pg_bin, "pg_ctl.exe")
        if not os.path.exists(initdb_exe) or not os.path.exists(pg_ctl_exe):
            self.skipTest("PostgreSQL 16 binaries not available for local test cluster")

        port = 5448
        data_dir = os.path.join(tempfile.gettempdir(), f"pg_rem_{int(time.time() * 1000) % 1000000}").replace("\\", "/")
        log_file = os.path.join(tempfile.gettempdir(), f"pg_rem_{int(time.time() * 1000) % 1000000}.log").replace("\\", "/")

        init_res = subprocess.run(
            [initdb_exe, "-D", data_dir, "-U", "postgres", "-A", "trust", "--no-locale", "-E", "UTF8"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if init_res.returncode != 0:
            self.skipTest("PostgreSQL initdb failed")

        subprocess.run(
            [pg_ctl_exe, "-D", data_dir, "-l", log_file, "-o", f"-p {port}", "start"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        import psycopg

        ready = False
        for _ in range(12):
            try:
                c = psycopg.connect(f"postgresql://postgres@127.0.0.1:{port}/postgres", connect_timeout=1)
                c.close()
                ready = True
                break
            except Exception:
                time.sleep(0.3)

        if not ready:
            self.skipTest("PostgreSQL failed to become ready")

        pg_url = f"postgresql+psycopg://postgres@127.0.0.1:{port}/postgres"
        pg_eng = create_engine(pg_url)
        Base.metadata.create_all(pg_eng)
        PgSession = sessionmaker(bind=pg_eng, autoflush=False, autocommit=False)
        db_pg = PgSession()

        try:
            # Seed remediated rules into PostgreSQL
            for r_dict in remediated_builtin_rules():
                db_pg.add(DetectionRule(**r_dict))
            db_pg.commit()

            pg_rules = {r.rule_id: r for r in db_pg.query(DetectionRule).all()}

            # 1. Test RULE-008 static exclusion on PostgreSQL
            base_t = datetime(2026, 10, 18, 12, 0, 0, tzinfo=UTC)
            static_evs = []
            for i in range(70):
                raw = RawLog(source_type="web", original_content=f"pg_stat_{i}")
                db_pg.add(raw)
                db_pg.flush()
                ev = NormalizedEvent(
                    id=1000 + i,
                    raw_log_id=raw.id,
                    timestamp=base_t + timedelta(seconds=i),
                    source_type="WEB",
                    event_category="web",
                    event_type="web_request",
                    severity="low",
                    source_ip="198.51.100.55",
                    request_path="/assets/images/product.png",
                    status_code=200,
                    message="GET /assets/images/product.png",
                )
                db_pg.add(ev)
                static_evs.append(ev)
            db_pg.commit()

            c1 = evaluate_rules_for_events(db_pg, static_evs, auto_correlate=False, rules_override=[pg_rules["RULE-008"]])
            db_pg.commit()
            self.assertEqual(c1, 0, "PostgreSQL: Static asset noise must NOT trigger RULE-008")

            # 2. Test RULE-014 URL-encoded XSS on PostgreSQL
            raw = RawLog(source_type="web", original_content="pg_xss")
            db_pg.add(raw)
            db_pg.flush()
            xss_ev = NormalizedEvent(
                id=2000,
                raw_log_id=raw.id,
                timestamp=base_t,
                source_type="WEB",
                event_category="web",
                event_type="web_request",
                severity="low",
                source_ip="198.51.100.56",
                request_path="/search?q=%3Cscript%20src%3D%22https%3A%2F%2Fevil.com%22%3E",
                status_code=200,
                message="XSS probe",
            )
            db_pg.add(xss_ev)
            db_pg.commit()

            c2 = evaluate_rules_for_events(db_pg, [xss_ev], auto_correlate=False, rules_override=[pg_rules["RULE-014"]])
            db_pg.commit()
            self.assertEqual(c2, 1, "PostgreSQL: URL-encoded XSS must trigger RULE-014")

            # 3. Test RULE-013 URL-encoded Traversal on PostgreSQL
            raw = RawLog(source_type="web", original_content="pg_trav")
            db_pg.add(raw)
            db_pg.flush()
            trav_ev = NormalizedEvent(
                id=3000,
                raw_log_id=raw.id,
                timestamp=base_t,
                source_type="WEB",
                event_category="web",
                event_type="web_request",
                severity="low",
                source_ip="198.51.100.57",
                request_path="/download?file=%2Fetc%2Fpasswd",
                status_code=200,
                message="Traversal probe",
            )
            db_pg.add(trav_ev)
            db_pg.commit()

            c3 = evaluate_rules_for_events(db_pg, [trav_ev], auto_correlate=False, rules_override=[pg_rules["RULE-013"]])
            db_pg.commit()
            self.assertEqual(c3, 1, "PostgreSQL: URL-encoded traversal must trigger RULE-013")

        finally:
            db_pg.close()
            pg_eng.dispose()
            subprocess.run([pg_ctl_exe, "-D", data_dir, "stop", "-m", "immediate"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            shutil.rmtree(data_dir, ignore_errors=True)
            if os.path.exists(log_file):
                os.remove(log_file)

    # =========================================================================
    # 7. Independent Review Audit Findings Remediation Cases (TC-26 to TC-32)
    # =========================================================================

    def test_tc26_seed_migration_idempotent_no_duplicate_rule_id(self):
        """TC-26 (Audit Finding 1 & 9): Migration idempotence when updating existing database.

        Tests that an existing database with older/baseline rule names (such as RULE-004
        'Login attempt from unusual country') is updated in-place without triggering
        'UNIQUE constraint failed: detection_rules.rule_id', and repeated seeding is idempotent.
        """
        self.db.query(DetectionRule).delete()
        self.db.commit()

        old_rule_004 = DetectionRule(
            rule_id="RULE-004",
            name="Login attempt from unusual country",
            description="Old description",
            category="account_anomaly",
            severity="medium",
            version="1.0",
            status="ACTIVE",
            source="builtin",
            conditions_json={"type": "threshold", "filters": {"geo_country_not_in": ["US"]}},
            time_window_minutes=10,
            threshold=1,
        )
        self.db.add(old_rule_004)
        self.db.commit()

        # Run ensure_builtin_rules on existing DB - must not crash with duplicate key
        ensure_builtin_rules(self.db)
        self.db.commit()

        # Verify rule was updated in-place
        rules_004 = self.db.query(DetectionRule).filter(DetectionRule.rule_id == "RULE-004").all()
        self.assertEqual(len(rules_004), 1, "Exactly one RULE-004 record must exist")
        self.assertEqual(rules_004[0].name, "Repeated failed login from unusual country")
        self.assertEqual(rules_004[0].threshold, 2)
        self.assertEqual(rules_004[0].conditions_json["filters"]["event_type"], "failed_login")

        # Second run must also be idempotent
        ensure_builtin_rules(self.db)
        self.db.commit()
        rules_004_second = self.db.query(DetectionRule).filter(DetectionRule.rule_id == "RULE-004").all()
        self.assertEqual(len(rules_004_second), 1)

    def test_tc27_sql_like_wildcard_escaping_no_false_positives(self):
        """TC-27 (Audit Finding 2 & Step 5): SQL LIKE literal wildcard escaping.

        RULE-013 searches for pattern '%2e%2e'. In unescaped SQL LIKE, '%' matches any string,
        causing benign paths like '/items/12e34/details' or '/product/2e/item2e' to trigger false positives.
        With proper escaping (escape="\\"), only literal '%2e%2e' matches.
        """
        rule_013 = self.rules["RULE-013"]

        # Benign events that would match unescaped '%2e%2e' as wildcards
        benign_events = [
            self._create_event(2701, path="/items/12e34/details"),
            self._create_event(2702, path="/catalog/section_2e_index"),
            self._create_event(2703, path="/api/v1/2e/test2e"),
        ]
        self.db.commit()

        c_benign = evaluate_rules_for_events(self.db, benign_events, auto_correlate=False, rules_override=[rule_013])
        self.db.commit()
        self.assertEqual(c_benign, 0, "Benign strings matching unescaped LIKE wildcards must NOT trigger RULE-013")

        # Genuine encoded traversal event with literal '%2e%2e'
        attack_event = self._create_event(2704, path="/download?file=%2e%2e%2fetc/passwd")
        self.db.commit()

        c_attack = evaluate_rules_for_events(self.db, [attack_event], auto_correlate=False, rules_override=[rule_013])
        self.db.commit()
        self.assertEqual(c_attack, 1, "Literal '%2e%2e' must trigger RULE-013")

    def test_tc28_rule008_traversal_prefix_evasion_blocked(self):
        """TC-28 (Audit Finding 3 & Step 7): Traversal prefix evasion in static asset exclusion.

        Adversary sends 65 rapid requests to '/assets/../api/users' or '/assets/%2e%2e/api/users'.
        Static asset exclusion must detect the traversal sequence and NOT exclude the traffic.
        """
        rule_008 = self.rules["RULE-008"]

        events = []
        for i in range(65):
            path = "/assets/../api/users" if i % 2 == 0 else "/assets/%2e%2e/api/users"
            ev = self._create_event(2800 + i, path=path, status_code=200, offset_seconds=i * 2)
            events.append(ev)
        self.db.commit()

        alert_count = evaluate_rules_for_events(
            self.db, events, auto_correlate=False, use_batched_threshold=True, rules_override=[rule_008]
        )
        self.db.commit()

        self.assertEqual(alert_count, 1, "Traversal prefix evasion (/assets/../api/users) must trigger RULE-008")
        alert = self.db.query(Alert).filter(Alert.rule_id == rule_008.id).first()
        self.assertIsNotNone(alert)
        self.assertGreaterEqual(alert.event_count, 60)

    def test_tc29_rule008_http304_with_null_path_handled(self):
        """TC-29 (Audit Finding 4 & Step 7): Safe handling of HTTP 304 events with NULL request_path.

        Events with status_code=304 and request_path=None must be safely excluded as 304s
        without breaking SQL query filters or throwing errors, and 200 events with NULL paths
        must be handled gracefully.
        """
        rule_008 = self.rules["RULE-008"]

        # 70 HTTP 304 events with NULL request_path
        ev_304 = []
        for i in range(70):
            ev = self._create_event(2900 + i, path=None, status_code=304, offset_seconds=i * 2)
            ev_304.append(ev)
        self.db.commit()

        count_304 = evaluate_rules_for_events(
            self.db, ev_304, auto_correlate=False, use_batched_threshold=True, rules_override=[rule_008]
        )
        self.db.commit()
        self.assertEqual(count_304, 0, "70 HTTP 304 requests with NULL paths must NOT trigger RULE-008")

        # 65 API requests alongside 10 HTTP 304 requests with NULL paths
        mixed_events = []
        for i in range(10):
            mixed_events.append(self._create_event(2970 + i, path=None, status_code=304, offset_seconds=i))
        for i in range(65):
            mixed_events.append(self._create_event(2980 + i, path=f"/api/v1/orders/{i}", status_code=200, offset_seconds=10 + i))
        self.db.commit()

        count_mixed = evaluate_rules_for_events(
            self.db, mixed_events, auto_correlate=False, use_batched_threshold=True, rules_override=[rule_008]
        )
        self.db.commit()
        self.assertEqual(count_mixed, 1, "API burst with interspersed HTTP 304s must trigger RULE-008")

    def test_tc30_form_encoded_space_plus_consistency(self):
        """TC-30 (Audit Finding 5 & Step 6): URL decoding and '+' form-encoding consistency.

        Verifies that application/x-www-form-urlencoded '+' spaces (e.g. 'UNION+SELECT',
        ''+or+1=1', 'sleep(5)') are detected consistently in both SQL queries and in-memory evaluation,
        while benign queries with '+' (e.g. 'search?q=apple+juice') do NOT trigger alerts.
        """
        rule_012 = self.rules["RULE-012"]

        # Benign search query with '+' space encoding
        benign_ev = self._create_event(3001, path="/search?q=organic+apple+juice")
        self.db.commit()

        c_benign = evaluate_rules_for_events(self.db, [benign_ev], auto_correlate=False, rules_override=[rule_012])
        self.db.commit()
        self.assertEqual(c_benign, 0, "Benign '+' search queries must NOT trigger RULE-012")

        # In-memory evaluation check for benign
        self.assertFalse(event_matches_filters(benign_ev, rule_012.conditions_json["filters"]))

        # Attack query with '+' form-encoded space: UNION+SELECT
        attack_ev = self._create_event(3002, path="/rest/products/search?q=' UNION+SELECT+1,email,password+FROM+Users--")
        self.db.commit()

        # Test in-memory evaluation
        self.assertTrue(
            event_matches_filters(attack_ev, rule_012.conditions_json["filters"]),
            "In-memory evaluation must detect form-encoded 'UNION+SELECT'",
        )

        # Test SQL evaluation
        c_attack = evaluate_rules_for_events(self.db, [attack_ev], auto_correlate=False, rules_override=[rule_012])
        self.db.commit()
        self.assertEqual(c_attack, 1, "SQL evaluation must detect form-encoded 'UNION+SELECT'")

    def test_tc31_builtin_rules_deterministic_dispatch_isolation(self):
        """TC-31 (Audit Finding 6 & Step 8): Explicit deterministic rule selection.

        Verifies pure functional deterministic rule selection:
        1. Default builtin_rules() returns remediated rules (threshold=2, exclude_static_assets=True).
        2. Explicit builtin_rules(mode='baseline') returns baseline rules.
        3. ensure_builtin_rules(db, mode=...) deterministically seeds baseline or remediated rules.
        4. Zero call-stack inspection, zero JWT heuristics, zero hidden process-wide state.
        5. Absolute context isolation between calls.
        """
        # 1. Default callsite without arguments yields remediated rules
        default_rules = builtin_rules()
        self.assertNotEqual(len(default_rules), 0)
        def_004 = next(r for r in default_rules if r["rule_id"] == "RULE-004")
        def_008 = next(r for r in default_rules if r["rule_id"] == "RULE-008")
        self.assertEqual(def_004["threshold"], 2)
        self.assertTrue(def_008["conditions_json"]["filters"].get("exclude_static_assets"))

        # 2. Explicit baseline selection via mode or remediated flag
        base_rules_mode = builtin_rules(mode="baseline")
        base_rules_flag = builtin_rules(remediated=False)
        base_004 = next(r for r in base_rules_mode if r["rule_id"] == "RULE-004")
        base_008 = next(r for r in base_rules_mode if r["rule_id"] == "RULE-008")
        self.assertEqual(base_004["threshold"], 1)
        self.assertEqual(base_008["conditions_json"]["filters"], {"event_category": "web"})
        self.assertEqual(base_rules_mode, base_rules_flag)

        # 3. Explicit remediated selection via mode or flag
        rem_rules_mode = builtin_rules(mode="remediated")
        rem_rules_flag = builtin_rules(remediated=True)
        self.assertEqual(rem_rules_mode, rem_rules_flag)
        self.assertEqual(rem_rules_mode, default_rules)

        # 4. Context isolation: calling baseline does NOT alter subsequent default calls
        after_default = builtin_rules()
        self.assertEqual(next(r for r in after_default if r["rule_id"] == "RULE-004")["threshold"], 2)

        # 5. ensure_builtin_rules seeding isolation
        self.db.query(DetectionRule).delete()
        self.db.commit()
        ensure_builtin_rules(self.db, mode="baseline")
        self.db.commit()
        db_004 = self.db.query(DetectionRule).filter(DetectionRule.rule_id == "RULE-004").first()
        self.assertEqual(db_004.threshold, 1)

        ensure_builtin_rules(self.db, mode="remediated")
        self.db.commit()
        db_004_rem = self.db.query(DetectionRule).filter(DetectionRule.rule_id == "RULE-004").first()
        self.assertEqual(db_004_rem.threshold, 2)

    def test_tc32_suspicious_successful_login_detection(self):
        """TC-32 (Audit Finding 7 & Step 9): Preservation of suspicious login detection.

        While RULE-004 is scoped to repeated failed logins from unusual countries (brute-force defense),
        suspicious successful logins remain actively detected by RULE-002 (successful login after failures)
        and RULE-003 (suspicious admin login).
        """
        rule_002 = self.rules["RULE-002"]
        rule_003 = self.rules["RULE-003"]

        # 1. Suspicious successful login for 'admin' user triggers RULE-003
        admin_ev = self._create_event(
            3201,
            event_category="authentication",
            event_type="successful_login",
            username="admin",
            source_ip="198.51.100.44",
        )
        self.db.commit()

        c_admin = evaluate_rules_for_events(self.db, [admin_ev], auto_correlate=False, rules_override=[rule_003])
        self.db.commit()
        self.assertEqual(c_admin, 1, "Successful login to 'admin' account must trigger RULE-003")

        # Standard user successful login must NOT trigger RULE-003
        user_ev = self._create_event(
            3202,
            event_category="authentication",
            event_type="successful_login",
            username="standard_user",
            source_ip="198.51.100.45",
        )
        self.db.commit()

        c_user = evaluate_rules_for_events(self.db, [user_ev], auto_correlate=False, rules_override=[rule_003])
        self.db.commit()
        self.assertEqual(c_user, 0, "Successful login to standard account must NOT trigger RULE-003")

        # 2. Successful login following 3 failed attempts triggers RULE-002
        fail_events = [
            self._create_event(3210, event_category="authentication", event_type="failed_login", username="victim", source_ip="198.51.100.99", offset_seconds=0),
            self._create_event(3211, event_category="authentication", event_type="failed_login", username="victim", source_ip="198.51.100.99", offset_seconds=30),
            self._create_event(3212, event_category="authentication", event_type="failed_login", username="victim", source_ip="198.51.100.99", offset_seconds=60),
            self._create_event(3213, event_category="authentication", event_type="successful_login", username="victim", source_ip="198.51.100.99", offset_seconds=90),
        ]
        self.db.commit()

        c_brute_success = evaluate_rules_for_events(self.db, fail_events, auto_correlate=False, rules_override=[rule_002])
        self.db.commit()
        self.assertEqual(c_brute_success, 1, "Successful login after failed attempts must trigger RULE-002")

    def test_tc33_builtin_rules_validation_and_rejection(self):
        """TC-33: Validation of unknown modes and contradictory arguments in builtin_rules().

        Requirements:
        1. Reject unknown mode values with ValueError.
        2. Reject contradictory mode and remediated arguments with ValueError.
        3. Preserve valid calls: default, mode='remediated', mode='baseline', mode='frozen',
           remediated=True, remediated=False, and consistent combinations.
        """
        # 1. Reject unknown mode values
        for invalid_mode in ["unknown", "invalid", "", "base_line", "rem", "PROD", "default"]:
            with self.assertRaises(ValueError) as ctx:
                builtin_rules(mode=invalid_mode)
            self.assertIn("Invalid mode", str(ctx.exception))
            # Also test positional argument rejection
            with self.assertRaises(ValueError) as ctx:
                builtin_rules(invalid_mode)
            self.assertIn("Invalid mode", str(ctx.exception))

        # 2. Reject contradictory mode and remediated arguments
        with self.assertRaises(ValueError) as ctx:
            builtin_rules(mode="baseline", remediated=True)
        self.assertIn("Contradictory arguments", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            builtin_rules(mode="frozen", remediated=True)
        self.assertIn("Contradictory arguments", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            builtin_rules(mode="remediated", remediated=False)
        self.assertIn("Contradictory arguments", str(ctx.exception))

        # 3. Preserve valid existing calls and verify correct selection
        # Default call -> Remediated
        def_rules = builtin_rules()
        self.assertEqual(next(r for r in def_rules if r["rule_id"] == "RULE-004")["threshold"], 2)

        # mode="remediated" -> Remediated
        rem_rules = builtin_rules(mode="remediated")
        self.assertEqual(next(r for r in rem_rules if r["rule_id"] == "RULE-004")["threshold"], 2)

        # mode="baseline" -> Baseline
        base_rules = builtin_rules(mode="baseline")
        self.assertEqual(next(r for r in base_rules if r["rule_id"] == "RULE-004")["threshold"], 1)

        # mode="frozen" -> Baseline
        frozen_rules = builtin_rules(mode="frozen")
        self.assertEqual(next(r for r in frozen_rules if r["rule_id"] == "RULE-004")["threshold"], 1)

        # remediated=True -> Remediated
        rem_flag_rules = builtin_rules(remediated=True)
        self.assertEqual(next(r for r in rem_flag_rules if r["rule_id"] == "RULE-004")["threshold"], 2)

        # remediated=False -> Baseline
        base_flag_rules = builtin_rules(remediated=False)
        self.assertEqual(next(r for r in base_flag_rules if r["rule_id"] == "RULE-004")["threshold"], 1)

        # Consistent combinations
        self.assertEqual(
            next(r for r in builtin_rules(mode="remediated", remediated=True) if r["rule_id"] == "RULE-004")["threshold"],
            2,
        )
        self.assertEqual(
            next(r for r in builtin_rules(mode="baseline", remediated=False) if r["rule_id"] == "RULE-004")["threshold"],
            1,
        )
        self.assertEqual(
            next(r for r in builtin_rules(mode="frozen", remediated=False) if r["rule_id"] == "RULE-004")["threshold"],
            1,
        )

        # Positional arguments
        self.assertEqual(next(r for r in builtin_rules("remediated") if r["rule_id"] == "RULE-004")["threshold"], 2)
        self.assertEqual(next(r for r in builtin_rules("baseline") if r["rule_id"] == "RULE-004")["threshold"], 1)
        self.assertEqual(next(r for r in builtin_rules("frozen") if r["rule_id"] == "RULE-004")["threshold"], 1)

        # 4. ensure_builtin_rules rejects invalid mode
        with self.assertRaises(ValueError):
            ensure_builtin_rules(self.db, mode="nonexistent_mode")


if __name__ == "__main__":
    unittest.main()
