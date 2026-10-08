import random
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from app.auth.security import hash_password
from app.models import Alert, AlertEvent, AlertNote, DetectionRule, NormalizedEvent, RawLog, ThreatIndicator, User
from app.rules import builtin_rules, evaluate_rules_for_events


DEMO_USERS = [
    ("admin", "admin@example.com", "admin", "AdminPass123!"),
    ("analyst", "analyst@example.com", "analyst", "AnalystPass123!"),
    ("viewer", "viewer@example.com", "viewer", "ViewerPass123!"),
]


def ensure_builtin_rules(db: Session) -> None:
    existing_rules = {rule.name: rule for rule in db.query(DetectionRule).all()}
    for item in builtin_rules():
        rule = existing_rules.get(item["name"])
        if not rule:
            db.add(DetectionRule(**item))
        else:
            # Backfill any metadata fields that were newly introduced or are empty
            for field in [
                "rule_id",
                "category",
                "version",
                "status",
                "source",
                "owner",
                "mitre_technique",
                "confidence",
                "false_positive_notes",
                "expected_data_source",
                "test_cases_json",
            ]:
                if getattr(rule, field, None) in (None, "", "NOT_MAPPED") and field in item:
                    setattr(rule, field, item[field])
    db.commit()


def seed_demo_data(db: Session) -> dict[str, int]:
    ensure_users(db)
    ensure_builtin_rules(db)
    ensure_indicators(db)

    raw_log = RawLog(source_type="demo", original_content="Generated safe demo events", file_name="demo-seed.jsonl")
    db.add(raw_log)
    db.flush()

    events = build_demo_events(raw_log.id)
    db.add_all(events)
    db.flush()
    alert_count = evaluate_rules_for_events(db, events)
    db.commit()
    return {"users": len(DEMO_USERS), "events": len(events), "alerts": max(alert_count, db.query(Alert).count())}


def clear_demo_data(db: Session) -> dict[str, int]:
    counts = {
        "alert_notes": db.query(AlertNote).count(),
        "alert_events": db.query(AlertEvent).count(),
        "alerts": db.query(Alert).count(),
        "events": db.query(NormalizedEvent).count(),
        "raw_logs": db.query(RawLog).count(),
        "threat_indicators": db.query(ThreatIndicator).count(),
    }
    db.query(AlertNote).delete()
    db.query(AlertEvent).delete()
    db.query(Alert).delete()
    db.query(NormalizedEvent).delete()
    db.query(RawLog).delete()
    db.query(ThreatIndicator).delete()
    db.commit()
    ensure_builtin_rules(db)
    ensure_indicators(db)
    return counts


def ensure_users(db: Session) -> None:
    for username, email, role, password in DEMO_USERS:
        user = db.query(User).filter(User.username == username).first()
        if user:
            user.role = role
            continue
        db.add(User(username=username, email=email, role=role, password_hash=hash_password(password)))
    db.commit()


def ensure_indicators(db: Session) -> None:
    indicators = [
        ("ip", "203.0.113.66", "Known noisy scanner in the demo dataset", "high"),
        ("ip", "198.51.100.200", "Repeated denied firewall traffic", "medium"),
        ("username", "svc-legacy", "Deprecated service account that should not authenticate", "high"),
        ("domain", "malware-demo.invalid", "Safe placeholder domain for demo matching", "critical"),
    ]
    existing = {(indicator.type, indicator.value) for indicator in db.query(ThreatIndicator).all()}
    for type_, value, description, severity in indicators:
        if (type_, value) not in existing:
            db.add(ThreatIndicator(type=type_, value=value, description=description, severity=severity))
    db.commit()


def build_demo_events(raw_log_id: int) -> list[NormalizedEvent]:
    random.seed(42)
    now = datetime.now(UTC).replace(second=0, microsecond=0)
    events: list[NormalizedEvent] = []
    usernames = ["alice", "bob", "carol", "dave", "svc-legacy", "admin", "root", "morgan"]
    hosts = ["web-01", "web-02", "auth-01", "vpn-01", "fw-01"]
    normal_ips = [f"203.0.113.{i}" for i in range(10, 55)] + [f"198.51.100.{i}" for i in range(10, 40)]
    suspicious_ips = ["203.0.113.66", "198.51.100.200", "45.88.12.24", "91.220.44.8", "185.199.110.15"]
    paths = ["/", "/docs", "/api/health", "/pricing", "/static/app.js", "/login", "/admin", "/wp-admin", "/.env", "/backup.zip"]
    agents = ["Mozilla/5.0", "Chrome/124.0", "curl/8.1", "python-requests/2.31", "nikto/2.5"]

    for index in range(360):
        ip = random.choice(normal_ips)
        path = random.choice(paths[:6])
        status = 200 if path not in {"/login"} else random.choice([200, 401])
        ts = now - timedelta(minutes=random.randint(0, 1440))
        events.append(
            event(
                raw_log_id,
                ts,
                source_ip=ip,
                hostname=random.choice(hosts[:2]),
                event_type="web_request" if status != 401 else "failed_login",
                event_category="web" if status != 401 else "authentication",
                severity="low" if status == 200 else "medium",
                message=f"GET {path} returned {status}",
                request_path=path,
                http_method="GET",
                status_code=status,
                user_agent=random.choice(agents[:2]),
                username=random.choice(usernames[:4]) if status == 401 else None,
            )
        )

    for cluster, ip in enumerate(suspicious_ips * 3):
        username = random.choice(usernames[:5])
        base = now - timedelta(minutes=cluster * 17)
        for offset in range(6):
            events.append(
                event(
                    raw_log_id,
                    base + timedelta(seconds=offset * 30),
                    source_ip=ip,
                    hostname="auth-01",
                    username=username,
                    event_type="failed_login",
                    event_category="authentication",
                    severity="medium",
                    message=f"Failed SSH login for {username}",
                )
            )
        events.append(
            event(
                raw_log_id,
                base + timedelta(minutes=5),
                source_ip=ip,
                hostname="auth-01",
                username=username,
                event_type="successful_login",
                event_category="authentication",
                severity="low",
                message=f"Successful SSH login for {username}",
            )
        )

    for index in range(9):
        ip = random.choice(suspicious_ips)
        base = now - timedelta(minutes=40 + index * 9)
        for offset in range(18):
            path = random.choice(["/missing", "/admin", "/wp-admin", "/.env", "/config.php", "/backup.zip"])
            status = 404 if path == "/missing" else random.choice([401, 403, 404])
            events.append(
                event(
                    raw_log_id,
                    base + timedelta(seconds=offset * 20),
                    source_ip=ip,
                    hostname="web-01",
                    event_type="http_404" if status == 404 else "sensitive_path_access",
                    event_category="web",
                    severity="medium",
                    message=f"GET {path} returned {status}",
                    request_path=path,
                    http_method="GET",
                    status_code=status,
                    user_agent=random.choice(agents[2:]),
                )
            )

    for index in range(5):
        base = now - timedelta(minutes=120 + index * 11)
        for offset in range(22):
            events.append(
                event(
                    raw_log_id,
                    base + timedelta(seconds=offset * 15),
                    source_ip=random.choice(["198.51.100.200", "45.88.12.24"]),
                    destination_ip=f"10.0.0.{random.randint(2, 40)}",
                    hostname="fw-01",
                    event_type="firewall_denied",
                    event_category="network",
                    severity="medium",
                    message="Firewall DENY traffic to protected subnet",
                )
            )

    for index in range(20):
        ip = random.choice(["45.88.12.24", "91.220.44.8", "185.199.110.15"])
        events.append(
            event(
                raw_log_id,
                now - timedelta(minutes=5 + index),
                source_ip=ip,
                hostname="auth-01",
                username=random.choice(["admin", "root", "administrator"]),
                event_type="successful_login",
                event_category="authentication",
                severity="low",
                message="Privileged account login",
            )
        )

    return events


def event(raw_log_id: int, timestamp: datetime, **kwargs) -> NormalizedEvent:
    source_ip = kwargs.get("source_ip")
    return NormalizedEvent(
        raw_log_id=raw_log_id,
        timestamp=timestamp,
        source_ip=source_ip,
        destination_ip=kwargs.get("destination_ip"),
        username=kwargs.get("username"),
        hostname=kwargs.get("hostname"),
        event_type=kwargs.get("event_type", "generic_event"),
        event_category=kwargs.get("event_category", "generic"),
        severity=kwargs.get("severity", "low"),
        message=kwargs.get("message", "Demo event"),
        raw_log=kwargs.get("raw_log", "generated demo log"),
        user_agent=kwargs.get("user_agent"),
        request_path=kwargs.get("request_path"),
        http_method=kwargs.get("http_method"),
        status_code=kwargs.get("status_code"),
        geo_country=country_for_ip(source_ip),
    )


def country_for_ip(ip: str | None) -> str | None:
    if not ip:
        return None
    if ip.startswith("203.0.113."):
        return "US"
    if ip.startswith("198.51.100."):
        return "DE"
    if ip.startswith("45."):
        return "RU"
    if ip.startswith("91."):
        return "CN"
    if ip.startswith("185."):
        return "NL"
    return "US"
