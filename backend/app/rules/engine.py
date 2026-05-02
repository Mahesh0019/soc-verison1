from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.models import Alert, AlertEvent, DetectionRule, NormalizedEvent, ThreatIndicator


ACTIVE_ALERT_STATUSES = ("open", "investigating")


def evaluate_rules_for_events(db: Session, events: list[NormalizedEvent]) -> int:
    if not events:
        return 0
    rules = db.query(DetectionRule).filter(DetectionRule.enabled.is_(True)).all()
    touched_alert_ids: set[int] = set()
    for rule in rules:
        rule_type = rule.conditions_json.get("type", "threshold")
        if rule_type == "sequence_success_after_failures":
            touched_alert_ids.update(evaluate_success_after_failures(db, rule, events))
        elif rule_type == "blacklist":
            touched_alert_ids.update(evaluate_blacklist(db, rule, events))
        else:
            touched_alert_ids.update(evaluate_threshold_rule(db, rule, events))
    db.flush()
    return len(touched_alert_ids)


def evaluate_threshold_rule(db: Session, rule: DetectionRule, events: list[NormalizedEvent]) -> set[int]:
    alert_ids: set[int] = set()
    filters = rule.conditions_json.get("filters", {})
    group_by = rule.conditions_json.get("group_by", ["source_ip"])
    for event in events:
        if not event_matches_filters(event, filters):
            continue
        group_values = {field: getattr(event, field, None) for field in group_by}
        if any(value in (None, "") for value in group_values.values()):
            continue
        start = event.timestamp - timedelta(minutes=rule.time_window_minutes)
        query = db.query(NormalizedEvent).filter(NormalizedEvent.timestamp >= start, NormalizedEvent.timestamp <= event.timestamp)
        query = apply_filters(query, filters)
        for field, value in group_values.items():
            query = query.filter(getattr(NormalizedEvent, field) == value)
        related = query.order_by(NormalizedEvent.timestamp.desc()).limit(250).all()
        if len(related) >= rule.threshold:
            alert = upsert_alert(db, rule, event, related, group_values)
            alert_ids.add(alert.id)
    return alert_ids


def evaluate_success_after_failures(db: Session, rule: DetectionRule, events: list[NormalizedEvent]) -> set[int]:
    alert_ids: set[int] = set()
    for event in events:
        if event.event_type != "successful_login" or not event.source_ip:
            continue
        start = event.timestamp - timedelta(minutes=rule.time_window_minutes)
        query = db.query(NormalizedEvent).filter(
            NormalizedEvent.timestamp >= start,
            NormalizedEvent.timestamp <= event.timestamp,
            NormalizedEvent.event_type == "failed_login",
            NormalizedEvent.source_ip == event.source_ip,
        )
        if event.username:
            query = query.filter(or_(NormalizedEvent.username == event.username, NormalizedEvent.username.is_(None)))
        failures = query.order_by(NormalizedEvent.timestamp.desc()).limit(250).all()
        if len(failures) >= rule.threshold:
            alert = upsert_alert(db, rule, event, failures + [event], {"source_ip": event.source_ip, "username": event.username})
            alert_ids.add(alert.id)
    return alert_ids


def evaluate_blacklist(db: Session, rule: DetectionRule, events: list[NormalizedEvent]) -> set[int]:
    alert_ids: set[int] = set()
    indicators = db.query(ThreatIndicator).all()
    ip_values = {indicator.value for indicator in indicators if indicator.type == "ip"}
    username_values = {indicator.value.lower() for indicator in indicators if indicator.type == "username"}
    domain_values = {indicator.value.lower() for indicator in indicators if indicator.type == "domain"}
    for event in events:
        matched = False
        if event.source_ip in ip_values or event.destination_ip in ip_values:
            matched = True
        if event.username and event.username.lower() in username_values:
            matched = True
        if event.request_path and any(domain in event.request_path.lower() for domain in domain_values):
            matched = True
        if not matched:
            continue
        alert = upsert_alert(db, rule, event, [event], {"source_ip": event.source_ip, "username": event.username}, forced_title="Blacklisted indicator matched")
        alert_ids.add(alert.id)
    return alert_ids


def upsert_alert(
    db: Session,
    rule: DetectionRule,
    anchor_event: NormalizedEvent,
    related_events: list[NormalizedEvent],
    group_values: dict[str, Any],
    forced_title: str | None = None,
) -> Alert:
    source_ip = group_values.get("source_ip") or anchor_event.source_ip
    affected_user = group_values.get("username") or anchor_event.username
    window_start = anchor_event.timestamp - timedelta(minutes=rule.time_window_minutes)
    query = db.query(Alert).filter(
        Alert.rule_id == rule.id,
        Alert.status.in_(ACTIVE_ALERT_STATUSES),
        Alert.last_seen >= window_start,
    )
    if source_ip:
        query = query.filter(Alert.source_ip == source_ip)
    if affected_user:
        query = query.filter(Alert.affected_user == affected_user)
    alert = query.order_by(Alert.last_seen.desc()).first()
    first_seen = min(as_aware(event.timestamp) for event in related_events)
    last_seen = max(as_aware(event.timestamp) for event in related_events)
    if alert:
        alert.last_seen = max(as_aware(alert.last_seen), last_seen)
        alert.first_seen = min(as_aware(alert.first_seen), first_seen)
        alert.event_count = max(alert.event_count, len(related_events))
    else:
        alert = Alert(
            rule_id=rule.id,
            title=forced_title or rule.name,
            description=build_alert_description(rule, related_events, group_values),
            severity=rule.severity,
            status="open",
            source_ip=source_ip,
            affected_user=affected_user,
            first_seen=first_seen,
            last_seen=last_seen,
            event_count=len(related_events),
        )
        db.add(alert)
        db.flush()
    link_events(db, alert, related_events)
    return alert


def build_alert_description(rule: DetectionRule, related_events: list[NormalizedEvent], group_values: dict[str, Any]) -> str:
    group_text = ", ".join(f"{key}={value}" for key, value in group_values.items() if value)
    return f"{rule.description} Matched {len(related_events)} events within {rule.time_window_minutes} minutes. {group_text}".strip()


def as_aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def link_events(db: Session, alert: Alert, events: list[NormalizedEvent]) -> None:
    pending = {(item.alert_id, item.event_id) for item in db.new if isinstance(item, AlertEvent)}
    with db.no_autoflush:
        existing = {row.event_id for row in db.query(AlertEvent).filter(AlertEvent.alert_id == alert.id).all()}
    for event in events:
        key = (alert.id, event.id)
        if event.id not in existing and key not in pending:
            db.add(AlertEvent(alert_id=alert.id, event_id=event.id))
            existing.add(event.id)
            pending.add(key)


def event_matches_filters(event: NormalizedEvent, filters: dict[str, Any]) -> bool:
    for key, expected in filters.items():
        value = getattr(event, key, None)
        if key == "status_code_range":
            low, high = expected
            if event.status_code is None or not (low <= event.status_code <= high):
                return False
        elif key == "request_path_contains_any":
            haystack = (event.request_path or "").lower()
            if not any(str(token).lower() in haystack for token in expected):
                return False
        elif key == "user_agent_contains_any":
            haystack = (event.user_agent or "").lower()
            if not any(str(token).lower() in haystack for token in expected):
                return False
        elif key == "geo_country_not_in":
            if event.geo_country in expected:
                return False
        elif key == "username_in":
            if (event.username or "").lower() not in {str(item).lower() for item in expected}:
                return False
        elif isinstance(expected, list):
            if value not in expected:
                return False
        elif value != expected:
            return False
    return True


def apply_filters(query, filters: dict[str, Any]):
    for key, expected in filters.items():
        if key == "status_code_range":
            low, high = expected
            query = query.filter(NormalizedEvent.status_code >= low, NormalizedEvent.status_code <= high)
        elif key == "request_path_contains_any":
            clauses = [NormalizedEvent.request_path.ilike(f"%{token}%") for token in expected]
            query = query.filter(or_(*clauses))
        elif key == "user_agent_contains_any":
            clauses = [NormalizedEvent.user_agent.ilike(f"%{token}%") for token in expected]
            query = query.filter(or_(*clauses))
        elif key == "geo_country_not_in":
            query = query.filter(~NormalizedEvent.geo_country.in_(expected))
        elif key == "username_in":
            query = query.filter(NormalizedEvent.username.in_(expected))
        elif isinstance(expected, list):
            query = query.filter(getattr(NormalizedEvent, key).in_(expected))
        else:
            query = query.filter(getattr(NormalizedEvent, key) == expected)
    return query
