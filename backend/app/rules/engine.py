import posixpath
import statistics
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import unquote, urlsplit

from sqlalchemy import and_, case, func, or_
from sqlalchemy.orm import Session

from app.models import Alert, AlertEvent, DetectionRule, NormalizedEvent, ThreatIndicator


ACTIVE_ALERT_STATUSES = ("open", "investigating")


def evaluate_rules_for_events(
    db: Session,
    events: list[NormalizedEvent],
    auto_correlate: bool = True,
    use_batched_threshold: bool = False,
    rules_override: list[DetectionRule] | None = None,
) -> int:
    if not events:
        return 0
    if rules_override is not None:
        rules = rules_override
    else:
        rules = (
            db.query(DetectionRule)
            .filter(
                DetectionRule.enabled.is_(True),
                or_(DetectionRule.status.is_(None), DetectionRule.status == "ACTIVE"),
            )
            .all()
        )
    touched_alert_ids: set[int] = set()
    for rule in rules:
        rule_type = rule.conditions_json.get("type", "threshold")
        if rule_type == "sequence_success_after_failures":
            touched_alert_ids.update(evaluate_success_after_failures(db, rule, events))
        elif rule_type == "blacklist":
            touched_alert_ids.update(evaluate_blacklist(db, rule, events))
        elif rule_type == "pattern":
            touched_alert_ids.update(evaluate_pattern_rule(db, rule, events))
        elif rule_type == "dynamic_baseline":
            touched_alert_ids.update(evaluate_dynamic_baseline(db, rule, events))
        else:
            if use_batched_threshold:
                touched_alert_ids.update(evaluate_threshold_rule_batched(db, rule, events))
            else:
                touched_alert_ids.update(evaluate_threshold_rule(db, rule, events))
    db.flush()
    if auto_correlate and touched_alert_ids:
        from app.rules.correlation import correlate_incidents
        correlate_incidents(db, touched_alert_ids)
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
        related = [r for r in related if event_matches_filters(r, filters)]
        if len(related) >= rule.threshold:
            alert = upsert_alert(db, rule, event, related, group_values)
            alert_ids.add(alert.id)
    return alert_ids


def evaluate_threshold_rule_batched(db: Session, rule: DetectionRule, events: list[NormalizedEvent]) -> set[int]:
    alert_ids: set[int] = set()
    filters = rule.conditions_json.get("filters", {})
    group_by = rule.conditions_json.get("group_by", ["source_ip"])

    valid_events: list[NormalizedEvent] = []
    unique_groups: set[tuple[tuple[str, Any], ...]] = set()

    for event in events:
        if not event_matches_filters(event, filters):
            continue
        group_items = tuple((field, getattr(event, field, None)) for field in group_by)
        if any(val in (None, "") for _, val in group_items):
            continue
        valid_events.append(event)
        unique_groups.add(group_items)

    if not valid_events:
        return alert_ids

    for group_items in unique_groups:
        group_dict = dict(group_items)
        group_events = [
            ev for ev in valid_events
            if all(getattr(ev, field) == val for field, val in group_dict.items())
        ]
        if not group_events:
            continue

        min_ts = min(ev.timestamp for ev in group_events)
        max_ts = max(ev.timestamp for ev in group_events)
        window_delta = timedelta(minutes=rule.time_window_minutes)
        start_ts = min_ts - window_delta

        query = db.query(NormalizedEvent).filter(
            NormalizedEvent.timestamp >= start_ts,
            NormalizedEvent.timestamp <= max_ts,
        )
        query = apply_filters(query, filters)
        for field, val in group_dict.items():
            query = query.filter(getattr(NormalizedEvent, field) == val)
        all_related = query.order_by(NormalizedEvent.timestamp.desc()).all()

        for event in group_events:
            ev_start = event.timestamp - window_delta
            window_matches = [
                r for r in all_related
                if ev_start <= r.timestamp <= event.timestamp and event_matches_filters(r, filters)
            ][:250]
            if len(window_matches) >= rule.threshold:
                alert = upsert_alert(db, rule, event, window_matches, group_dict)
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


def evaluate_pattern_rule(db: Session, rule: DetectionRule, events: list[NormalizedEvent]) -> set[int]:
    alert_ids: set[int] = set()
    filters = rule.conditions_json.get("filters", {})
    group_by = rule.conditions_json.get("group_by", ["source_ip"])
    for event in events:
        if not event_matches_filters(event, filters):
            continue
        group_values = {field: getattr(event, field, None) for field in group_by}
        start = event.timestamp - timedelta(minutes=rule.time_window_minutes)
        query = db.query(NormalizedEvent).filter(NormalizedEvent.timestamp >= start, NormalizedEvent.timestamp <= event.timestamp)
        query = apply_filters(query, filters)
        for field, value in group_values.items():
            if value:
                query = query.filter(getattr(NormalizedEvent, field) == value)
        related = query.order_by(NormalizedEvent.timestamp.desc()).limit(250).all()
        if not related:
            related = [event]
        if len(related) >= rule.threshold:
            alert = upsert_alert(db, rule, event, related, group_values)
            alert_ids.add(alert.id)
    return alert_ids


def evaluate_dynamic_baseline(db: Session, rule: DetectionRule, events: list[NormalizedEvent]) -> set[int]:
    alert_ids: set[int] = set()
    filters = rule.conditions_json.get("filters", {})
    group_by = rule.conditions_json.get("group_by", ["source_ip"])
    eval_window_min = rule.conditions_json.get("evaluation_window_minutes", rule.time_window_minutes or 5)
    baseline_window_min = rule.conditions_json.get("baseline_window_minutes", 30)
    bucket_size_min = rule.conditions_json.get("bucket_size_minutes", 5)
    sigma_multiplier = float(rule.conditions_json.get("sigma_multiplier", 2.0))
    min_floor = int(rule.conditions_json.get("min_floor", rule.threshold or 40))
    max_ceiling = rule.conditions_json.get("max_ceiling")
    if max_ceiling is not None:
        max_ceiling = int(max_ceiling)
    update_strategy = rule.conditions_json.get("update_strategy", "rolling_sma")
    ewma_alpha = float(rule.conditions_json.get("ewma_alpha", 0.3))

    evaluated_groups: set[tuple[tuple[tuple[str, Any], ...], datetime]] = set()

    for event in events:
        if not event_matches_filters(event, filters):
            continue
        group_items = tuple((field, getattr(event, field, None)) for field in group_by)
        if any(v in (None, "") for _, v in group_items):
            continue

        anchor_key = (group_items, event.timestamp)
        if anchor_key in evaluated_groups:
            continue
        evaluated_groups.add(anchor_key)

        group_values = dict(group_items)
        eval_start = event.timestamp - timedelta(minutes=eval_window_min)
        eval_query = db.query(NormalizedEvent).filter(
            NormalizedEvent.timestamp >= eval_start,
            NormalizedEvent.timestamp <= event.timestamp,
        )
        eval_query = apply_filters(eval_query, filters)
        for field, value in group_values.items():
            if value is not None:
                eval_query = eval_query.filter(getattr(NormalizedEvent, field) == value)
        current_related = eval_query.order_by(NormalizedEvent.timestamp.desc()).limit(500).all()
        current_related = [r for r in current_related if event_matches_filters(r, filters)]
        current_volume = len(current_related)

        base_start = eval_start - timedelta(minutes=baseline_window_min)
        base_end = eval_start
        base_query = db.query(NormalizedEvent).filter(
            NormalizedEvent.timestamp >= base_start,
            NormalizedEvent.timestamp < base_end,
        )
        base_query = apply_filters(base_query, filters)
        for field, value in group_values.items():
            if value is not None:
                base_query = base_query.filter(getattr(NormalizedEvent, field) == value)
        base_events = base_query.all()
        base_events = [r for r in base_events if event_matches_filters(r, filters)]

        num_buckets = max(1, baseline_window_min // bucket_size_min)
        bucket_counts = [0] * num_buckets
        for b_ev in base_events:
            offset_sec = (b_ev.timestamp - base_start).total_seconds()
            bucket_idx = int(offset_sec // (bucket_size_min * 60))
            if 0 <= bucket_idx < num_buckets:
                bucket_counts[bucket_idx] += 1
            elif bucket_idx == num_buckets:
                bucket_counts[-1] += 1

        if not base_events:
            mean_val = 0.0
            std_val = 0.0
        else:
            if update_strategy == "ewma":
                ewma_val = float(bucket_counts[0])
                for count in bucket_counts[1:]:
                    ewma_val = ewma_alpha * count + (1.0 - ewma_alpha) * ewma_val
                mean_val = ewma_val
                diffs = [(c - mean_val) ** 2 for c in bucket_counts]
                std_val = (sum(diffs) / len(diffs)) ** 0.5
            elif update_strategy == "periodic":
                mean_val = statistics.median(bucket_counts)
                std_val = statistics.stdev(bucket_counts) if len(bucket_counts) > 1 else 0.0
            else:
                mean_val = statistics.mean(bucket_counts)
                std_val = statistics.stdev(bucket_counts) if len(bucket_counts) > 1 else 0.0

        calc_threshold = mean_val + (sigma_multiplier * std_val)
        effective_threshold = max(float(min_floor), calc_threshold)
        if max_ceiling is not None:
            effective_threshold = min(float(max_ceiling), effective_threshold)

        if current_volume >= effective_threshold:
            alert = upsert_alert(
                db,
                rule,
                event,
                current_related,
                group_values,
                forced_title=f"{rule.name} (Dynamic: {current_volume} >= {effective_threshold:.1f}, base_mean={mean_val:.1f}, sigma={std_val:.1f})",
            )
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


def normalize_request_path(raw_path: str | None) -> str:
    if not raw_path:
        return ""
    try:
        parsed = urlsplit(str(raw_path).strip())
        path = parsed.path
    except Exception:
        path = str(raw_path).split("?", 1)[0].split("#", 1)[0]

    if not path:
        return ""

    try:
        path = unquote(path)
    except Exception:
        pass

    normalized = posixpath.normpath(path)
    if path.endswith("/") and not normalized.endswith("/"):
        normalized = normalized + "/"
    return normalized.lower()


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
        elif key == "request_path_not_contains_any":
            if expected:
                norm_path = normalize_request_path(event.request_path)
                if norm_path and any(str(token).lower() in norm_path for token in expected if token):
                    return False
        elif key == "user_agent_contains_any":
            haystack = (event.user_agent or "").lower()
            if not any(str(token).lower() in haystack for token in expected):
                return False
        elif key == "pattern_any":
            haystack = f"{event.request_path or ''} {event.message or ''} {event.raw_log or ''} {getattr(event, 'raw_reference', None) or ''} {getattr(event, 'command_line', None) or ''}".lower()
            if not any(str(token).lower() in haystack for token in expected):
                return False
        elif key == "command_line_contains_any":
            haystack = (getattr(event, "command_line", None) or "").lower()
            if not any(str(token).lower() in haystack for token in expected):
                return False
        elif key == "dns_query_contains_any":
            haystack = (getattr(event, "dns_query", None) or "").lower()
            if not any(str(token).lower() in haystack for token in expected):
                return False
        elif key == "process_in":
            val = (getattr(event, "process", None) or "").lower()
            if val not in {str(item).lower() for item in expected}:
                return False
        elif key == "parent_process_in":
            val = (getattr(event, "parent_process", None) or "").lower()
            if val not in {str(item).lower() for item in expected}:
                return False
        elif key == "destination_port_in":
            if getattr(event, "destination_port", None) not in expected:
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
        elif key == "request_path_not_contains_any":
            if expected:
                active_tokens = [str(token) for token in expected if token]
                if active_tokens:
                    clean_path = case(
                        (NormalizedEvent.request_path.contains("?"), func.substr(NormalizedEvent.request_path, 1, func.instr(NormalizedEvent.request_path, "?") - 1)),
                        (NormalizedEvent.request_path.contains("#"), func.substr(NormalizedEvent.request_path, 1, func.instr(NormalizedEvent.request_path, "#") - 1)),
                        else_=NormalizedEvent.request_path,
                    )
                    clauses = [~clean_path.ilike(f"%{token}%") for token in active_tokens]
                    query = query.filter(or_(NormalizedEvent.request_path.is_(None), and_(*clauses)))
        elif key == "user_agent_contains_any":
            clauses = [NormalizedEvent.user_agent.ilike(f"%{token}%") for token in expected]
            query = query.filter(or_(*clauses))
        elif key == "pattern_any":
            clauses = []
            for token in expected:
                clauses.append(NormalizedEvent.request_path.ilike(f"%{token}%"))
                clauses.append(NormalizedEvent.message.ilike(f"%{token}%"))
                clauses.append(NormalizedEvent.raw_reference.ilike(f"%{token}%"))
                clauses.append(NormalizedEvent.command_line.ilike(f"%{token}%"))
            query = query.filter(or_(*clauses))
        elif key == "command_line_contains_any":
            clauses = [NormalizedEvent.command_line.ilike(f"%{token}%") for token in expected]
            query = query.filter(or_(*clauses))
        elif key == "dns_query_contains_any":
            clauses = [NormalizedEvent.dns_query.ilike(f"%{token}%") for token in expected]
            query = query.filter(or_(*clauses))
        elif key == "process_in":
            query = query.filter(func.lower(NormalizedEvent.process).in_([str(item).lower() for item in expected]))
        elif key == "parent_process_in":
            query = query.filter(func.lower(NormalizedEvent.parent_process).in_([str(item).lower() for item in expected]))
        elif key == "destination_port_in":
            query = query.filter(NormalizedEvent.destination_port.in_(expected))
        elif key == "geo_country_not_in":
            query = query.filter(~NormalizedEvent.geo_country.in_(expected))
        elif key == "username_in":
            query = query.filter(NormalizedEvent.username.in_(expected))
        elif isinstance(expected, list):
            query = query.filter(getattr(NormalizedEvent, key).in_(expected))
        else:
            query = query.filter(getattr(NormalizedEvent, key) == expected)
    return query
