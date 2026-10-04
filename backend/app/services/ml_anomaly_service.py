"""
backend/app/services/ml_anomaly_service.py

Behavioral ML Anomaly Detection Engine (Phase 7):
- Extracts behavioral feature vectors from event sequences / entity windows:
  * request_rate, 4xx/5xx error ratios, path entropy, method diversity,
    status diversity, off-hours deviation, sensitive path ratio, failed login ratio.
- Lightweight Isolation Forest model from scikit-learn (fast, low-memory footprint).
- Standardized explainability with feature deviation attribution.
- Robust graceful fallback for sparse or initial bootstrap data.
- Integration into Detection Quality Engine factor scoring.
"""

from __future__ import annotations

import collections
import math
from datetime import UTC, datetime, timedelta
from typing import Any, Optional

import numpy as np
from sklearn.ensemble import IsolationForest
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models import Alert, AlertEvent, NormalizedEvent


FEATURE_NAMES = [
    "request_rate",
    "error_ratio_4xx",
    "error_ratio_5xx",
    "path_entropy",
    "method_diversity",
    "status_diversity",
    "off_hours_ratio",
    "unique_paths_ratio",
    "failed_login_ratio",
    "sensitive_path_ratio",
]

SENSITIVE_KEYWORDS = [
    "admin",
    "api",
    "config",
    ".env",
    "login",
    "auth",
    "secret",
    "token",
    "exec",
    "backup",
    "db",
    "ftp",
    "passwd",
    "shadow",
    "system",
    "root",
    "setup",
    "install",
    "swagger",
    "graphql",
]


def calculate_shannon_entropy(items: list[str]) -> float:
    """Computes Shannon entropy in bits for a list of string items (e.g., URI paths)."""
    if not items:
        return 0.0
    total = len(items)
    counts = collections.Counter(items)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def extract_features_from_events(events: list[NormalizedEvent]) -> dict[str, float]:
    """
    Extracts numerical behavioral feature vector from a list of NormalizedEvents.
    Returns normalized feature dictionary.
    """
    total = len(events)
    if total == 0:
        return {k: 0.0 for k in FEATURE_NAMES}

    # Time span for request rate
    timestamps = [e.timestamp for e in events if e.timestamp]
    if len(timestamps) >= 2:
        span_seconds = abs((max(timestamps) - min(timestamps)).total_seconds())
        span_minutes = max(1.0, span_seconds / 60.0)
    else:
        span_minutes = 1.0

    request_rate = round(total / span_minutes, 2)

    # 4xx and 5xx errors
    status_codes = [e.status_code for e in events if e.status_code is not None]
    count_4xx = sum(1 for c in status_codes if 400 <= c < 500)
    count_5xx = sum(1 for c in status_codes if 500 <= c < 600)
    error_ratio_4xx = round(count_4xx / total, 4)
    error_ratio_5xx = round(count_5xx / total, 4)

    # Path entropy and uniqueness
    paths = [e.request_path for e in events if e.request_path]
    path_entropy = calculate_shannon_entropy(paths) if paths else 0.0
    unique_paths_ratio = round(len(set(paths)) / total, 4) if paths else 0.0

    # HTTP method and status diversity
    methods = [e.http_method.upper() for e in events if e.http_method]
    method_diversity = round(len(set(methods)) / 5.0, 4)  # normalized relative to 5 common methods
    method_diversity = min(1.0, method_diversity)

    distinct_statuses = set(status_codes)
    status_diversity = round(len(distinct_statuses) / 8.0, 4)
    status_diversity = min(1.0, status_diversity)

    # Off-hours activity (outside 06:00 - 22:00 UTC)
    off_hours_count = 0
    for ts in timestamps:
        hour = ts.hour if hasattr(ts, "hour") else 12
        if hour < 6 or hour >= 22:
            off_hours_count += 1
    off_hours_ratio = round(off_hours_count / total, 4)

    # Failed login attempts
    failed_logins = 0
    for e in events:
        msg = (e.message or "").lower()
        evt_type = (e.event_type or "").lower()
        if ("login" in evt_type or "auth" in evt_type or "login" in msg) and (
            e.status_code in (401, 403) or "fail" in msg or "denied" in msg or (e.severity and e.severity.lower() in ("high", "critical"))
        ):
            failed_logins += 1
    failed_login_ratio = round(failed_logins / total, 4)

    # Sensitive path ratio
    sensitive_count = 0
    for p in paths:
        p_lower = p.lower()
        if any(keyword in p_lower for keyword in SENSITIVE_KEYWORDS):
            sensitive_count += 1
    sensitive_path_ratio = round(sensitive_count / total, 4) if paths else 0.0

    return {
        "request_rate": request_rate,
        "error_ratio_4xx": error_ratio_4xx,
        "error_ratio_5xx": error_ratio_5xx,
        "path_entropy": path_entropy,
        "method_diversity": method_diversity,
        "status_diversity": status_diversity,
        "off_hours_ratio": off_hours_ratio,
        "unique_paths_ratio": unique_paths_ratio,
        "failed_login_ratio": failed_login_ratio,
        "sensitive_path_ratio": sensitive_path_ratio,
    }


class BehavioralAnomalyDetector:
    """
    Lightweight Isolation Forest Anomaly Detector with feature explainability
    and automatic graceful fallback.
    """

    def __init__(self, contamination: float = 0.08, n_estimators: int = 50):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.model: Optional[IsolationForest] = None
        self.is_fitted: bool = False
        self.sample_count: int = 0
        self.last_trained: Optional[datetime] = None
        self.feature_names = list(FEATURE_NAMES)

        # Baseline reference statistics (mean, std)
        self.baseline_means: dict[str, float] = {
            "request_rate": 5.0,
            "error_ratio_4xx": 0.04,
            "error_ratio_5xx": 0.01,
            "path_entropy": 1.2,
            "method_diversity": 0.20,
            "status_diversity": 0.25,
            "off_hours_ratio": 0.10,
            "unique_paths_ratio": 0.20,
            "failed_login_ratio": 0.02,
            "sensitive_path_ratio": 0.05,
        }
        self.baseline_stds: dict[str, float] = {
            "request_rate": 8.0,
            "error_ratio_4xx": 0.08,
            "error_ratio_5xx": 0.03,
            "path_entropy": 0.8,
            "method_diversity": 0.20,
            "status_diversity": 0.20,
            "off_hours_ratio": 0.15,
            "unique_paths_ratio": 0.20,
            "failed_login_ratio": 0.05,
            "sensitive_path_ratio": 0.10,
        }

    def _feature_dict_to_array(self, feat_dict: dict[str, float]) -> np.ndarray:
        return np.array([feat_dict.get(k, 0.0) for k in self.feature_names], dtype=np.float32).reshape(1, -1)

    def fit(self, samples: list[dict[str, float]]) -> dict[str, Any]:
        """
        Fits the Isolation Forest on a batch of feature dictionaries.
        """
        if len(samples) < 4:
            # Insufficient samples for statistical ML; retain baseline references
            return {
                "success": False,
                "reason": "Insufficient samples (minimum 4 required)",
                "sample_count": len(samples),
            }

        matrix = np.array(
            [[s.get(k, 0.0) for k in self.feature_names] for s in samples],
            dtype=np.float32,
        )

        model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=42,
        )
        model.fit(matrix)

        self.model = model
        self.is_fitted = True
        self.sample_count = len(samples)
        self.last_trained = datetime.now(UTC)

        # Update empirical baseline statistics
        means = np.mean(matrix, axis=0)
        stds = np.std(matrix, axis=0)
        for i, name in enumerate(self.feature_names):
            self.baseline_means[name] = round(float(means[i]), 4)
            # prevent division by zero
            self.baseline_stds[name] = max(0.01, round(float(stds[i]), 4))

        return {
            "success": True,
            "sample_count": self.sample_count,
            "feature_dimensions": len(self.feature_names),
            "contamination": self.contamination,
            "trained_at": self.last_trained,
        }

    def score_features(
        self,
        features: dict[str, float],
        entity_type: str = "entity",
        entity_id: str = "unknown",
    ) -> dict[str, Any]:
        """
        Calculates normalized anomaly score [0.0, 1.0], classification, and explainability breakdown.
        """
        # Calculate feature deviations against baseline
        deviations: dict[str, float] = {}
        for name in self.feature_names:
            val = features.get(name, 0.0)
            mean = self.baseline_means.get(name, 0.0)
            std = self.baseline_stds.get(name, 1.0)
            z = max(0.0, (val - mean) / max(0.01, std))
            deviations[name] = round(min(1.0, z / 3.0), 3)  # mapped to [0.0, 1.0]

        # Identify primary contributing factor
        sorted_devs = sorted(deviations.items(), key=lambda item: item[1], reverse=True)
        top_feature, top_dev = sorted_devs[0] if sorted_devs else ("request_rate", 0.0)

        feature_val = features.get(top_feature, 0.0)
        base_val = self.baseline_means.get(top_feature, 0.0)
        primary_factor = f"{top_feature.replace('_', ' ').capitalize()} ({feature_val:.2f} vs normal {base_val:.2f})"

        # Determine anomaly score
        top_3_dev_avg = sum(d[1] for d in sorted_devs[:3]) / max(1, min(3, len(sorted_devs)))

        if self.is_fitted and self.model is not None:
            arr = self._feature_dict_to_array(features)
            # sklearn score_samples is negative; -score_samples is positive (inlier ~0.45, outlier ~0.58-0.75)
            tree_raw = -float(self.model.score_samples(arr)[0])
            tree_score = min(1.0, max(0.0, (tree_raw - 0.40) / 0.30))

            # Hybrid calibrated anomaly score: 50% tree isolation depth + 50% feature baseline deviation
            combined_score = (0.50 * tree_score) + (0.50 * top_3_dev_avg)
            anomaly_score = round(min(1.0, max(0.0, combined_score)), 3)
            is_anomaly = bool(self.model.predict(arr)[0] == -1 or anomaly_score >= 0.55 or top_dev >= 0.75)
            confidence = round(min(1.0, abs(anomaly_score - 0.5) * 2.0 + 0.3), 2)
        else:
            # Fallback heuristic calculation
            heuristic_score = (
                (0.30 * deviations.get("error_ratio_4xx", 0.0))
                + (0.25 * deviations.get("sensitive_path_ratio", 0.0))
                + (0.20 * deviations.get("path_entropy", 0.0))
                + (0.15 * deviations.get("failed_login_ratio", 0.0))
                + (0.10 * deviations.get("request_rate", 0.0))
            )
            anomaly_score = round(min(1.0, max(0.0, max(heuristic_score, top_3_dev_avg * 0.8))), 3)
            is_anomaly = anomaly_score >= 0.50
            confidence = 0.70


        if is_anomaly:
            explanation = (
                f"Anomalous behavioral profile detected for {entity_type} {entity_id} "
                f"(Score: {anomaly_score:.2f}). Primary driver: {primary_factor}."
            )
        else:
            explanation = (
                f"Behavioral profile for {entity_type} {entity_id} appears consistent with normal activity "
                f"(Score: {anomaly_score:.2f})."
            )

        return {
            "entity_type": entity_type,
            "entity_id": str(entity_id),
            "anomaly_score": anomaly_score,
            "is_anomaly": is_anomaly,
            "confidence": confidence,
            "primary_factor": primary_factor,
            "features": features,
            "feature_contributions": deviations,
            "explanation": explanation,
        }


# Global singleton detector instance
_global_detector = BehavioralAnomalyDetector()


def get_behavioral_detector() -> BehavioralAnomalyDetector:
    return _global_detector


def score_ip_behavior(db: Session, ip: str, window_minutes: int = 60) -> dict[str, Any]:
    """
    Extracts events for a given IP in the recent window and computes its behavioral anomaly score.
    """
    detector = get_behavioral_detector()
    since = datetime.now(UTC) - timedelta(minutes=window_minutes)

    events = (
        db.query(NormalizedEvent)
        .filter(NormalizedEvent.source_ip == ip, NormalizedEvent.timestamp >= since)
        .order_by(NormalizedEvent.timestamp.asc())
        .all()
    )

    if not events:
        # Fallback to any recent events for this IP regardless of time window
        events = (
            db.query(NormalizedEvent)
            .filter(NormalizedEvent.source_ip == ip)
            .order_by(NormalizedEvent.timestamp.desc())
            .limit(50)
            .all()
        )

    features = extract_features_from_events(events)
    return detector.score_features(features, entity_type="ip", entity_id=ip)


def score_alert_behavior(db: Session, alert: Alert) -> dict[str, Any]:
    """
    Calculates behavioral anomaly score for an Alert based on its associated events.
    """
    detector = get_behavioral_detector()

    # Query events linked directly to this alert
    events = (
        db.query(NormalizedEvent)
        .join(AlertEvent, AlertEvent.event_id == NormalizedEvent.id)
        .filter(AlertEvent.alert_id == alert.id)
        .order_by(NormalizedEvent.timestamp.asc())
        .all()
    )

    # If no linked events, fall back to matching source_ip events
    if not events and alert.source_ip:
        events = (
            db.query(NormalizedEvent)
            .filter(NormalizedEvent.source_ip == alert.source_ip)
            .order_by(NormalizedEvent.timestamp.desc())
            .limit(30)
            .all()
        )

    features = extract_features_from_events(events)
    return detector.score_features(features, entity_type="alert", entity_id=str(alert.id))


def train_behavioral_model_from_db(
    db: Session,
    window_minutes: int = 1440,
    contamination: float = 0.08,
) -> dict[str, Any]:
    """
    Gathers historical event profiles grouped by source_ip and time window,
    then trains the Isolation Forest anomaly detector.
    """
    detector = get_behavioral_detector()
    detector.contamination = contamination

    # Fetch unique source IPs with events
    active_ips = [
        row[0]
        for row in db.query(NormalizedEvent.source_ip)
        .filter(NormalizedEvent.source_ip.is_not(None))
        .distinct()
        .all()
    ]

    samples: list[dict[str, float]] = []

    for ip in active_ips:
        ip_events = (
            db.query(NormalizedEvent)
            .filter(NormalizedEvent.source_ip == ip)
            .order_by(NormalizedEvent.timestamp.asc())
            .limit(200)
            .all()
        )
        if ip_events:
            features = extract_features_from_events(ip_events)
            samples.append(features)

    # If samples are few, create diverse synthetic normal/borderline samples to bootstrap
    if len(samples) < 5:
        # Augment with baseline normal variation samples
        for rate, err4, entropy in [
            (3.0, 0.02, 0.8),
            (5.0, 0.05, 1.1),
            (8.0, 0.03, 1.4),
            (4.0, 0.01, 0.9),
            (12.0, 0.06, 1.5),
            (2.5, 0.00, 0.5),
        ]:
            samples.append({
                "request_rate": rate,
                "error_ratio_4xx": err4,
                "error_ratio_5xx": 0.01,
                "path_entropy": entropy,
                "method_diversity": 0.20,
                "status_diversity": 0.25,
                "off_hours_ratio": 0.05,
                "unique_paths_ratio": 0.30,
                "failed_login_ratio": 0.00,
                "sensitive_path_ratio": 0.02,
            })

    result = detector.fit(samples)
    return result


def get_recent_behavioral_anomalies(db: Session, limit: int = 20) -> list[dict[str, Any]]:
    """
    Returns recent anomalous entities scored across active IP addresses.
    """
    detector = get_behavioral_detector()
    active_ips = [
        row[0]
        for row in db.query(NormalizedEvent.source_ip)
        .filter(NormalizedEvent.source_ip.is_not(None))
        .distinct()
        .all()
    ]

    results = []
    for ip in active_ips[:50]:
        res = score_ip_behavior(db, ip, window_minutes=120)
        if res.get("is_anomaly") or res.get("anomaly_score", 0.0) >= 0.50:
            results.append(res)

    results.sort(key=lambda r: r.get("anomaly_score", 0.0), reverse=True)
    return results[:limit]
