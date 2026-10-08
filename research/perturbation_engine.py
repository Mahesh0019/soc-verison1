"""
research/perturbation_engine.py

Phase 7: Adversarial Telemetry Perturbation Engine
Provides deterministic, reproducible transformations for evaluating SOC robustness.
Every transformation logs provenance metadata:
  - original_event_id
  - transformed_event_id
  - transformation_type
  - transformation_parameters
  - seed
The original scenario data remains strictly immutable.
"""

from __future__ import annotations

import copy
import hashlib
from datetime import datetime, timedelta
from typing import Any, Optional


class TelemetryPerturbationEngine:
    """
    Applies deterministic perturbations to telemetry scenario event streams.
    """

    def __init__(self, seed: int = 42):
        self.seed = seed

    def _generate_event_id(self, original_id: str, transform_type: str, idx: int) -> str:
        digest = hashlib.sha256(f"{self.seed}:{original_id}:{transform_type}:{idx}".encode("utf-8")).hexdigest()[:8]
        return f"{original_id}_{transform_type}_{digest}"

    def remove_event(
        self,
        events: list[dict[str, Any]],
        target_source: Optional[str] = None,
        target_index: Optional[int] = None,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Removes an event matching source type or specific index."""
        result = []
        transform_log = []
        removed = False

        for i, ev in enumerate(events):
            should_remove = False
            if target_index is not None and i == target_index and not removed:
                should_remove = True
            elif target_source is not None and ev.get("source_type") == target_source and not removed:
                should_remove = True

            if should_remove:
                removed = True
                transform_log.append({
                    "original_event_id": ev.get("raw_reference", f"evt_{i}"),
                    "transformed_event_id": None,
                    "transformation_type": "remove_event",
                    "transformation_parameters": {"target_source": target_source, "target_index": target_index},
                    "seed": self.seed,
                })
            else:
                result.append(copy.deepcopy(ev))

        return result, transform_log

    def duplicate_event(
        self,
        events: list[dict[str, Any]],
        target_index: int = 0,
        time_offset_seconds: float = 0.0,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Duplicates an event at target_index with optional small time offset."""
        result = [copy.deepcopy(e) for e in events]
        transform_log = []

        if 0 <= target_index < len(events):
            orig = events[target_index]
            dup = copy.deepcopy(orig)
            orig_id = orig.get("raw_reference", f"evt_{target_index}")
            new_id = self._generate_event_id(orig_id, "dup", target_index)
            dup["raw_reference"] = new_id

            if time_offset_seconds != 0.0 and "timestamp" in dup:
                try:
                    dt = datetime.fromisoformat(dup["timestamp"])
                    dup["timestamp"] = (dt + timedelta(seconds=time_offset_seconds)).isoformat()
                except Exception:
                    pass

            result.insert(target_index + 1, dup)
            transform_log.append({
                "original_event_id": orig_id,
                "transformed_event_id": new_id,
                "transformation_type": "duplicate_event",
                "transformation_parameters": {"time_offset_seconds": time_offset_seconds},
                "seed": self.seed,
            })

        return result, transform_log

    def reorder_events(
        self,
        events: list[dict[str, Any]],
        reverse: bool = True,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Reorders events (e.g. reverse arrival order)."""
        transform_log = []
        if reverse:
            result = list(reversed([copy.deepcopy(e) for e in events]))
        else:
            result = [copy.deepcopy(e) for e in events]
            if len(result) >= 2:
                result[0], result[1] = result[1], result[0]

        for i, ev in enumerate(result):
            transform_log.append({
                "original_event_id": ev.get("raw_reference", f"evt_{i}"),
                "transformed_event_id": ev.get("raw_reference", f"evt_{i}"),
                "transformation_type": "reorder_events",
                "transformation_parameters": {"reverse": reverse, "new_index": i},
                "seed": self.seed,
            })

        return result, transform_log

    def delay_timestamp(
        self,
        events: list[dict[str, Any]],
        target_source: Optional[str] = None,
        target_index: Optional[int] = None,
        delay_seconds: float = 350.0,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Delays a specific event's timestamp into the future."""
        result = []
        transform_log = []

        for i, ev in enumerate(events):
            item = copy.deepcopy(ev)
            matches = False
            if target_index is not None and i == target_index:
                matches = True
            elif target_source is not None and ev.get("source_type") == target_source:
                matches = True

            orig_id = ev.get("raw_reference", f"evt_{i}")
            if matches and "timestamp" in item:
                try:
                    dt = datetime.fromisoformat(item["timestamp"])
                    item["timestamp"] = (dt + timedelta(seconds=delay_seconds)).isoformat()
                    new_id = self._generate_event_id(orig_id, "delay", i)
                    item["raw_reference"] = new_id
                    transform_log.append({
                        "original_event_id": orig_id,
                        "transformed_event_id": new_id,
                        "transformation_type": "delay_timestamp",
                        "transformation_parameters": {"delay_seconds": delay_seconds},
                        "seed": self.seed,
                    })
                except Exception:
                    pass
            result.append(item)

        return result, transform_log

    def shift_timestamp(
        self,
        events: list[dict[str, Any]],
        shift_seconds: float = 60.0,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Applies a uniform timestamp drift across events."""
        result = []
        transform_log = []

        for i, ev in enumerate(events):
            item = copy.deepcopy(ev)
            orig_id = ev.get("raw_reference", f"evt_{i}")
            if "timestamp" in item:
                try:
                    dt = datetime.fromisoformat(item["timestamp"])
                    item["timestamp"] = (dt + timedelta(seconds=shift_seconds)).isoformat()
                except Exception:
                    pass
            transform_log.append({
                "original_event_id": orig_id,
                "transformed_event_id": orig_id,
                "transformation_type": "shift_timestamp",
                "transformation_parameters": {"shift_seconds": shift_seconds},
                "seed": self.seed,
            })
            result.append(item)

        return result, transform_log

    def mutate_case(
        self,
        events: list[dict[str, Any]],
        target_fields: list[str] = ("command_line", "process", "request_path"),
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Mutates casing on target attributes (e.g. pOwErShElL.ExE, cMd.eXe)."""
        result = []
        transform_log = []

        def alternate_case(s: str) -> str:
            return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(s))

        for i, ev in enumerate(events):
            item = copy.deepcopy(ev)
            mutated = False
            orig_id = ev.get("raw_reference", f"evt_{i}")
            for field in target_fields:
                if field in item and isinstance(item[field], str) and item[field]:
                    item[field] = alternate_case(item[field])
                    mutated = True

            if mutated:
                new_id = self._generate_event_id(orig_id, "case", i)
                item["raw_reference"] = new_id
                transform_log.append({
                    "original_event_id": orig_id,
                    "transformed_event_id": new_id,
                    "transformation_type": "mutate_case",
                    "transformation_parameters": {"target_fields": list(target_fields)},
                    "seed": self.seed,
                })
            result.append(item)

        return result, transform_log

    def remove_optional_field(
        self,
        events: list[dict[str, Any]],
        target_fields: list[str] = ("hostname", "process_id", "parent_process"),
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Strips optional identity fields to test missing field resilience."""
        result = []
        transform_log = []

        for i, ev in enumerate(events):
            item = copy.deepcopy(ev)
            orig_id = ev.get("raw_reference", f"evt_{i}")
            stripped = []
            for field in target_fields:
                if field in item and item[field] is not None:
                    item[field] = None
                    stripped.append(field)

            if stripped:
                new_id = self._generate_event_id(orig_id, "optfield", i)
                item["raw_reference"] = new_id
                transform_log.append({
                    "original_event_id": orig_id,
                    "transformed_event_id": new_id,
                    "transformation_type": "remove_optional_field",
                    "transformation_parameters": {"stripped_fields": stripped},
                    "seed": self.seed,
                })
            result.append(item)

        return result, transform_log

    def truncate_field(
        self,
        events: list[dict[str, Any]],
        target_field: str = "command_line",
        max_length: int = 15,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Truncates long telemetry fields."""
        result = []
        transform_log = []

        for i, ev in enumerate(events):
            item = copy.deepcopy(ev)
            orig_id = ev.get("raw_reference", f"evt_{i}")
            if target_field in item and isinstance(item[target_field], str) and len(item[target_field]) > max_length:
                item[target_field] = item[target_field][:max_length]
                new_id = self._generate_event_id(orig_id, "trunc", i)
                item["raw_reference"] = new_id
                transform_log.append({
                    "original_event_id": orig_id,
                    "transformed_event_id": new_id,
                    "transformation_type": "truncate_field",
                    "transformation_parameters": {"target_field": target_field, "max_length": max_length},
                    "seed": self.seed,
                })
            result.append(item)

        return result, transform_log

    def mutate_payload(
        self,
        events: list[dict[str, Any]],
        mutation_style: str = "url_encode",
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Applies adversarial payload obfuscation (URL encoding, SQL comments, powershell alias)."""
        result = []
        transform_log = []

        for i, ev in enumerate(events):
            item = copy.deepcopy(ev)
            orig_id = ev.get("raw_reference", f"evt_{i}")
            mutated = False

            # Web request mutation
            if "request_path" in item and item["request_path"]:
                val = item["request_path"]
                if mutation_style == "url_encode":
                    if "' or 1=1" in val.lower():
                        item["request_path"] = val.replace("'", "%27").replace(" ", "%20").replace("=", "%3D")
                        mutated = True
                elif mutation_style == "sql_comments":
                    if "union select" in val.lower():
                        item["request_path"] = val.replace("union select", "union/**/select")
                        mutated = True
                    elif "' or '1'='1" in val.lower():
                        item["request_path"] = val.replace("' or '1'='1", "'/**/or/**/'1'='1")
                        mutated = True

            # PowerShell command line mutation
            if "command_line" in item and item["command_line"]:
                cmd = item["command_line"]
                if mutation_style == "ps_alias":
                    if "powershell" in cmd.lower() and "-enc" in cmd.lower():
                        # Replace -enc with -e or -EncodedCommand
                        item["command_line"] = cmd.replace("-enc", "-e")
                        mutated = True

            if mutated:
                new_id = self._generate_event_id(orig_id, f"mut_{mutation_style}", i)
                item["raw_reference"] = new_id
                transform_log.append({
                    "original_event_id": orig_id,
                    "transformed_event_id": new_id,
                    "transformation_type": "mutate_payload",
                    "transformation_parameters": {"mutation_style": mutation_style},
                    "seed": self.seed,
                })
            result.append(item)

        return result, transform_log

    def alter_destination_port(
        self,
        events: list[dict[str, Any]],
        new_port: int = 8080,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Alters destination port on Zeek/network events."""
        result = []
        transform_log = []

        for i, ev in enumerate(events):
            item = copy.deepcopy(ev)
            orig_id = ev.get("raw_reference", f"evt_{i}")
            if item.get("source_type") in ("ZEEK", "SYSMON") and item.get("destination_port") is not None:
                item["destination_port"] = new_port
                new_id = self._generate_event_id(orig_id, "port", i)
                item["raw_reference"] = new_id
                transform_log.append({
                    "original_event_id": orig_id,
                    "transformed_event_id": new_id,
                    "transformation_type": "alter_destination_port",
                    "transformation_parameters": {"new_port": new_port},
                    "seed": self.seed,
                })
            result.append(item)

        return result, transform_log

    def alter_process_name(
        self,
        events: list[dict[str, Any]],
        new_process: str = "svch0st.exe",
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Alters process name to a typo-squatted variant."""
        result = []
        transform_log = []

        for i, ev in enumerate(events):
            item = copy.deepcopy(ev)
            orig_id = ev.get("raw_reference", f"evt_{i}")
            if item.get("source_type") == "SYSMON" and item.get("process") is not None:
                item["process"] = new_process
                new_id = self._generate_event_id(orig_id, "procname", i)
                item["raw_reference"] = new_id
                transform_log.append({
                    "original_event_id": orig_id,
                    "transformed_event_id": new_id,
                    "transformation_type": "alter_process_name",
                    "transformation_parameters": {"new_process": new_process},
                    "seed": self.seed,
                })
            result.append(item)

        return result, transform_log

    def alter_dns_query(
        self,
        events: list[dict[str, Any]],
        new_domain: str = "beacon.evilcorp.org",
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Alters DNS query string."""
        result = []
        transform_log = []

        for i, ev in enumerate(events):
            item = copy.deepcopy(ev)
            orig_id = ev.get("raw_reference", f"evt_{i}")
            if item.get("dns_query") is not None:
                item["dns_query"] = new_domain
                new_id = self._generate_event_id(orig_id, "dns", i)
                item["raw_reference"] = new_id
                transform_log.append({
                    "original_event_id": orig_id,
                    "transformed_event_id": new_id,
                    "transformation_type": "alter_dns_query",
                    "transformation_parameters": {"new_domain": new_domain},
                    "seed": self.seed,
                })
            result.append(item)

        return result, transform_log

    def introduce_unrelated_event(
        self,
        events: list[dict[str, Any]],
        source_type: str = "ZEEK",
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Introduces an unrelated event into the event stream."""
        result = [copy.deepcopy(e) for e in events]
        now = datetime.now()
        unrelated_ev = {
            "source_type": source_type,
            "source_name": "unrelated_sensor",
            "source_ip": "198.18.0.99",
            "destination_ip": "198.18.0.100",
            "destination_port": 80,
            "protocol": "tcp",
            "hostname": "corp-printer-01",
            "username": "svc_printer",
            "event_type": "conn",
            "event_category": "network",
            "severity": "low",
            "message": "Routine printer heartbeat connection",
            "timestamp": now.isoformat(),
            "raw_reference": f"unrelated_{self.seed}",
        }
        result.append(unrelated_ev)
        transform_log = [{
            "original_event_id": None,
            "transformed_event_id": unrelated_ev["raw_reference"],
            "transformation_type": "introduce_unrelated_event",
            "transformation_parameters": {"source_type": source_type},
            "seed": self.seed,
        }]
        return result, transform_log
