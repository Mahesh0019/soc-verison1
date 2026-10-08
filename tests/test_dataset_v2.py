"""
tests/test_dataset_v2.py

Automated test suite for Research Dataset V2:
- Verifies integrity, scenario counts, split separation, category coverage,
  schema validation, and data leakage guards.
- Verifies Dataset V1 backwards compatibility is preserved.
"""

from __future__ import annotations

import json
from pathlib import Path
import unittest


class TestResearchDatasetV2(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root_dir = Path(__file__).resolve().parent.parent
        cls.v2_dir = cls.root_dir / "research" / "datasets" / "dataset_v2"
        cls.full_path = cls.v2_dir / "dataset_v2.json"
        cls.dev_path = cls.v2_dir / "dev_set.json"
        cls.val_path = cls.v2_dir / "val_set.json"
        cls.test_path = cls.v2_dir / "test_set.json"
        cls.manifest_path = cls.v2_dir / "dataset_v2_manifest.json"

        with open(cls.full_path, encoding="utf-8") as f:
            cls.full_data = json.load(f)
        with open(cls.dev_path, encoding="utf-8") as f:
            cls.dev_data = json.load(f)
        with open(cls.val_path, encoding="utf-8") as f:
            cls.val_data = json.load(f)
        with open(cls.test_path, encoding="utf-8") as f:
            cls.test_data = json.load(f)
        with open(cls.manifest_path, encoding="utf-8") as f:
            cls.manifest = json.load(f)

    def test_01_dataset_v2_artifacts_exist(self):
        """All required Dataset V2 machine-readable files must exist."""
        self.assertTrue(self.full_path.exists())
        self.assertTrue(self.dev_path.exists())
        self.assertTrue(self.val_path.exists())
        self.assertTrue(self.test_path.exists())
        self.assertTrue(self.manifest_path.exists())

    def test_02_scenario_counts_and_balance(self):
        """Dataset V2 must contain 200 scenarios: 100 ATTACK, 100 BENIGN."""
        self.assertEqual(len(self.full_data), 200)
        attacks = [s for s in self.full_data if s["ground_truth"] == "ATTACK"]
        benign = [s for s in self.full_data if s["ground_truth"] == "BENIGN"]
        self.assertEqual(len(attacks), 100)
        self.assertEqual(len(benign), 100)

    def test_03_split_proportions(self):
        """Splits must adhere to 50% Dev (100), 20% Val (40), 30% Test (60) with 50/50 ground truth balance."""
        self.assertEqual(len(self.dev_data), 100)
        self.assertEqual(len(self.val_data), 40)
        self.assertEqual(len(self.test_data), 60)

        self.assertEqual(sum(1 for s in self.dev_data if s["ground_truth"] == "ATTACK"), 50)
        self.assertEqual(sum(1 for s in self.dev_data if s["ground_truth"] == "BENIGN"), 50)

        self.assertEqual(sum(1 for s in self.val_data if s["ground_truth"] == "ATTACK"), 20)
        self.assertEqual(sum(1 for s in self.val_data if s["ground_truth"] == "BENIGN"), 20)

        self.assertEqual(sum(1 for s in self.test_data if s["ground_truth"] == "ATTACK"), 30)
        self.assertEqual(sum(1 for s in self.test_data if s["ground_truth"] == "BENIGN"), 30)

    def test_04_no_duplicate_scenario_ids(self):
        """Every scenario in Dataset V2 must have a globally unique ID."""
        ids = [s["scenario_id"] for s in self.full_data]
        self.assertEqual(len(ids), len(set(ids)))

    def test_05_split_disjointness(self):
        """Dev, Val, and Test scenario sets must be strictly mutually exclusive."""
        dev_ids = {s["scenario_id"] for s in self.dev_data}
        val_ids = {s["scenario_id"] for s in self.val_data}
        test_ids = {s["scenario_id"] for s in self.test_data}

        self.assertEqual(len(dev_ids & val_ids), 0)
        self.assertEqual(len(dev_ids & test_ids), 0)
        self.assertEqual(len(val_ids & test_ids), 0)
        self.assertEqual(dev_ids | val_ids | test_ids, {s["scenario_id"] for s in self.full_data})

    def test_06_all_20_categories_represented(self):
        """All 20 specified categories must be present in the dataset."""
        expected_categories = {
            "Normal browsing",
            "Normal authentication",
            "Failed authentication",
            "Repeated authentication failures",
            "SQL injection",
            "XSS",
            "Path traversal",
            "Suspicious HTTP requests",
            "Reconnaissance",
            "Abnormal request rate",
            "Suspicious user-agent behavior",
            "Suspicious source-IP behavior",
            "Multi-step attacks",
            "Privilege-related behavior",
            "Account-related anomalies",
            "Mixed attack/benign sequences",
            "Benign behavior resembling attacks",
            "Missing/partial telemetry",
            "Duplicate telemetry",
            "Timing variations",
        }
        present_categories = {s["attack_category"] for s in self.full_data}
        self.assertEqual(expected_categories, present_categories)

    def test_07_required_metadata_and_event_schemas(self):
        """All scenarios and constituent events must adhere strictly to the schema."""
        req_scen_fields = {
            "scenario_id", "scenario_version", "split", "ground_truth",
            "attack_category", "name", "description", "source", "timestamp",
            "expected_detection", "expected_severity", "difficulty", "events"
        }
        req_ev_fields = {
            "timestamp", "source_ip", "destination_ip", "event_type",
            "event_category", "severity", "message", "raw_log"
        }

        for s in self.full_data:
            self.assertTrue(req_scen_fields.issubset(s.keys()))
            self.assertIn(s["ground_truth"], {"ATTACK", "BENIGN"})
            self.assertGreater(len(s["events"]), 0)
            for ev in s["events"]:
                self.assertTrue(req_ev_fields.issubset(ev.keys()))

    def test_08_data_leakage_ip_isolation(self):
        """Test subnet IPs must not appear in Dev set, ensuring no IP memorization."""
        for s in self.dev_data:
            for ev in s["events"]:
                if ev.get("source_ip"):
                    self.assertFalse(ev["source_ip"].startswith("192.0.2."))

        for s in self.test_data:
            for ev in s["events"]:
                if ev.get("source_ip") and ev["source_ip"] != "198.51.100.99":
                    self.assertFalse(ev["source_ip"].startswith("198.51.100."))

    def test_09_dataset_v1_untouched_and_functional(self):
        """Historical Dataset V1 catalog must remain strictly intact and preserved."""
        v1_catalog = self.root_dir / "soc_attack_catalog.json"
        self.assertTrue(v1_catalog.exists())
        with open(v1_catalog, encoding="utf-8") as f:
            v1_items = json.load(f)
        self.assertEqual(len(v1_items), 10)

        verified_matrix = self.root_dir / "research" / "results" / "verified_benchmark_matrix.json"
        self.assertTrue(verified_matrix.exists())
        with open(verified_matrix, encoding="utf-8") as f:
            matrix_data = json.load(f)
        self.assertEqual(matrix_data["total_scenarios"], 22)
        self.assertEqual(len(matrix_data["verified_benchmark_matrix"]), 7)


if __name__ == "__main__":
    unittest.main()
