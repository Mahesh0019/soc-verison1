"""
Empirical Performance Measurement for Zeek Telemetry Replay Engine.
Measures: events processed, accepted, rejected, duplicated, throughput, latency.
"""
import os
import sys
from pathlib import Path

# Ensure sqlite in-memory database before app imports
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["AUTO_CREATE_TABLES"] = "true"

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(backend_dir))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database.base import Base
from app.services.zeek_service import ingest_zeek_telemetry

def run_benchmark():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()

    fixtures_dir = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "zeek"
    fixtures = [
        ("conn.log", "conn"),
        ("conn.json", "conn"),
        ("http.log", "http"),
        ("http.json", "http"),
        ("dns.log", "dns"),
        ("dns.json", "dns"),
    ]

    print("=== EMPIRICAL ZEEK REPLAY BENCHMARK MEASUREMENTS ===")
    total_proc = 0
    total_acc = 0
    total_rej = 0
    total_dup = 0
    all_throughputs = []
    all_avg_lats = []
    all_max_lats = []
    all_errors = []

    for fname, ltype in fixtures:
        fpath = fixtures_dir / fname
        content = fpath.read_text(encoding="utf-8")
        res = ingest_zeek_telemetry(db, content=content, log_type=ltype, mode="REPLAY", file_name=fname, user_id=None)
        print(f"Fixture: {fname} ({ltype})")
        print(f"  processed: {res['events_processed']}, accepted: {res['events_accepted']}, rejected: {res['events_rejected']}, duplicated: {res['events_duplicated']}")
        print(f"  throughput: {res['throughput_eps']} eps, avg_lat: {res['average_latency_ms']} ms, max_lat: {res['maximum_latency_ms']} ms")
        print(f"  errors: {res['errors']}")
        total_proc += res['events_processed']
        total_acc += res['events_accepted']
        total_rej += res['events_rejected']
        total_dup += res['events_duplicated']
        all_throughputs.append(res['throughput_eps'])
        all_avg_lats.append(res['average_latency_ms'])
        all_max_lats.append(res['maximum_latency_ms'])
        all_errors.extend(res['errors'])

    print("\n=== AGGREGATE SUMMARY ===")
    print(f"Total events processed: {total_proc}")
    print(f"Total events accepted: {total_acc}")
    print(f"Total events rejected: {total_rej}")
    print(f"Total events duplicated: {total_dup}")
    print(f"Average throughput: {round(sum(all_throughputs)/len(all_throughputs), 2)} eps")
    print(f"Overall average latency: {round(sum(all_avg_lats)/len(all_avg_lats), 3)} ms")
    print(f"Peak latency: {max(all_max_lats)} ms")
    print(f"Total errors: {len(all_errors)}")

if __name__ == "__main__":
    run_benchmark()
