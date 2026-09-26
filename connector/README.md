# OWASP Juice Shop Telemetry Connector for Mini-SIEM

The Juice Shop Connector continuously polls real HTTP request telemetry from an OWASP Juice Shop victim instance, transforms the events into the Mini-SIEM `NormalizedEvent` schema, and forwards them in batches to the Mini-SIEM ingestion API (`POST /api/logs/ingest`).

---

## 🚀 Environment Variables

Configure the connector via environment variables or a `.env` file:

| Environment Variable | Description | Default Value |
| :--- | :--- | :--- |
| `JUICE_SHOP_TELEMETRY_URL` | Victim telemetry API endpoint URL | `https://demo-victim-1.onrender.com/api/telemetry/events` |
| `JUICE_SHOP_TELEMETRY_API_KEY` | Bearer API key for victim telemetry access | `""` |
| `SIEM_INGEST_URL` | Mini-SIEM log ingestion API endpoint URL | `http://localhost:8000/api/logs/ingest` |
| `SIEM_JWT_TOKEN` | Bearer JWT Token for Mini-SIEM ingestion auth | `""` |
| `POLL_INTERVAL_SECONDS` | Polling interval in seconds (continuous mode) | `10` |
| `BATCH_SIZE` | Maximum number of events sent per SIEM batch | `50` |

---

## 🛠️ Usage

### 1. Run Single Ingestion Cycle (--once mode)
Fetches available telemetry once, transforms it, ingests it into Mini-SIEM, updates the checkpoint, and exits:
```bash
python -m connector.juice_shop_connector --once
```

### 2. Run Continuous Ingestion (Normal mode)
Polls the telemetry endpoint periodically based on `POLL_INTERVAL_SECONDS`:
```bash
python -m connector.juice_shop_connector
```

---

## 📌 Checkpoint Mechanism

- The connector maintains state by writing the `event_id` of the last successfully ingested telemetry item into `connector/.checkpoint`.
- Incremental fetches use `?since=<event_id>` to ensure events are not processed repeatedly.
- Checkpoints are updated **only after** Mini-SIEM ingestion returns a successful response.

---

## 🧪 Testing

Run the connector test suite:
```bash
python -m unittest tests/test_juice_shop_connector.py
```
