# Research Reproducibility Guide

**Framework:** Detection-Quality-Aware SOC Platform  
**Target Audience:** Security Researchers & Peer Reviewers  

---

## Step-by-Step Instructions

### 1. Clone Repository & Checkout Validation Branch
```bash
git clone https://github.com/Mahesh0019/soc-verison1.git
cd soc-verison1
git checkout audit/research-validation
```

### 2. Configure Environment Variables
Create `.env` file from standard template (no secret credentials required):
```bash
cp .env.example .env
```
Ensure `.env` contains:
```env
DATABASE_URL=sqlite:///./mini_siem.db
JWT_SECRET_KEY=local-research-development-secret-key-32-chars
JWT_EXPIRE_MINUTES=720
AUTO_CREATE_TABLES=true
ENABLE_JUICE_SHOP_CONNECTOR=false
```

### 3. Install Backend Dependencies
```bash
pip install -r backend/requirements.txt
```

### 4. Run Automated Test Suite
Execute all unit, integration, and security hardening tests:
```bash
python -m unittest discover tests
```
*Expected Output:* `Ran 79 tests in ... OK`

### 5. Execute Reproducible Experiment Pipeline (M0 - M6)
Run the automated benchmark runner:
```bash
python research/scripts/run_experiments.py
```
This script will:
- Initialize the ground truth evaluation dataset ([research/datasets/soc_attack_catalog.json](research/datasets/soc_attack_catalog.json)).
- Run simulations across **M0** (Raw Telemetry), **M1** (Static Rules), **M2** (Correlation), **M3** (Evidence Hashing), **M4** (Quality-Aware), **M5** (Behavioral ML), and **M6** (Full Hybrid SOC).
- Persist raw run JSON artifacts to `research/runs/` and matrix files to `research/results/benchmark_matrix.csv` and `research/results/benchmark_matrix.json`.

### 6. Build & Verify Frontend Dashboard
```bash
cd frontend
npm install
npm run build
```
*Expected Output:* Vite production bundle generated successfully in `frontend/dist`.

### 7. Run Full Stack Locally (Optional)
```bash
docker compose up --build
```
- Interactive React Dashboard: `http://localhost:5173`
- Backend REST API Docs: `http://localhost:8000/api/docs`
- Research Benchmarks View: Navigate to `/research` in browser.
