# Developer Guide
## CyberGuard AI — Setup & Contribution Guide

**Version:** 1.0  
**Date:** September 2026

---

## 1. Development Environment Setup

### 1.1 Prerequisites

| Tool | Version | Purpose |
|---|---|---|
| Python | 3.11+ | Agent and API server |
| Rust | 1.75+ | Performance-critical agent modules |
| Node.js | 20+ | Dashboard frontend |
| Docker Desktop | 24+ | Local service stack |
| Git | 2.40+ | Version control |
| VS Code / PyCharm | Latest | Recommended IDEs |

### 1.2 Repository Structure

```
cyber/
├── agent/                      # Monitoring agent (Python + Rust)
│   ├── src/
│   │   ├── main.py             # Agent entrypoint
│   │   ├── collector/          # Process & network data collection
│   │   ├── ai_engine/          # ONNX model inference
│   │   ├── heuristics/         # Rule-based threat detection
│   │   ├── log_parser/         # Log file ingestion
│   │   ├── kill_executor/      # Process termination
│   │   └── websocket_client/   # Agent-to-server communication
│   ├── rust_proc/              # Rust crate for fast process enumeration
│   ├── tests/
│   ├── requirements.txt
│   └── Cargo.toml
├── api/                        # API server (FastAPI)
│   ├── app/
│   │   ├── main.py             # FastAPI application
│   │   ├── routers/            # API endpoint routers
│   │   ├── models/             # SQLAlchemy models
│   │   ├── schemas/            # Pydantic schemas
│   │   ├── services/           # Business logic
│   │   ├── auth/               # JWT + MFA authentication
│   │   └── websocket/          # WebSocket hub
│   ├── db/
│   │   └── migrations/         # Alembic migrations
│   ├── tests/
│   └── requirements.txt
├── dashboard/                  # Frontend (React + TypeScript)
│   ├── src/
│   │   ├── App.tsx
│   │   ├── components/
│   │   ├── pages/
│   │   ├── stores/             # Zustand state stores
│   │   ├── hooks/
│   │   ├── api/                # API client
│   │   └── styles/
│   ├── package.json
│   └── vite.config.ts
├── models/                     # AI model files
│   └── threat_model_v1.0.onnx
├── docker-compose.yml
├── docker-compose.dev.yml
├── docs/
└── ...
```

---

### 1.3 Initial Setup

```bash
# 1. Clone the repository
git clone https://github.com/your-org/cyberguard-ai.git
cd cyberguard-ai

# 2. Set up Python virtual environment (for API server)
cd api
python3.11 -m venv venv
source venv/bin/activate       # Windows: venv\Scripts\activate
pip install -r requirements.txt
pip install -r requirements-dev.txt

# 3. Set up agent dependencies
cd ../agent
python3.11 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt

# 4. Build Rust process collector
cd rust_proc
cargo build
cd ..

# 5. Set up dashboard
cd ../dashboard
npm install

# 6. Start the local development stack
cd ..
docker compose -f docker-compose.dev.yml up -d

# 7. Run database migrations
cd api
source venv/bin/activate
alembic upgrade head

# 8. Seed dev data (optional)
python scripts/seed_dev_data.py
```

---

### 1.4 Running in Development Mode

**Start all services at once:**
```bash
# Terminal 1: API server (with hot reload)
cd api && source venv/bin/activate
uvicorn app.main:app --reload --port 8443 --ssl-certfile ../certs/dev.crt --ssl-keyfile ../certs/dev.key

# Terminal 2: Agent (targeting local API server)
cd agent && source venv/bin/activate
python src/main.py --config config/dev.yaml

# Terminal 3: Dashboard (with hot reload)
cd dashboard
npm run dev
```

**Or use the development helper script:**
```bash
./scripts/dev-start.sh
```

Dashboard will be available at: `https://localhost:5173`

---

## 2. Architecture Quick Reference

See [Architecture Document](ARCHITECTURE.md) for the full system design.

### Component Responsibilities

| Component | Language | Key Libraries |
|---|---|---|
| Agent (core) | Python 3.11 | psutil, onnxruntime, watchdog |
| Agent (process collection) | Rust | procfs, tokio |
| API Server | Python 3.11 | FastAPI, SQLAlchemy, PyJWT |
| Dashboard | TypeScript/React | React 18, Zustand, Recharts |
| Database | - | SQLite (dev), PostgreSQL (prod) |

---

## 3. Coding Standards

### 3.1 Python (Agent + API)

- **Style:** Follow PEP 8. Use `ruff` for linting and `black` for formatting.
- **Type hints:** Required on all function signatures and class attributes.
- **Docstrings:** Google-style docstrings for all public functions and classes.
- **Error handling:** Never use bare `except`. Always catch specific exceptions.

```bash
# Format code
black api/ agent/

# Lint
ruff check api/ agent/ --fix

# Type check
mypy api/app/ agent/src/
```

### 3.2 Rust (Process Collector)

- **Style:** Follow `rustfmt` defaults.
- **Error handling:** Use `Result<T, E>` — no `unwrap()` in production code paths.
- **Safety:** No `unsafe` blocks without a detailed comment explaining why it's safe.

```bash
cd agent/rust_proc
cargo fmt
cargo clippy
cargo test
```

### 3.3 TypeScript (Dashboard)

- **Style:** ESLint + Prettier (configured in project).
- **Type safety:** No `any` types except with explicit justification comment.
- **Components:** Functional components only (no class components).
- **State:** Use Zustand for global state, `useState` for local UI state only.

```bash
cd dashboard
npm run lint
npm run type-check
npm run format
```

---

## 4. Testing

### Running Tests

```bash
# API server tests
cd api && source venv/bin/activate
pytest tests/ -v --cov=app --cov-report=term-missing

# Agent tests
cd agent && source venv/bin/activate
pytest tests/ -v --cov=src --cov-report=term-missing

# Rust tests
cd agent/rust_proc
cargo test

# Dashboard tests
cd dashboard
npm run test
npm run test:coverage
```

### Writing Tests

**Unit tests** go in `tests/unit/`  
**Integration tests** go in `tests/integration/`

```python
# Example: unit test for threat threshold logic
# agent/tests/unit/test_threat_classifier.py

import pytest
from src.ai_engine.classifier import ThreatClassifier

def test_safe_classification():
    classifier = ThreatClassifier(
        suspicious_threshold=0.3,
        malicious_threshold=0.7
    )
    result = classifier.classify(score=0.1)
    assert result == "SAFE"

def test_malicious_classification():
    classifier = ThreatClassifier(
        suspicious_threshold=0.3,
        malicious_threshold=0.7
    )
    result = classifier.classify(score=0.85)
    assert result == "MALICIOUS"

def test_protected_pid_cannot_be_killed():
    from src.kill_executor import KillExecutor
    executor = KillExecutor(protected_pids=[1, 2])
    
    with pytest.raises(ProtectedProcessError):
        executor.kill(pid=1, force=True)
```

---

## 5. Git Workflow

### Branch Strategy

```
main           — Production-ready code. Protected. No direct pushes.
develop        — Integration branch. All PRs target this.
feature/*      — Feature branches (e.g., feature/autonomous-kill-mode)
fix/*          — Bug fix branches (e.g., fix/websocket-reconnect)
release/*      — Release preparation branches (e.g., release/v1.1.0)
hotfix/*       — Emergency production fixes
```

### Pull Request Process

1. Create branch from `develop`:
   ```bash
   git checkout develop && git pull
   git checkout -b feature/your-feature-name
   ```

2. Write code, tests, and update relevant docs

3. Ensure CI passes locally:
   ```bash
   ./scripts/ci-check.sh
   # Runs: format, lint, type-check, unit tests
   ```

4. Push and open a Pull Request to `develop`

5. PR requirements:
   - ✅ All CI checks pass
   - ✅ At least 1 approving review
   - ✅ Code coverage does not decrease
   - ✅ No new `TODO` or `FIXME` without a linked GitHub issue

### Commit Message Format

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short description>

[optional body]

[optional footer]
```

**Types:** `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `chore`

**Examples:**
```
feat(agent): add DNS tunneling detection to log parser
fix(api): reject kill requests for PID 1 in all cases
test(agent): add unit tests for autonomous kill threshold logic
docs(api): update WebSocket event documentation
perf(agent): reduce scan cycle latency by 40% using async process batch
```

---

## 6. Security-Sensitive Code Areas

The following areas require **two reviewers** (not one) before merging:

- `agent/src/kill_executor/` — Process termination logic
- `api/app/auth/` — Authentication and token handling
- `api/app/routers/auth.py` — Login endpoint
- Any change to protected PID list or kill guards
- Any change to audit log hash chain computation

**Never commit:**
- Real API keys, passwords, or secrets
- Private TLS certificates
- Actual malware samples (use behavior simulators in tests)

---

## 7. AI Model Development

### Model Training Pipeline

```bash
cd ml/

# Prepare training data
python prepare_dataset.py \
    --clean-process-samples data/clean/ \
    --malware-behavior-samples data/malware/ \
    --output data/processed/

# Train the model
python train_model.py \
    --data data/processed/ \
    --model-type xgboost \
    --output models/threat_model_candidate.pkl

# Convert to ONNX
python convert_to_onnx.py \
    --input models/threat_model_candidate.pkl \
    --output models/threat_model_candidate.onnx

# Validate on test set
python validate_model.py \
    --model models/threat_model_candidate.onnx \
    --test-data data/test/ \
    --target-tpr 0.90 \
    --target-fpr 0.05
```

### Updating the Bundled Model

1. Train and validate new model (TPR ≥ 90%, FPR ≤ 5%)
2. Compute SHA-256: `sha256sum models/threat_model_vX.Y.onnx`
3. Update `models/MODELS.json` with new version entry
4. Sign the model: `openssl dgst -sha256 -sign model_signing_key.pem threat_model_vX.Y.onnx > threat_model_vX.Y.onnx.sig`
5. Add model file to release package

---

## 8. Environment Variables Reference

| Variable | Component | Default | Description |
|---|---|---|---|
| `SECRET_KEY` | API | none | JWT signing secret — required |
| `DATABASE_URL` | API | `sqlite:///./cyberguard.db` | Database connection string |
| `REDIS_URL` | API | `redis://localhost:6379` | Redis connection |
| `CORS_ORIGINS` | API | `["https://localhost:5173"]` | Allowed dashboard origins |
| `AGENT_API_URL` | Agent | none | API server URL — required |
| `AGENT_API_KEY` | Agent | none | Device-specific API key — required |
| `VITE_API_URL` | Dashboard | `https://localhost:8443` | API server URL for dashboard build |

---

## 9. CI/CD Pipeline

The CI pipeline runs on every PR and push to `develop` and `main`:

```yaml
# .github/workflows/ci.yml (abbreviated)

jobs:
  lint-and-type-check:
    - ruff check
    - mypy
    - eslint + tsc

  unit-tests:
    - pytest api/tests/unit/
    - pytest agent/tests/unit/
    - cargo test
    - npm run test

  integration-tests:
    - docker compose up (test containers)
    - pytest api/tests/integration/
    - pytest agent/tests/integration/
    - docker compose down

  security-scan:
    - bandit (Python security linter)
    - cargo audit (Rust dependency audit)
    - npm audit

  ai-model-validation:
    - On changes to ml/ or models/
    - Validate model accuracy against test dataset
```

---

*End of Developer Guide v1.0*
