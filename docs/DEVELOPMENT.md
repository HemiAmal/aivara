# AIVARA — Local Development Guide

**Phase:** Phase 3 — Domain Model & Relational Database Schema  
**Date:** 2026-09-01  

---

## 1. Environment Activation

AIVARA uses a Python 3.11 64-bit virtual environment located at `D:\Downloads\Projects\AiVara\.venv`.

### PowerShell:
```powershell
.\.venv\Scripts\Activate.ps1
```

Verify the active Python interpreter:
```powershell
python --version
# Expected: Python 3.11.9
```

---

## 2. Dependencies

### Backend Dependencies:
```powershell
python -m pip install -r backend\requirements.txt
```

### Frontend Dependencies:
```powershell
cd frontend
npm install
cd ..
```

---

## 3. Running Backend Services

Start the development FastAPI server on `127.0.0.1:8000`:
```powershell
python -m uvicorn aivara.main:app --host 127.0.0.1 --port 8000
```

Verify backend health:
```powershell
curl http://127.0.0.1:8000/health
```

Expected response:
```json
{
  "status": "ok",
  "service": "aivara",
  "version": "0.1.0"
}
```

---

## 4. Running the Frontend Development Shell

Start the local Vite server:
```powershell
cd frontend
npm run dev
```
Available locally at: `http://127.0.0.1:5173`.

---

## 5. Running the Test Suite

Execute pytest across all unit, domain validation, database schema, and API integration tests:
```powershell
python -m pytest -v
```

Expected output: `68 passed`.

---

## 6. Directory Structure & Conventions

```
AiVara/
├── backend/
│   ├── aivara/
│   │   ├── api/            # API envelope, error handlers, and modular routers
│   │   │   └── routers/    # projects, contributors, datasets, models, etc.
│   │   ├── core/           # Configuration, logging, domain exceptions
│   │   ├── database/       # SQLite connection and complete SQLAlchemy models (14 entities)
│   │   ├── domain/         # Pydantic schemas (Create/Read/Update separation, ADR-028 enforcement)
│   │   ├── services/       # Domain CRUD services (projects, contributors, datasets, models)
│   │   └── main.py         # FastAPI application entry point
│   └── requirements.txt    # Pinned dependencies
├── frontend/               # React + TypeScript + Vite shell
├── data/                   # Local storage (datasets, models, cache, reports)
├── docs/                   # Authoritative architectural & database documentation
│   ├── ARCHITECTURE.md     # System architecture
│   ├── DECISIONS.md        # Architectural Decision Records (ADRs)
│   ├── DATABASE.md         # Relational database schema & entity catalog
│   ├── DEVELOPMENT.md      # Development instructions
│   └── PHASE_STATUS.md     # Current project phase tracking
├── scripts/                # Environment validation and developer utilities
└── tests/                  # Pytest test suite (68 tests)
```

### Development Guidelines:
1. **Localhost Only:** The backend and frontend development servers must only bind to `127.0.0.1`. Never expose to `0.0.0.0`.
2. **Offline First:** No runtime code may make outbound HTTP requests or query external CDNs/APIs.
3. **No Sensitive Logging:** All logs pass through sanitization filters to prevent private keys or secrets from leaking into logs.
4. **Database Conventions:** All ORM entities use `id` (UUID4 string), SQLite WAL mode, and `PRAGMA foreign_keys=ON;`. Non-destructive assurance data must use `ON DELETE RESTRICT`.
