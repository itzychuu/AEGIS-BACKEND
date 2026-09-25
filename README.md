# AEGIS Backend — Phishing Prevention System

AEGIS is an advanced, multi-layered cybersecurity phishing prevention system that combines machine learning URL classification, parallel technical security analysis, in-memory trust caching, and advisory local AI reasoning into a high-performance REST API.

---

## 🎯 Architecture Overview

```text
Browser Extension / Client
           │
           │ HTTP POST /api/v1/analyze
           ▼
    ┌──────────────┐
    │   FastAPI    │
    │  (api/app)   │
    └──────┬───────┘
           │
           ▼
    ┌──────────────┐
    │ AegisEngine  │
    └──────┬───────┘
           │
  ┌────────┴────────┐
  │                 │
  ▼                 ▼
Trust Cache     Analysis Pipeline
                    │
         ┌──────────┴──────────┐
         │                     │
         ▼                     ▼
    Phase 1 ML           Phase 3 Cyber
     (XGBoost)             Analysis
         │                     │
         └──────────┬──────────┘
                    │
                    ▼
              Risk Scoring
                    │
                    ▼
             Decision Engine
                    │
         (SAFE/SUSPICIOUS/CRITICAL)
                    │
                    ▼
              Phase 4 Local AI
            (Advisory Qwen3:4B)
                    │
                    ▼
             AnalyzeResponse
```

---

## 🚀 Quick Start

```bash
# 1. Clone repository
git clone https://github.com/itzychuu/AEGIS-BACKEND.git
cd AEGIS-BACKEND

# 2. Setup virtual environment & dependencies
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

# 3. Environment configuration
cp .env.example .env

# 4. Launch backend API server
python -m uvicorn api.app:app --host 127.0.0.1 --port 8000 --reload
```

---

## 📖 System Architecture & Component Output Docs

For a complete deep-dive into how each component works and the exact JSON output schemas produced by each pipeline layer:
👉 **[SYSTEM_ARCHITECTURE.md](file:///d:/AEGIS/AEGIS-BACKEND/SYSTEM_ARCHITECTURE.md)**

---

## 📚 Integration Guide for Frontend & Chrome Extension

For step-by-step frontend integration instructions, CORS setup, and JavaScript code snippets for Chrome extension developers:
👉 **[INTEGRATION_GUIDE.md](file:///d:/AEGIS/AEGIS-BACKEND/INTEGRATION_GUIDE.md)**

---

## 📖 Interactive OpenAPI Docs

Once Uvicorn is running:
- **Swagger UI**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **ReDoc**: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)

---

## 🧪 Testing

Run the full pytest test suite (112 / 112 passing tests):

```bash
.venv\Scripts\python.exe -m pytest -q
```
