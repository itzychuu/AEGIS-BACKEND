# AEGIS Backend — Frontend & Chrome Extension Integration Guide

Welcome! This document provides a complete guide for connecting your frontend (Chrome Extension, Web Application, or Firebase integration) to the AEGIS Phishing Prevention Backend.

---

## 🚀 Quick Start (Running the Backend Locally)

### 1. Prerequisites
- Python **3.12+**
- (Optional) [Ollama](https://ollama.com/) running locally with model `qwen3:4b-instruct` for Advisory AI reasoning features.

### 2. Environment Setup
Clone the repository and set up a Python virtual environment:

```bash
# Clone the repository (if not already done)
git clone https://github.com/itzychuu/AEGIS-BACKEND.git
cd AEGIS-BACKEND

# Create and activate virtual environment
python -m venv .venv

# On Windows (PowerShell):
.venv\Scripts\Activate.ps1

# On Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Environment Variables
Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

Key configuration parameters in `.env`:
```ini
AEGIS_API_HOST=127.0.0.1
AEGIS_API_PORT=8000
AEGIS_CORS_ORIGINS=chrome-extension://*,http://localhost:3000,http://localhost:8000,http://127.0.0.1:8000
AEGIS_CYBER_ANALYSIS_ENABLED=true
AEGIS_AI_ENABLED=true
AEGIS_AI_MODEL=qwen3:4b-instruct
```

### 4. Start the Server
Run the FastAPI application using Uvicorn:

```bash
python -m uvicorn api.app:app --host 127.0.0.1 --port 8000 --reload
```

or simply:

```bash
python main.py
```

Once running, interactive API documentation is available at:
- **Swagger UI**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **ReDoc**: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)
- **OpenAPI Schema**: [http://127.0.0.1:8000/openapi.json](http://127.0.0.1:8000/openapi.json)

---

## 📡 API Endpoint Reference

### 1. `POST /api/v1/analyze` (Primary Phishing Analysis)

Analyzes a target URL using ML classification, parallel cybersecurity evidence analysis, risk scoring, and advisory Local AI reasoning.

#### **Request Header**
```http
Content-Type: application/json
```

#### **Request Body**
```json
{
  "url": "https://example.com"
}
```

#### **Response Body Schema (HTTP 200 OK)**
```json
{
  "url": "https://example.com",
  "classification": "SAFE",
  "risk_score": 4,
  "reasons": [
    "Low phishing probability from the ML model."
  ],
  "signals": {
    "ml_probability": 0.05,
    "ml_prediction": 0,
    "ml_label": "legitimate",
    "cyber_analysis": {
      "dns": { "available": true, "status": "success", "data": { ... } },
      "http": { "available": true, "status": "success", "data": { ... } },
      "tls": { "available": true, "status": "success", "data": { ... } },
      "redirects": { "available": true, "status": "success", "data": { ... } },
      "threat_intel": { "available": true, "status": "success", "data": { ... } }
    }
  },
  "ai": {
    "available": true,
    "status": "success",
    "provider": "ollama",
    "model": "qwen3:4b-instruct",
    "summary": "The URL example.com shows low-risk signals with valid HTTPS and no known malicious domain matches.",
    "risk_assessment": "The target domain matches legitimate operational characteristics.",
    "key_findings": [
      "Low ML phishing probability score (0.05)",
      "Standard HTTPS TLS certificate active"
    ],
    "supporting_signals": ["ml_probability", "dns_resolution"],
    "conflicting_signals": [],
    "uncertainties": [],
    "latency_ms": 450.2
  },
  "model_version": "xgboost_v6",
  "cached": false,
  "analysis_time_ms": 120.5
}
```

---

### 2. `GET /api/v1/health` (Service Liveness Check)

Lightweight probe to verify backend server is online (sub-millisecond execution, 0 ML/network overhead).

#### **Response Body (HTTP 200 OK)**
```json
{
  "status": "ok",
  "service": "aegis-backend",
  "version": "1.0.0"
}
```

---

### 3. `GET /api/v1/ready` (Subsystem Readiness Check)

Checks operational readiness of internal components (ML Model, Cybersecurity Orchestrator, Local AI).

#### **Response Body (HTTP 200 OK)**
```json
{
  "status": "ready",
  "checks": {
    "ml_model": "ready",
    "cyber_analysis": "ready",
    "local_ai": "available"
  }
}
```

---

## 🎨 Frontend / Extension UI Integration Rules

### 1. Classification & Risk Score Mapping

| Classification | Risk Score Range | UI Badge Color | Recommended Extension Action |
| :--- | :--- | :--- | :--- |
| **`SAFE`** | `0` to `29` | 🟢 **Green** | Allow user navigation silently or show safe checkmark in popup. |
| **`SUSPICIOUS`** | `30` to `69` | 🟡 **Orange / Yellow** | Show warning banner / popup badge with threat reasons list. |
| **`CRITICAL`** | `70` to `100` | 🔴 **Red** | Show blocking warning page / modal overlay to stop credential submission. |

> ⚠️ **Important Security Rule**: `classification` and `risk_score` are strictly calculated by the deterministic security engine. The `ai` object is advisory and explanatory only. Always rely on `classification` and `risk_score` for locking or warning UI logic.

### 2. Displaying Threat Explanations (`reasons`)
The `reasons` field contains human-readable security risk factors generated by the backend. Use this array directly in UI tooltips or warning modals:
- *"High phishing probability (0.92) detected by XGBoost ML model."*
- *"Target domain resolves to a restricted/private IP address (SSRF risk)."*
- *"Plain unencrypted HTTP connection used for sensitive entry point."*

### 3. Displaying Local AI Reasoning (`ai`)
When `ai.available` is `true`:
- Use `ai.summary` for a concise 1–2 sentence context summary.
- Use `ai.key_findings` (array of bullet points) for detailed explanation tabs in the extension popup.

### 4. Handling Cache (`cached: true`)
When `cached` is `true`, the backend returned the result instantly (< 10 ms) from the in-memory Trust Cache. No special UI changes are needed, but you can display a subtle *"Verified (Cached)"* indicator in the extension popup.

---

## 💻 Code Snippet for Extension / Frontend Integration

Here is a ready-to-use JavaScript snippet for your Chrome Extension `background.js` or `content.js`:

```javascript
const AEGIS_BACKEND_URL = "http://127.0.0.1:8000/api/v1/analyze";

/**
 * Analyzes a URL using the AEGIS Backend API.
 * @param {string} targetUrl - The URL of the active tab or link to scan.
 * @returns {Promise<Object>} Analysis result object.
 */
async function analyzeUrlWithAegis(targetUrl) {
  try {
    const response = await fetch(AEGIS_BACKEND_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json"
      },
      body: JSON.stringify({ url: targetUrl })
    });

    if (!response.ok) {
      const errorData = await response.json();
      console.error("AEGIS API Error:", errorData.error);
      throw new Error(errorData.error?.message || "Failed to analyze URL");
    }

    const result = await response.json();
    console.log("AEGIS Analysis Result:", result);

    // Apply UI Logic based on deterministic classification
    switch (result.classification) {
      case "CRITICAL":
        triggerCriticalBlockPage(result);
        break;
      case "SUSPICIOUS":
        triggerWarningBanner(result);
        break;
      case "SAFE":
      default:
        showSafeBadge(result);
        break;
    }

    return result;
  } catch (error) {
    console.error("AEGIS Connection Failure:", error);
    // Fail safe or fallback according to extension policy
  }
}
```

---

## 🛠 Backend Architecture Overview

The AEGIS Backend is structured into 5 modular, fully tested phases:

1. **Phase 1 — ML Model & Feature Extraction (`ml_model/`)**:
   - XGBoost V6 URL classification model with 51 extracted lexical/structural features.
   - Pre-trained model artifact `phishguard_xgb_v6.joblib` with optimal classification threshold `0.7125`.

2. **Phase 2 — Aegis Engine, Risk Scoring & Trust Cache (`aegis_engine/`, `cache/`)**:
   - In-memory thread-safe `MemoryCache` with TTL, LRU eviction, and automatic model-version invalidation.
   - Deterministic risk scoring matrix converting ML probabilities & cyber signals to `SAFE`, `SUSPICIOUS`, or `CRITICAL`.

3. **Phase 3 — Cybersecurity Tools & Threat Intel (`cyber_analysis/`)**:
   - Parallel `CyberOrchestrator` executing DNS resolution, HTTP inspection, TLS certificate analysis, redirect loop detection, local allowlist/blocklist lookup, and SSRF internal network protection.

4. **Phase 4 — Model-Agnostic Local AI (`local_ai/`)**:
   - Privacy-preserving, local AI coordinator interfacing with Ollama (`qwen3:4b-instruct`).
   - Produces advisory signal correlation and contextual security explanations without altering authoritative risk scores.

5. **Phase 5 — FastAPI Backend Integration (`api/`)**:
   - Clean FastAPI application with Pydantic request/response schemas, OpenAPI documentation, CORS middleware, security headers, request ID tracking, centralized error boundaries, and 100% test coverage across 112 pytest unit/integration tests.

---

## 🧪 Running Verification Tests

To verify that all backend systems are operating correctly before frontend integration, run the full test suite:

```bash
.venv\Scripts\python.exe -m pytest -q
```

Expected output:
```text
112 passed in ~7.00s
```

---

## 🔒 Security & Error Codes

Error responses returned by the API use standard HTTP status codes and a consistent JSON format:

| Status Code | Error Code | Description / Cause |
| :--- | :--- | :--- |
| **`400 Bad Request`** | `INVALID_URL` | Supplied URL is empty, malformed, or failed canonical parsing. |
| **`422 Unprocessable Entity`** | `VALIDATION_ERROR` | Missing required fields or URL exceeds maximum length (8192 chars). |
| **`500 Internal Error`** | `ENGINE_ERROR` / `INTERNAL_ERROR` | Internal server exception. Sensitive stack traces are safely masked. |

---

## 👥 Team Contact & Backend Support

If you encounter any issues connecting your extension or frontend to the API endpoints, please check:
1. Is Uvicorn running on `127.0.0.1:8000`?
2. Is `AEGIS_CORS_ORIGINS` configured in `.env` if requests are blocked by CORS?
3. Check interactive Swagger docs at `http://127.0.0.1:8000/docs` to test requests directly in your browser.
