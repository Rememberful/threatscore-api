# ThreatScore API

**ML-powered real-time threat scoring API — one HTTP call from any backend.**

[![Live API](https://img.shields.io/badge/API-Live-brightgreen)](https://threatscore-api.onrender.com/api/health)
[![Dashboard](https://img.shields.io/badge/Dashboard-Live-blue)](https://threatscore-dashboard.onrender.com)
[![Python](https://img.shields.io/badge/Python-3.11+-blue)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green)](https://fastapi.tiangolo.com)
[![LightGBM](https://img.shields.io/badge/LightGBM-F1%200.93-orange)](https://lightgbm.readthedocs.io)

---

## What is ThreatScore?

ThreatScore is a production-ready threat intelligence API that scores incoming network requests in real time using machine learning trained on the **UNSW-NB15 dataset** (82,000+ labeled network flows).

Send basic request metadata — IP, protocol, bytes, duration — and receive back:
- A **0–100 threat score** with verdict
- **SHAP-derived human-readable flags** explaining why
- **Geo-intelligence** (country, city, datacenter/VPN/TOR detection)
- **Historical context** (times seen, avg score, previously blocked)
- **Velocity signals** (requests in last 60s / 1h, spike detection)
- **Closest attack profile** (Exploits, DoS, Reconnaissance, etc.)

---

## Quick Start

```bash
curl -X POST https://threatscore-api.onrender.com/api/score \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ts_your_key_here" \
  -d '{
    "srcip": "1.2.3.4",
    "proto": "tcp",
    "service": "http",
    "sbytes": 5000,
    "dbytes": 200,
    "dur": 0.4,
    "sttl": 64
  }'
```

**Response:**
```json
{
  "threat_score": 82,
  "verdict": "CRITICAL",
  "flags": [
    "TTL value (64) consistent with known attack fingerprint",
    "Destination byte volume anomalous for this service",
    "Inter-packet timing matches automated/scanner behaviour"
  ],
  "closest_attack_profile": "Exploits",
  "confidence": 0.9224,
  "recommendation": "block",
  "geo": {
    "country": "Romania",
    "city": "Bucharest",
    "is_tor": false,
    "is_vpn": false,
    "is_datacenter": false
  },
  "history": {
    "times_seen": 14,
    "avg_score": 87.0,
    "first_seen": "2026-06-01",
    "previously_blocked": true
  },
  "velocity": {
    "requests_last_60s": 3,
    "requests_last_1h": 45,
    "spike_detected": false
  },
  "simulated": false,
  "list_status": "none"
}
```

---

## Integration Examples

### Node.js / Express
```javascript
app.use(async (req, res, next) => {
  const response = await fetch("https://threatscore-api.onrender.com/api/score", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-API-Key": process.env.THREATSCORE_KEY,
    },
    body: JSON.stringify({
      srcip:   req.ip,
      proto:   "tcp",
      service: "http",
      sbytes:  parseInt(req.headers["content-length"] || 0),
      dbytes:  0,
      dur:     0.1,
      sttl:    64,
    }),
  })
  const { threat_score, verdict, recommendation } = await response.json()
  if (recommendation === "block") return res.status(403).json({ error: "Blocked" })
  req.threatScore = { threat_score, verdict }
  next()
})
```

### Python / FastAPI
```python
import httpx

async def score_request(srcip: str, sbytes: int = 0):
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            "https://threatscore-api.onrender.com/api/score",
            headers={"X-API-Key": os.getenv("THREATSCORE_KEY")},
            json={"srcip": srcip, "proto": "tcp", "service": "http",
                  "sbytes": sbytes, "dbytes": 0, "dur": 0.1, "sttl": 64}
        )
    data = resp.json()
    if data["recommendation"] == "block":
        raise HTTPException(status_code=403, detail="Blocked by ThreatScore")
    return data
```

---

## Shadow Mode

Test without risk — scores every request but never influences your app logic:

```bash
curl -X POST https://threatscore-api.onrender.com/api/score \
  -H "X-API-Key: ts_your_key" \
  -H "X-ThreatScore-Mode: shadow" \
  -d '{"srcip": "1.2.3.4", ...}'
```

Response includes `"simulated": true`. Run in shadow mode for a week, monitor results, then remove the header to go live.

---

## IP Blocklist & Allowlist

Manage trusted and blocked IPs per API key via JWT-authenticated endpoints:

```bash
# Block a confirmed attacker permanently
curl -X POST https://threatscore-api.onrender.com/api/blocklist \
  -H "Authorization: Bearer YOUR_JWT" \
  -d '{"srcip": "1.2.3.4", "reason": "confirmed scanner"}'

# Allowlist your office / monitoring service
curl -X POST https://threatscore-api.onrender.com/api/allowlist \
  -H "Authorization: Bearer YOUR_JWT" \
  -d '{"srcip": "192.168.1.1", "reason": "office IP"}'

# View blocklist
curl -X GET https://threatscore-api.onrender.com/api/blocklist \
  -H "Authorization: Bearer YOUR_JWT"

# Remove from blocklist
curl -X DELETE https://threatscore-api.onrender.com/api/blocklist/1.2.3.4 \
  -H "Authorization: Bearer YOUR_JWT"
```

Blocklisted IPs return instantly (`list_status: blocklisted`) without running the ML pipeline. Allowlist takes priority over blocklist.

---

## API Reference

### POST /api/score

**Headers:**
| Header | Required | Description |
|---|---|---|
| `X-API-Key` | Yes | Your ThreatScore API key |
| `X-ThreatScore-Mode` | No | Set to `shadow` for dry-run mode |

**Request Body:**
| Field | Type | Default | Description |
|---|---|---|---|
| `srcip` | string | `0.0.0.0` | Source IP address |
| `sport` | int | `0` | Source port number |
| `proto` | string | `tcp` | Protocol: `tcp` / `udp` / `icmp` |
| `service` | string | `-` | Service: `http` / `ftp` / `ssh` / `dns` / `-` |
| `sbytes` | int | `0` | Bytes sent by source |
| `dbytes` | int | `0` | Bytes sent by destination |
| `dur` | float | `0.0` | Connection duration in seconds |
| `sttl` | int | `64` | IP time-to-live value |
| `sinpkt` | float | `0.0` | Source inter-packet arrival time |

**Verdict Thresholds:**
| Score | Verdict | Recommendation |
|---|---|---|
| 0–30 | SAFE | allow |
| 31–60 | SUSPICIOUS | monitor |
| 61–80 | HIGH RISK | challenge |
| 81–100 | CRITICAL | block |

### GET /api/health
Returns service status. No auth required.

### Auth Endpoints
| Method | Endpoint | Description |
|---|---|---|
| POST | `/auth/register` | Create account |
| POST | `/auth/login` | Returns JWT |
| POST | `/auth/apikey` | Generate API key (JWT required) |
| GET | `/auth/apikey` | List active API keys |
| DELETE | `/auth/apikey/{id}` | Revoke API key |

### Dashboard Endpoints (JWT required)
| Method | Endpoint | Description |
|---|---|---|
| GET | `/dashboard/feed` | Last 50 scored requests |
| GET | `/dashboard/stats` | Total calls, avg score, verdict breakdown |
| GET | `/dashboard/threats` | Top 10 threat source IPs |

### IP List Endpoints (JWT required)
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/blocklist` | Add IP to blocklist |
| GET | `/api/blocklist` | View blocklist |
| DELETE | `/api/blocklist/{ip}` | Remove from blocklist |
| POST | `/api/allowlist` | Add IP to allowlist |
| GET | `/api/allowlist` | View allowlist |
| DELETE | `/api/allowlist/{ip}` | Remove from allowlist |

---

## ML Pipeline

### Dataset
**UNSW-NB15** — 82,332 training rows, 175,341 test rows, 10 attack categories.

### Models
| Model | Task | Performance |
|---|---|---|
| LightGBM Binary | Attack vs Normal | F1: **0.9325**, AUC: **0.9858** |
| LightGBM Multiclass | Attack Category | Macro F1: **0.5319** |

### Features Used
| Feature | Source |
|---|---|
| `dur`, `sbytes`, `dbytes`, `sttl`, `sinpkt` | Developer-provided |
| `proto`, `service` | Developer-provided (label encoded) |
| `byte_ratio` | Engineered (`sbytes / dbytes+1`) |
| `ct_srv_src` | Computed from DB logs (last 100 requests) |

### Explainability
SHAP TreeExplainer runs on every request — top 3 contributing features are converted to human-readable flags explaining the score.

---

## Architecture

```
Developer App
    │
    ▼
POST /api/score (X-API-Key)
    │
    ├── Validate API key
    ├── Check blocklist / allowlist (instant return if matched)
    ├── Fetch ct_srv_src from DB logs
    ├── Call ip-api.com for geo intelligence
    ├── Query history + velocity from DB
    │
    ├── ML Pipeline (asyncio.gather → parallel)
    │   ├── Binary LightGBM → threat score 0-100
    │   ├── Multiclass LightGBM → attack profile
    │   └── SHAP TreeExplainer → flags array
    │
    ├── Log to PostgreSQL
    └── Return enriched JSON response

React Dashboard
    ├── Live feed (polling every 5s)
    ├── Analytics charts (Recharts)
    ├── API key management
    └── Integration docs
```

---

## Project Structure

```
threatscore/
├── backend/
│   ├── main.py                  # FastAPI app, CORS, rate limiting
│   ├── db.py                    # SQLAlchemy models
│   ├── requirements.txt
│   ├── models/                  # Trained .pkl files
│   │   ├── binary_classifier.pkl
│   │   ├── multiclass_classifier.pkl
│   │   ├── feature_scaler.pkl
│   │   ├── label_encoders.pkl
│   │   └── shap_explainer.pkl
│   ├── routers/
│   │   ├── auth.py              # Register, login, API key CRUD
│   │   ├── score.py             # POST /api/score
│   │   ├── dashboard.py         # Feed, stats, threats
│   │   └── iplist.py            # Blocklist / allowlist
│   └── services/
│       ├── ml_service.py        # Model inference + SHAP
│       ├── feature_service.py   # Geo, history, velocity, ct_srv_src
│       └── auth_service.py      # JWT, bcrypt, API key hashing
│
├── frontend/
│   └── src/
│       ├── pages/               # Landing, Auth, Feed, Analytics, Keys, Docs
│       ├── components/          # Layout, sidebar
│       └── context/             # AuthContext (JWT in sessionStorage)
│
└── ml/
    ├── eda.ipynb
    ├── train.ipynb
    └── evaluate.ipynb
```

---

## Local Setup

### Backend

```bash
cd backend
python -m venv venv
venv\Scripts\activate        # Windows
pip install -r requirements.txt

# Create .env
DATABASE_URL=postgresql+asyncpg://postgres:password@localhost:5432/threatscore
JWT_SECRET=your-secret-here
MODEL_PATH=./models

# Create DB
psql -U postgres -c "CREATE DATABASE threatscore;"

# Start
uvicorn main:app --reload
```

### Frontend

```bash
cd frontend
npm install
# Create .env
VITE_API_URL=http://localhost:8000
npm run dev
```

---

## Deployment

Deployed on **Render**:

| Service | Type | URL |
|---|---|---|
| `threatscore-api` | Web Service (Python) | `https://threatscore-api.onrender.com` |
| `threatscore-dashboard` | Static Site | `https://threatscore-dashboard.onrender.com` |
| `notes-db` | PostgreSQL (shared) | Render managed |

**Environment variables required:**
```
DATABASE_URL    = postgresql+asyncpg://...
JWT_SECRET      = your-secret
MODEL_PATH      = /opt/render/project/src/backend/models
ALLOWED_ORIGINS = https://threatscore-dashboard.onrender.com,http://localhost:5173
```

---

## SDKs

Drop-in middleware packages are built and ready to publish:

**Node.js / Express:**
```javascript
const threatGuard = require('threatscore-sdk')
app.use(threatGuard({
  apiKey:         process.env.THREATSCORE_KEY,
  blockThreshold: 80,
  mode:           'shadow',  // start safe, go live later
}))
```

**Python / FastAPI:**
```python
from threatscore import ThreatGuard
app.add_middleware(ThreatGuard,
    api_key         = os.getenv("THREATSCORE_KEY"),
    block_threshold = 80,
    mode            = "live",
)
```

Both SDKs auto-extract IP, protocol, service, timing, and bytes from the request — zero manual payload construction needed.

---

## Roadmap

- [x] Core ML scoring (Binary + Multiclass LightGBM)
- [x] SHAP explainability flags
- [x] Geo-intelligence (ip-api.com)
- [x] Historical context per IP
- [x] Velocity signals
- [x] Shadow / dry-run mode
- [x] IP blocklist + allowlist
- [x] Node.js middleware SDK
- [x] Python middleware SDK
- [ ] Redis caching layer
- [ ] Webhook alerts (Slack / Discord / custom endpoint)
- [ ] Batch scoring endpoint
- [ ] IP reputation endpoint (`GET /api/ip/{ip}`)
- [ ] Smart feature fallback / estimation
- [ ] Global threat intelligence feed

---

## Research Background

This project builds on steganalysis and anomaly detection research. The ML pipeline applies techniques from network intrusion detection literature to a developer-facing API product.

**Dataset:** Moustafa, N. & Slay, J. (2015). UNSW-NB15: A Comprehensive Dataset for Network Intrusion Detection Systems. *Military Communications and Information Systems Conference (MilCIS)*.

---

## Author

**Aditya Kumar**  
B.Tech Information Technology, Institute of Engineering and Management, Kolkata  
GitHub: [@Rememberful](https://github.com/Rememberful)  
Live: [threatscore-dashboard.onrender.com](https://threatscore-dashboard.onrender.com)