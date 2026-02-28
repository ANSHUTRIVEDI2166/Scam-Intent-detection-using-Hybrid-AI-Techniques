# ScamShield – AI Honeypot System

> AI-powered agentic honeypot that detects scam messages, autonomously engages scammers through multi-turn conversations, and extracts intelligence — all saved locally as JSON.

---

## What It Does

When a scam message arrives, ScamShield:

1. **Detects** if it's a scam using LLM (NVIDIA NIMs) + 80+ rule-based patterns
2. **Engages** the scammer with a realistic human-like AI persona
3. **Extracts** intelligence: phone numbers, UPI IDs, bank accounts, phishing links, email addresses
4. **Saves** everything to local JSON files for review
5. **Keeps talking** — never ends the conversation early, maximizing intelligence gathering

---

## Project Structure

```
scamshield/
├── src/
│   ├── api.py          # FastAPI backend — all HTTP endpoints
│   ├── graph.py        # LangGraph workflow definition
│   ├── nodes.py        # Workflow node implementations
│   ├── state.py        # LangGraph state + payload builder
│   ├── prompts.py      # LLM prompts (scam detection, intel extraction, agent response)
│   ├── utils.py        # Regex extractors + JSON storage
│   └── config.py       # All config / environment variables
│
├── frontend/           # React 18 + Vite frontend
│   ├── src/
│   │   ├── App.jsx
│   │   ├── index.css
│   │   └── components/
│   │       ├── Chat.jsx          # Live chat simulator
│   │       ├── Sidebar.jsx       # Server config, session info, quick samples
│   │       ├── IntelPanel.jsx    # Real-time extracted intelligence
│   │       ├── SessionsView.jsx  # Browse all saved sessions
│   │       └── Toast.jsx
│   ├── package.json
│   └── vite.config.js  # Proxies /api/* to localhost:8000
│
├── data/               # Auto-created on first run
│   ├── intelligence_log.json   # All sessions (append log)
│   └── sessions/
│       └── {sessionId}.json    # Per-session intelligence
│
├── requirements.txt
└── README.md
```

---

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+
- NVIDIA NIMs API key (free at [build.nvidia.com](https://build.nvidia.com))

---

### 1 — Install Python dependencies

```bash
pip install -r requirements.txt
```

---

### 2 — Create `.env` file

```env
NVIDIA_API_KEY=nvapi-xxxxxxxxxxxxxxxxxxxx

# Optional
API_KEY=any-secret-key-you-want
PORT=8000
LOG_LEVEL=INFO
MAX_MESSAGES=50
```

---

### 3 — Start the backend

```bash
uvicorn src.api:app --host 0.0.0.0 --port 8000 --reload
```

You should see:

```
╔══════════════════════════════════════════════════════════════╗
║  ScamShield - AI Honeypot System                            ║
╚══════════════════════════════════════════════════════════════╝
🚀 Starting server on 0.0.0.0:8000
🤖 LLM Model: meta/llama-3.1-8b-instruct
💾 Data Directory: data
```

---

### 4 — Start the React frontend

```bash
cd frontend
npm install     # only needed once
npm run dev
```

Open **http://localhost:3000**

The Vite dev server automatically proxies all `/api/*` calls to `http://localhost:8000` — no CORS config needed.

---

## React Frontend

The frontend has two main views:

**Chat Tab**
- Send messages as "Scammer" or "User"
- AI agent replies in real time
- Live scam detection alert banner
- Quick sample buttons (Bank Scam, KYC Scam, Lottery Scam, etc.)
- Session info + confidence meter in the sidebar
- Right panel shows extracted intelligence updating live

**Sessions Tab**
- Stats: total sessions, scams detected, intel items collected, avg engagement duration
- Browse all saved sessions with expandable detail rows
- See phone numbers, UPI IDs, bank accounts, links, emails per session
- Export any session as JSON

---

## API Reference

All endpoints are served on `http://localhost:8000`.
Interactive API docs: `http://localhost:8000/docs`

---

### `POST /api/message`

Main endpoint. Send a message, get the AI honeypot reply.

**Request body:**
```json
{
  "sessionId": "sess_abc123",
  "message": {
    "sender": "scammer",
    "text": "Your SBI account will be blocked. Update KYC: http://sbi-kyc.xyz",
    "timestamp": 1770005528731
  },
  "conversationHistory": [],
  "metadata": {
    "channel": "SMS",
    "language": "English",
    "locale": "IN"
  }
}
```

`sender` can be `"scammer"` or `"user"`.  
`conversationHistory` is optional — include previous turns for multi-turn sessions.

**Response:**
```json
{
  "status": "success",
  "reply": "Oh no! Why will my account get blocked? I haven't done anything wrong...",
  "sessionId": "sess_abc123"
}
```

---

### `GET /api/sessions`

Returns all sessions from `data/intelligence_log.json`.

```json
{
  "status": "success",
  "total": 12,
  "sessions": [ ... ]
}
```

---

### `GET /api/sessions/{session_id}/intelligence`

Returns saved intelligence for a specific session from `data/sessions/{id}.json`.

```json
{
  "status": "success",
  "data": {
    "sessionId": "sess_abc123",
    "scamDetected": true,
    "totalMessagesExchanged": 8,
    "engagementDurationSeconds": 142,
    "extractedIntelligence": {
      "phoneNumbers": ["9876543210"],
      "upiIds": ["scammer@paytm"],
      "bankAccounts": ["1234567890123456"],
      "phishingLinks": ["http://sbi-kyc.xyz"],
      "emailAddresses": ["fraud@fake.com"]
    },
    "savedAt": "2026-02-28T10:45:12"
  }
}
```

---

### `GET /api/session/{session_id}`

Returns live in-memory session state (available only while the server is running).

---

### `DELETE /api/session/{session_id}`

Removes a session from in-memory storage.

---

### `GET /health`

```json
{ "status": "online", "service": "ScamShield Honeypot", "version": "2.0.0" }
```

---

## LangGraph Workflow

Every incoming message is processed through this graph:

```
START
  │
  ▼
add_message          ← Appends scammer message to conversation history
  │
  ▼
detect_scam          ← LLM + rule-based detection, confidence scoring
  │
  ▼
[Always engage]      ← Honeypot strategy: engage everything
  │
  ▼
extract_intelligence ← Regex pass + LLM pass, merged & validated
  │
  ▼
generate_response    ← AI picks persona, strategy, asks probing question
  │
  ▼
check_continuation   ← Always continue (until MAX_MESSAGES safety limit)
  │
  ├─ continue → END  ← Returns reply to API; waits for next message
  │
  └─ end → final_callback → END  ← Saves final payload to JSON
```

In background after every turn: session state is saved to `data/sessions/{id}.json`.

---

## How Intelligence Extraction Works

Two passes run on every turn and results are merged (union):

| Pass | Method | What it finds |
|---|---|---|
| 1st (fast) | Regex patterns | Phone numbers, UPI IDs, bank accounts, URLs, emails |
| 2nd (contextual) | LLM (llama-3.1-8b) | Embedded/obfuscated intel, scam context keywords |

After merging, each item is **validated** — it must actually appear in the raw conversation text to prevent LLM hallucinations.

**Extracted categories:**
- `phoneNumbers` — Indian mobile numbers (starts with 6–9, 10 digits, handles +91 prefix)
- `upiIds` — `user@bankhandle` format (excludes regular email addresses)
- `bankAccounts` — 9–18 digit sequences with banking context keywords nearby
- `phishingLinks` — HTTP/HTTPS URLs and bare domains (`.com`, `.in`, `.xyz`, etc.)
- `emailAddresses` — `user@domain.tld` format
- `suspiciousKeywords` — urgency words, threat words, authority impersonation, payment requests

---

## Scam Detection Logic

Uses a **dual detection** strategy:

| Method | Weight | Patterns |
|---|---|---|
| LLM (llama-3.1-8b) | Primary | 10-step Chain-of-Thought analysis |
| Rule-based | Fallback / supplement | 30 high-confidence + 50 medium-confidence patterns |

Final confidence = `max(LLM confidence, rule confidence)`.  
Engagement threshold is intentionally low (**0.15**) — honeypot strategy, better to engage a false positive than miss a scam.

**Scam patterns covered:** Bank/KYC scams, lottery/prize scams, government/police impersonation, digital arrest, OTP interception, fake refund, crypto investment, job offer, loan approval, Aadhaar/PAN fraud.

---

## Agent Behaviour

The AI agent adapts through four **turn phases** based on how far the conversation has progressed:

| Phase | Turn % | Strategy |
|---|---|---|
| `early` | 0–30% | Build rapport, seem confused/curious, gentle questions |
| `mid` | 30–60% | Actively probe for payment details and contact info |
| `late` | 60–85% | Push hard for remaining intel categories |
| `wrap_up` | 85%+ | Extract final details before conversation limit |

Available personas: concerned citizen, confused elderly person, eager believer, anxious customer.

---

## Local Data Storage

All intelligence is stored locally — no external APIs involved.

**Per-session file** (`data/sessions/{sessionId}.json`):
```json
{
  "status": "success",
  "sessionId": "sess_abc...",
  "scamDetected": true,
  "totalMessagesExchanged": 10,
  "engagementDurationSeconds": 187,
  "extractedIntelligence": {
    "phoneNumbers": ["9876543210"],
    "bankAccounts": ["123456789012"],
    "upiIds": ["pay.scammer@paytm"],
    "phishingLinks": ["http://fake-kyc.in/verify"],
    "emailAddresses": []
  },
  "engagementMetrics": {
    "engagementDurationSeconds": 187,
    "totalMessagesExchanged": 10
  },
  "agentNotes": "Scammer used KYC urgency tactic with phishing link...",
  "savedAt": "2026-02-28T10:45:12.000000"
}
```

**Global log** (`data/intelligence_log.json`): array of all session objects, updated after every turn.

---

## Configuration Reference

All settings are in `src/config.py` and can be overridden with environment variables.

| Variable | Default | Description |
|---|---|---|
| `NVIDIA_API_KEY` | *(required)* | NVIDIA NIMs API key |
| `NVIDIA_MODEL` | `meta/llama-3.1-8b-instruct` | LLM model to use |
| `API_KEY` | *(empty)* | Optional auth key for API endpoints |
| `PORT` | `8000` | Backend server port |
| `MAX_MESSAGES` | `50` | Safety limit for conversation length |
| `SCAM_CONFIDENCE_THRESHOLD` | `0.15` | Minimum score to engage |
| `INTELLIGENCE_SUFFICIENCY_THRESHOLD` | `10` | Score to consider intel "sufficient" |
| `DATA_DIR` | `data` | Directory for JSON storage |

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.11, FastAPI 0.115, Pydantic v2 |
| AI Workflow | LangGraph 0.2, LangChain 0.3 |
| LLM | NVIDIA NIMs — `meta/llama-3.1-8b-instruct` |
| Frontend | React 18, Vite 5, Lucide React |
| Storage | Local JSON files |
| NLP | Regex + LLM hybrid extraction |

---

## Quick Test with curl

```bash
# Send a scam message
curl -X POST http://localhost:8000/api/message \
  -H "Content-Type: application/json" \
  -d '{
    "sessionId": "test-001",
    "message": {
      "sender": "scammer",
      "text": "URGENT: Your SBI account is blocked. Update KYC at http://sbi-verify.xyz or call 9876543210. Share OTP to agent@fraud.in",
      "timestamp": 1740000000000
    },
    "conversationHistory": []
  }'

# List all saved sessions
curl http://localhost:8000/api/sessions

# Get a specific session's extracted intel
curl http://localhost:8000/api/sessions/test-001/intelligence
```
