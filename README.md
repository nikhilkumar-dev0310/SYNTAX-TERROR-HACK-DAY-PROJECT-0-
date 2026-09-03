# DiodeShield AI — Passive AI Threat Detection Engine
**Smart India Hackathon 2026 | Problem Statement: SIH26145 (NTRO)**  
**Team: SYNTAX TERROR**

---

## 🛡️ Project Overview
**DiodeShield AI** is an AI-powered passive threat detection and telemetry engine specifically architected for **unidirectional data diode networks** protecting critical air-gapped enclaves (NTRO / Defense / Critical Infrastructure).

Because physical data diodes strictly prohibit reverse transmissions (100% optical RX only; zero TX return path), standard bidirectional TCP handshakes, active probing, and agent callbacks cannot function. DiodeShield AI performs **passive AST feature extraction, supervised known signature classification (XGBoost), and unsupervised zero-day anomaly detection (Isolation Forest)** at line rate without generating a single reverse packet.

---

## ⚡ Key Architecture & Components

- **Backend (`backend/main.py`)**:
  - **FastAPI** application with non-blocking `asyncio` task lifecycles.
  - **Telemetry Simulator Loop**: Generates synthetic unidirectional packet flows every 50–200ms with inter-arrival times (IAT), byte entropy, and TCP flags.
  - **Dual-Model Inference Engine**:
    - `classify_known`: Supervised XGBoost classifier (~1.42ms latency, ~97% benign, detects DDoS SYN floods, Port Scans, and C2 beaconing).
    - `classify_anomaly`: Unsupervised Isolation Forest detector (~2.08ms latency, detects zero-day optical ingress anomalies).
  - **WebSocket Realtime Channel (`/ws/live`)**: Pushes `packet_event`, `threat_event`, and live metric counters safely to all connected frontends.
  - **REST Endpoints**:
    - `GET /health` — Service & model engine status.
    - `GET /metrics/summary` — Running metrics for count-up cards.
    - `GET /model-status` — Inference latencies, accuracy, and live classification timestamps.
    - `GET /threats?filter={type}&search={term}` — Filterable threat store.
    - `GET /threats/{flow_id}` — Deep feature vector & IAT sequence for drawer.
    - `GET /threats/export` — Streamed CSV export of all detected threats.
    - `POST /simulate-attack` — Injects an instantaneous 8-flow DDoS/Zero-day attack burst for live demo evaluation.

- **Frontend (`index.html`)**:
  - High-density SOC Cyberpunk interface styled with Tailwind CSS, JetBrains Mono, and Geist.
  - **Animated 4-Card Metric Row**: Real count-up transitions connected to backend metrics.
  - **Diode Hardware Flow Monitor**: Visual optical laser-to-photodiode pipeline with HTML5 Canvas unidirectional photon streams.
  - **Interactive Flow Analytics Chart**: 60-second rolling buffer with Volume (pps), Threat Score, and Latency switches.
  - **Live Threat Log Table**: Search debouncing (300ms), category filters, CSV download, and slide-over threat inspection drawer.

---

## 🚀 Running Locally

### 1. Backend Setup
```bash
# Navigate to backend directory
cd backend

# Create & activate virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Start FastAPI server with Uvicorn
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```
Backend will be live at `http://localhost:8000` (API Docs at `http://localhost:8000/docs`).

### 2. Frontend Setup
Simply serve `index.html` with any static server or open it directly:
```bash
# From the project root
python3 -m http.server 3000
```
Open `http://localhost:3000` in your browser. The frontend automatically connects to the backend at `localhost:8000` (HTTP and WebSockets).

---

## 🌐 Cloud Deployment (Render + Vercel)

### Backend on Render (Web Service)
1. Push this repository to GitHub.
2. Create a new **Web Service** on [Render](https://render.com).
3. Set the following build settings:
   - **Root Directory**: `backend`
   - **Runtime**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn main:app --host 0.0.0.0 --port $PORT`
4. Render will provide a public URL like `https://diodeshield-backend.onrender.com`.

### Frontend on Vercel
1. In Vercel, import the repository root containing `index.html`.
2. Framework Preset: `Other` (Static HTML).
3. If deployed on a separate domain from the backend, update `API_BASE` and `WS_BASE` in `index.html` to point to your Render domain:
   - `const API_BASE = "https://diodeshield-backend.onrender.com";`
   - `const WS_BASE = "wss://diodeshield-backend.onrender.com/ws/live";`
4. Deploy to get your live production demo URL.
