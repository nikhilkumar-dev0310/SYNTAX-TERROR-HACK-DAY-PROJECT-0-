"""
DiodeShield AI - Passive AI Threat Detection Engine for Unidirectional Data Diode Networks
Smart India Hackathon 2026 | Problem Statement: SIH26145 (NTRO)
Team: SYNTAX TERROR
"""

import asyncio
import csv
import io
import json
import logging
import random
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

# ── Logging Configuration ──────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
)
logger = logging.getLogger("diodeshield-engine")

# ── Global In-Memory State & Metrics ──────────────────────────────────
METRICS = {
    "packets_analyzed": 142850,
    "threats_today": 37,
    "zero_day_count": 3,
    "avg_soc_latency_ms": 1.48,
    "total_latency_samples": 1000,
    "total_latency_sum": 1480.0
}

MODEL_STATUS = {
    "xgboost": {
        "name": "XGBoost Supervised Threat Engine",
        "version": "v2.4-diode-opt",
        "accuracy": 99.42,
        "avg_inference_ms": 1.42,
        "last_classified_at": datetime.now(timezone.utc).isoformat(),
        "status": "ONLINE",
        "classes": ["BENIGN", "DDoS SYN Flood", "Port Scan", "C2 Beaconing"]
    },
    "isolation_forest": {
        "name": "Isolation Forest Zero-Day Anomaly Detector",
        "version": "v1.9-unsupervised",
        "accuracy": 98.76,
        "avg_inference_ms": 2.08,
        "last_classified_at": datetime.now(timezone.utc).isoformat(),
        "status": "ACTIVE",
        "contamination": 0.002,
        "baseline_drift": "0.02%"
    },
    "diode_hardware": {
        "mode": "PASSIVE_HARDWARE_LOCK",
        "direction": "INGRESS_ONLY (RX)",
        "reverse_leakage_risk": "0.00%",
        "optical_interface": "Single-Strand Photodiode Tap (10GbE)",
        "status": "SECURE_ACTIVE"
    }
}

# ── Seeded Initial Threat History ───────────────────────────────────────
INITIAL_THREATS = [
    {
        "flow_id": "flw_8b31a01",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "label": "DDoS SYN Flood",
        "threat_type": "ddos",
        "confidence": 0.984,
        "latency_ms": 1.45,
        "anomaly_score": None,
        "src_ip": "198.51.100.74",
        "dst_ip": "10.0.80.12",
        "src_port": 54210,
        "dst_port": 443,
        "protocol": "TCP",
        "tcp_flags": ["SYN"],
        "src_zone": "untrusted_ingress",
        "dst_zone": "isolated_enclave",
        "severity": "CRITICAL",
        "mitre_technique": "T1498.001 - Direct Network Flood",
        "iat_ms": 0.18,
        "iat_series": [0.22, 0.19, 0.18, 0.20, 0.17, 0.18, 0.19, 0.18, 0.17, 0.18],
        "byte_dist": {"packet_size": 64, "entropy": 1.12, "payload_bytes": 0, "header_bytes": 64},
        "feature_vector": {
            "flow_duration_ms": 1820.4,
            "packet_rate_pps": 8420.0,
            "byte_entropy": 1.12,
            "syn_ack_ratio": 99.8,
            "iat_variance": 0.003
        }
    },
    {
        "flow_id": "flw_7c99f42",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "label": "ZERO_DAY_ANOMALY",
        "threat_type": "zero-day",
        "confidence": 0.962,
        "latency_ms": 2.15,
        "anomaly_score": -0.842,
        "src_ip": "203.0.113.19",
        "dst_ip": "10.0.80.4",
        "src_port": 41992,
        "dst_port": 8080,
        "protocol": "TCP",
        "tcp_flags": ["PSH", "ACK", "URG"],
        "src_zone": "untrusted_ingress",
        "dst_zone": "isolated_enclave",
        "severity": "CRITICAL",
        "mitre_technique": "T1203 - Unknown Protocol Anomaly",
        "iat_ms": 4.12,
        "iat_series": [12.4, 8.2, 4.1, 9.8, 15.2, 4.1, 7.3, 3.9, 14.1, 4.12],
        "byte_dist": {"packet_size": 1420, "entropy": 7.94, "payload_bytes": 1366, "header_bytes": 54},
        "feature_vector": {
            "flow_duration_ms": 450.2,
            "packet_rate_pps": 240.0,
            "byte_entropy": 7.94,
            "syn_ack_ratio": 1.0,
            "iat_variance": 14.28
        }
    },
    {
        "flow_id": "flw_4e12c88",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "label": "Port Scan",
        "threat_type": "scans",
        "confidence": 0.945,
        "latency_ms": 1.32,
        "anomaly_score": None,
        "src_ip": "192.0.2.144",
        "dst_ip": "10.0.80.20",
        "src_port": 39811,
        "dst_port": 22,
        "protocol": "TCP",
        "tcp_flags": ["SYN"],
        "src_zone": "untrusted_ingress",
        "dst_zone": "isolated_enclave",
        "severity": "MEDIUM",
        "mitre_technique": "T1046 - Network Service Discovery",
        "iat_ms": 1.25,
        "iat_series": [1.4, 1.2, 1.3, 1.1, 1.2, 1.3, 1.2, 1.4, 1.2, 1.25],
        "byte_dist": {"packet_size": 60, "entropy": 1.05, "payload_bytes": 0, "header_bytes": 60},
        "feature_vector": {
            "flow_duration_ms": 120.0,
            "packet_rate_pps": 800.0,
            "byte_entropy": 1.05,
            "syn_ack_ratio": 100.0,
            "iat_variance": 0.02
        }
    },
    {
        "flow_id": "flw_2a90e31",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "label": "C2 Beaconing",
        "threat_type": "c2",
        "confidence": 0.931,
        "latency_ms": 1.62,
        "anomaly_score": None,
        "src_ip": "198.51.100.205",
        "dst_ip": "10.0.80.8",
        "src_port": 60124,
        "dst_port": 8443,
        "protocol": "TCP",
        "tcp_flags": ["PSH", "ACK"],
        "src_zone": "untrusted_ingress",
        "dst_zone": "isolated_enclave",
        "severity": "HIGH",
        "mitre_technique": "T1071.001 - Web Protocols Command and Control",
        "iat_ms": 500.0,
        "iat_series": [500.2, 499.8, 500.1, 500.0, 499.9, 500.3, 500.0, 500.1, 499.8, 500.0],
        "byte_dist": {"packet_size": 256, "entropy": 6.88, "payload_bytes": 202, "header_bytes": 54},
        "feature_vector": {
            "flow_duration_ms": 5000.0,
            "packet_rate_pps": 2.0,
            "byte_entropy": 6.88,
            "syn_ack_ratio": 0.0,
            "iat_variance": 0.0001
        }
    }
]

THREAT_STORE: List[Dict] = list(INITIAL_THREATS)
MAX_STORE_SIZE = 500

# ── Connection Manager for WebSocket Realtime Channel ──────────────────
class ConnectionManager:
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        async with self._lock:
            self.active_connections.add(websocket)
        logger.info(f"WebSocket client connected. Total active clients: {len(self.active_connections)}")

    async def disconnect(self, websocket: WebSocket):
        async with self._lock:
            self.active_connections.discard(websocket)
        logger.info(f"WebSocket client disconnected. Remaining active: {len(self.active_connections)}")

    async def broadcast_json(self, data: dict):
        if not self.active_connections:
            return

        dead_connections = set()
        # Create a shallow copy snapshot to avoid mutation issues during iteration
        connections_snapshot = list(self.active_connections)
        
        for ws in connections_snapshot:
            try:
                # Wrap each send in a safe non-blocking future with a 2-second timeout
                await asyncio.wait_for(ws.send_json(data), timeout=2.0)
            except Exception:
                dead_connections.add(ws)

        if dead_connections:
            async with self._lock:
                for dead_ws in dead_connections:
                    self.active_connections.discard(dead_ws)
            logger.debug(f"Cleaned up {len(dead_connections)} disconnected WebSocket client(s).")

ws_manager = ConnectionManager()

# ── Mock AI Classifier Engines ──────────────────────────────────────────
KNOWN_THREAT_LABELS = [
    ("DDoS SYN Flood", "ddos", "CRITICAL", "T1498.001 - Direct Network Flood"),
    ("Port Scan", "scans", "MEDIUM", "T1046 - Network Service Discovery"),
    ("C2 Beaconing", "c2", "HIGH", "T1071.001 - Web Protocols Command and Control"),
]

def classify_known(flow: dict) -> dict:
    """
    Simulates high-speed XGBoost classification inference (~1.0 - 2.8ms).
    97% Benign, 3% Known Threats.
    """
    start = time.perf_counter()
    # Artificial tiny computation to emulate feature evaluation
    _ = flow["iat_ms"] * 1.5 + flow["byte_dist"]["entropy"]
    latency_ms = round((time.perf_counter() - start) * 1000 + random.uniform(1.1, 2.4), 2)

    # 97% Benign rate during standard operation
    is_threat = random.random() < 0.03

    if not is_threat:
        return {
            "label": "BENIGN",
            "threat_type": "benign",
            "confidence": round(random.uniform(0.96, 0.998), 3),
            "latency_ms": latency_ms,
            "severity": "LOW",
            "mitre_technique": None
        }
    
    choice = random.choice(KNOWN_THREAT_LABELS)
    return {
        "label": choice[0],
        "threat_type": choice[1],
        "confidence": round(random.uniform(0.91, 0.995), 3),
        "latency_ms": latency_ms,
        "severity": choice[2],
        "mitre_technique": choice[3]
    }

def classify_anomaly(flow: dict) -> dict:
    """
    Simulates unsupervised Isolation Forest anomaly detection (~1.8 - 3.2ms).
    Rare (~1 in 500) ZERO_DAY_ANOMALY.
    """
    start = time.perf_counter()
    # Emulate isolation path depth calculation
    _ = (flow["byte_dist"]["packet_size"] / 1500.0) * flow["byte_dist"]["entropy"]
    latency_ms = round((time.perf_counter() - start) * 1000 + random.uniform(1.8, 3.1), 2)

    is_anomaly = random.random() < 0.002  # ~ 1 in 500

    if not is_anomaly:
        return {
            "is_anomaly": False,
            "label": "NORMAL_PROFILE",
            "anomaly_score": round(random.uniform(0.10, 0.35), 3),
            "latency_ms": latency_ms
        }

    return {
        "is_anomaly": True,
        "label": "ZERO_DAY_ANOMALY",
        "threat_type": "zero-day",
        "anomaly_score": round(random.uniform(-0.94, -0.72), 3),
        "confidence": round(random.uniform(0.93, 0.985), 3),
        "latency_ms": latency_ms,
        "severity": "CRITICAL",
        "mitre_technique": "T1203 - Zero-Day Ingress Anomaly"
    }

def generate_synthetic_flow(is_attack: bool = False, attack_type: str = "ddos") -> dict:
    """
    Generates realistic network flow telemetry passing through the unidirectional data diode.
    """
    flow_id = f"flw_{uuid.uuid4().hex[:7]}"
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    if is_attack and attack_type == "ddos":
        iat = round(random.uniform(0.08, 0.45), 3)
        flags = ["SYN"]
        pkt_size = random.choice([60, 64, 128])
        entropy = round(random.uniform(1.05, 1.85), 2)
        src_ip = f"198.51.100.{random.randint(2, 250)}"
        dst_ip = "10.0.80.12"
        dst_port = random.choice([443, 80, 8080, 8443])
    elif is_attack and attack_type == "zero-day":
        iat = round(random.uniform(3.0, 12.0), 3)
        flags = ["PSH", "ACK", "URG"]
        pkt_size = random.randint(1200, 1490)
        entropy = round(random.uniform(7.85, 7.99), 2)
        src_ip = f"203.0.113.{random.randint(2, 250)}"
        dst_ip = "10.0.80.4"
        dst_port = random.choice([8080, 9000, 5000])
    else:
        iat = round(random.uniform(1.2, 18.5), 3)
        flags = random.choice([["ACK"], ["PSH", "ACK"], ["SYN", "ACK"], ["ACK", "FIN"]])
        pkt_size = random.randint(64, 1500)
        entropy = round(random.uniform(3.2, 5.8), 2)
        src_ip = f"{random.randint(11, 190)}.{random.randint(10, 240)}.{random.randint(1, 250)}.{random.randint(1, 250)}"
        dst_ip = f"10.0.80.{random.randint(2, 40)}"
        dst_port = random.choice([443, 80, 22, 53, 8080, 3306, 9200])

    iat_series = [round(max(0.05, iat + random.uniform(-0.3, 0.3)), 2) for _ in range(10)]
    payload_bytes = max(0, pkt_size - 54)

    return {
        "flow_id": flow_id,
        "timestamp": now_iso,
        "src_zone": "untrusted_ingress",
        "dst_zone": "isolated_enclave",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": random.randint(1024, 65535),
        "dst_port": dst_port,
        "protocol": "TCP",
        "tcp_flags": flags,
        "iat_ms": iat,
        "iat_series": iat_series,
        "byte_dist": {
            "packet_size": pkt_size,
            "entropy": entropy,
            "payload_bytes": payload_bytes,
            "header_bytes": min(54, pkt_size)
        },
        "feature_vector": {
            "flow_duration_ms": round(random.uniform(80.0, 3500.0), 1),
            "packet_rate_pps": round(1000.0 / max(0.1, iat), 1),
            "byte_entropy": entropy,
            "syn_ack_ratio": 99.8 if "SYN" in flags else 1.0,
            "iat_variance": round(random.uniform(0.001, 12.5), 4)
        }
    }

# ── Background Non-Blocking Packet Simulator Task ───────────────────────
async def packet_simulator_loop():
    """
    Continuously generates realistic diode telemetry in the background.
    Runs non-blockingly inside the asyncio event loop.
    """
    logger.info("DiodeShield AI background telemetry simulator loop started.")
    try:
        while True:
            # Random delay ~50-200ms between packet flows
            await asyncio.sleep(random.uniform(0.05, 0.20))

            flow = generate_synthetic_flow()
            known_res = classify_known(flow)
            anomaly_res = classify_anomaly(flow)

            # Update Running Metrics
            METRICS["packets_analyzed"] += 1
            sample_latency = (known_res["latency_ms"] + anomaly_res["latency_ms"]) / 2.0
            METRICS["total_latency_samples"] += 1
            METRICS["total_latency_sum"] += sample_latency
            METRICS["avg_soc_latency_ms"] = round(METRICS["total_latency_sum"] / METRICS["total_latency_samples"], 2)

            now_iso = datetime.now(timezone.utc).isoformat()
            MODEL_STATUS["xgboost"]["last_classified_at"] = now_iso
            MODEL_STATUS["isolation_forest"]["last_classified_at"] = now_iso

            # Check if this flow is a threat
            is_known_threat = known_res["label"] != "BENIGN"
            is_zero_day = anomaly_res["is_anomaly"]

            if is_zero_day or is_known_threat:
                METRICS["threats_today"] += 1
                if is_zero_day:
                    METRICS["zero_day_count"] += 1
                    label = anomaly_res["label"]
                    threat_type = "zero-day"
                    conf = anomaly_res["confidence"]
                    sev = anomaly_res["severity"]
                    mitre = anomaly_res["mitre_technique"]
                    anom_score = anomaly_res["anomaly_score"]
                else:
                    label = known_res["label"]
                    threat_type = known_res["threat_type"]
                    conf = known_res["confidence"]
                    sev = known_res["severity"]
                    mitre = known_res["mitre_technique"]
                    anom_score = None

                threat_record = {
                    **flow,
                    "label": label,
                    "threat_type": threat_type,
                    "confidence": conf,
                    "latency_ms": known_res["latency_ms"] if not is_zero_day else anomaly_res["latency_ms"],
                    "anomaly_score": anom_score,
                    "severity": sev,
                    "mitre_technique": mitre
                }

                # Store threat
                THREAT_STORE.insert(0, threat_record)
                if len(THREAT_STORE) > MAX_STORE_SIZE:
                    THREAT_STORE.pop()

                # Broadcast threat event over WebSocket
                await ws_manager.broadcast_json({
                    "type": "threat_event",
                    "data": threat_record,
                    "metrics": {
                        "packets_analyzed": METRICS["packets_analyzed"],
                        "threats_today": METRICS["threats_today"],
                        "zero_day_count": METRICS["zero_day_count"],
                        "avg_soc_latency_ms": METRICS["avg_soc_latency_ms"]
                    }
                })
            else:
                # Normal Benign packet event
                await ws_manager.broadcast_json({
                    "type": "packet_event",
                    "data": {
                        "flow_id": flow["flow_id"],
                        "timestamp": flow["timestamp"],
                        "src_ip": flow["src_ip"],
                        "dst_port": flow["dst_port"],
                        "protocol": flow["protocol"],
                        "iat_ms": flow["iat_ms"],
                        "byte_dist": flow["byte_dist"],
                        "label": "BENIGN",
                        "latency_ms": known_res["latency_ms"]
                    },
                    "metrics": {
                        "packets_analyzed": METRICS["packets_analyzed"],
                        "threats_today": METRICS["threats_today"],
                        "zero_day_count": METRICS["zero_day_count"],
                        "avg_soc_latency_ms": METRICS["avg_soc_latency_ms"]
                    }
                })

    except asyncio.CancelledError:
        logger.info("DiodeShield AI simulator loop received cancellation signal.")
    except Exception as exc:
        logger.exception(f"Unexpected error in simulator loop: {exc}")

# ── Attack Simulation Task ──────────────────────────────────────────────
async def trigger_attack_burst(burst_count: int = 8):
    """
    Injects a rapid burst of malicious flows over ~2 seconds to power the Demo Attack button.
    """
    logger.info(f"Injecting simulated attack burst of {burst_count} malicious flows...")
    for i in range(burst_count):
        await asyncio.sleep(random.uniform(0.15, 0.25))

        attack_type = "zero-day" if (i == 3) else "ddos"
        flow = generate_synthetic_flow(is_attack=True, attack_type=attack_type)

        if attack_type == "zero-day":
            label = "ZERO_DAY_ANOMALY"
            threat_type = "zero-day"
            conf = round(random.uniform(0.96, 0.99), 3)
            sev = "CRITICAL"
            mitre = "T1203 - Optical Ingress Anomaly Exploitation"
            anom_score = round(random.uniform(-0.95, -0.85), 3)
            METRICS["zero_day_count"] += 1
        else:
            label = "DDoS SYN Flood"
            threat_type = "ddos"
            conf = round(random.uniform(0.97, 0.995), 3)
            sev = "CRITICAL"
            mitre = "T1498.001 - High-Rate Ingress SYN Flood"
            anom_score = None

        METRICS["packets_analyzed"] += 1
        METRICS["threats_today"] += 1
        lat = round(random.uniform(1.2, 1.8), 2)

        threat_record = {
            **flow,
            "label": label,
            "threat_type": threat_type,
            "confidence": conf,
            "latency_ms": lat,
            "anomaly_score": anom_score,
            "severity": sev,
            "mitre_technique": mitre
        }

        THREAT_STORE.insert(0, threat_record)
        if len(THREAT_STORE) > MAX_STORE_SIZE:
            THREAT_STORE.pop()

        await ws_manager.broadcast_json({
            "type": "threat_event",
            "data": threat_record,
            "metrics": {
                "packets_analyzed": METRICS["packets_analyzed"],
                "threats_today": METRICS["threats_today"],
                "zero_day_count": METRICS["zero_day_count"],
                "avg_soc_latency_ms": METRICS["avg_soc_latency_ms"]
            }
        })

# ── Lifespan Context Manager ────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: spawn non-blocking simulator task
    simulator_task = asyncio.create_task(packet_simulator_loop())
    yield
    # Shutdown: cancel task cleanly
    simulator_task.cancel()
    try:
        await simulator_task
    except asyncio.CancelledError:
        pass
    logger.info("DiodeShield AI backend gracefully stopped.")

# ── FastAPI Application ─────────────────────────────────────────────────
app = FastAPI(
    title="DiodeShield AI - Passive Threat Detection Engine",
    description="Backend AI telemetry simulator and threat detection engine for unidirectional data diode networks. NTRO SIH 2026 (SIH26145). Team: SYNTAX TERROR.",
    version="2.0.0",
    lifespan=lifespan
)

# Enable CORS for frontend deployment (Vercel, localhost, etc.)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── REST API Endpoints ──────────────────────────────────────────────────

@app.get("/health")
async def health():
    """
    Health check endpoint for Render/Kubernetes probes.
    """
    return {
        "status": "ok",
        "engine": "active",
        "project": "DiodeShield AI",
        "ps": "SIH26145",
        "team": "SYNTAX TERROR",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.get("/metrics/summary")
async def get_metrics_summary():
    """
    Returns running aggregated metrics for the 4 dashboard metric cards.
    """
    return {
        "packets_analyzed": METRICS["packets_analyzed"],
        "threats_today": METRICS["threats_today"],
        "zero_day_count": METRICS["zero_day_count"],
        "avg_soc_latency_ms": METRICS["avg_soc_latency_ms"]
    }


@app.get("/model-status")
async def get_model_status():
    """
    Returns real-time status, accuracy, and inference metrics for the AI detection models.
    """
    return MODEL_STATUS


@app.post("/simulate-attack")
async def simulate_attack():
    """
    Triggers an immediate burst of 6-10 malicious flows over 2 seconds.
    Powers the frontend 'SIMULATE ATTACK' button.
    """
    burst_size = random.randint(6, 9)
    asyncio.create_task(trigger_attack_burst(burst_count=burst_size))
    return {
        "status": "attack_injected",
        "burst_size": burst_size,
        "target": "untrusted_ingress_diode",
        "message": f"Simulating rapid DDoS/Zero-Day burst ({burst_size} malicious packets) across data diode interface."
    }


@app.get("/threats")
async def get_threats(
    filter: str = Query("all", description="Threat type filter: all, ddos, zero-day, c2, scans"),
    search: str = Query("", description="Search term for flow_id, label, ip, flags, etc.")
):
    """
    Search and filter live/historical threats stored in memory.
    """
    results = THREAT_STORE
    filter_lower = filter.strip().lower()

    if filter_lower and filter_lower != "all":
        if filter_lower in ("ddos", "dos"):
            results = [t for t in results if t.get("threat_type") == "ddos"]
        elif filter_lower in ("zero-day", "zeroday", "zero_day", "anomaly"):
            results = [t for t in results if t.get("threat_type") == "zero-day"]
        elif filter_lower == "c2":
            results = [t for t in results if t.get("threat_type") == "c2"]
        elif filter_lower in ("scans", "scan", "port_scan"):
            results = [t for t in results if t.get("threat_type") == "scans"]

    search_query = search.strip().lower()
    if search_query:
        results = [
            t for t in results
            if search_query in t.get("flow_id", "").lower()
            or search_query in t.get("label", "").lower()
            or search_query in t.get("src_ip", "").lower()
            or search_query in str(t.get("dst_port", "")).lower()
            or search_query in t.get("mitre_technique", "").lower()
            or search_query in " ".join(t.get("tcp_flags", [])).lower()
        ]

    return {
        "threats": results,
        "total": len(results)
    }


@app.get("/threats/export")
async def export_threats_csv():
    """
    Exports the in-memory threat intelligence log to a downloadable CSV file.
    """
    output = io.StringIO()
    writer = csv.writer(output)
    
    # CSV Header
    writer.writerow([
        "Flow ID",
        "Timestamp (UTC)",
        "Threat Label",
        "Threat Type",
        "Confidence",
        "Severity",
        "Source IP",
        "Dest Port",
        "Protocol",
        "TCP Flags",
        "Inference Latency (ms)",
        "Anomaly Score",
        "MITRE Technique",
        "Byte Entropy",
        "Packet Size (Bytes)"
    ])

    for t in THREAT_STORE:
        writer.writerow([
            t.get("flow_id", ""),
            t.get("timestamp", ""),
            t.get("label", ""),
            t.get("threat_type", ""),
            f"{t.get('confidence', 0.0):.3f}",
            t.get("severity", ""),
            t.get("src_ip", ""),
            t.get("dst_port", ""),
            t.get("protocol", ""),
            "|".join(t.get("tcp_flags", [])),
            t.get("latency_ms", ""),
            t.get("anomaly_score") or "N/A",
            t.get("mitre_technique", ""),
            t.get("byte_dist", {}).get("entropy", ""),
            t.get("byte_dist", {}).get("packet_size", "")
        ])

    output.seek(0)
    filename = f"diodeshield_threat_log_{int(time.time())}.csv"
    
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@app.get("/threats/{flow_id}")
async def get_threat_detail(flow_id: str):
    """
    Returns full feature vector and IAT time-series telemetry for the Threat Detail Drawer.
    """
    for t in THREAT_STORE:
        if t.get("flow_id") == flow_id:
            return t
    raise HTTPException(status_code=404, detail=f"Threat flow '{flow_id}' not found.")


# ── WebSocket Realtime Telemetry Stream ─────────────────────────────────

@app.websocket("/ws/live")
async def websocket_live_endpoint(websocket: WebSocket):
    """
    Realtime bidirectional WebSocket channel pushing live packet events,
    threat detections, and metric updates to the frontend dashboard.
    """
    await ws_manager.connect(websocket)
    try:
        # Send initial sync payload immediately upon connection
        await websocket.send_json({
            "type": "connection_established",
            "message": "Connected to DiodeShield AI Telemetry Bus",
            "metrics": {
                "packets_analyzed": METRICS["packets_analyzed"],
                "threats_today": METRICS["threats_today"],
                "zero_day_count": METRICS["zero_day_count"],
                "avg_soc_latency_ms": METRICS["avg_soc_latency_ms"]
            },
            "model_status": MODEL_STATUS
        })

        # Keep socket open and listen for optional client heartbeat/messages
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
                # Handle client ping or query if needed
                if data == "ping":
                    await websocket.send_json({"type": "pong", "timestamp": time.time()})
            except asyncio.TimeoutError:
                # Send keep-alive heartbeat ping
                await websocket.send_json({"type": "heartbeat", "timestamp": time.time()})

    except WebSocketDisconnect:
        await ws_manager.disconnect(websocket)
    except Exception as exc:
        logger.warning(f"WebSocket client encounter: {exc}")
        await ws_manager.disconnect(websocket)
