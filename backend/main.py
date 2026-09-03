import os
import json
import logging

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from google import genai
from google.genai import types

# ── Logging ───────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("axon-rev-backend")

# ── Gemini client ─────────────────────────────────────────────────────
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
if not GEMINI_API_KEY:
    raise RuntimeError(
        "GEMINI_API_KEY environment variable is not set. "
        "Export it before starting the server: export GEMINI_API_KEY='your-key'"
    )

client = genai.Client(api_key=GEMINI_API_KEY)

MODEL = "gemini-3.6-flash"

SYSTEM_INSTRUCTION = (
    "You are a senior defensive malware analyst working in a Security Operations "
    "Center (SOC). Your role is strictly defensive — you analyze, explain, and "
    "detect malicious scripts submitted by analysts.\n\n"
    "Rules you MUST follow:\n"
    "1. NEVER suggest improvements, evasion techniques, or ways to make the "
    "   malware more effective.\n"
    "2. NEVER generate new malicious code — only explain and deobfuscate what "
    "   is submitted.\n"
    "3. Provide a catchy, descriptive threat name for the malware family.\n"
    "4. Explain in plain English what the code does, its intent, and its impact.\n"
    "5. Produce a clean, deobfuscated, human-readable version of the code with "
    "   comments explaining each significant block.\n"
    "6. Generate a valid, production-quality YARA rule that reliably detects "
    "   this specific script or its variants. The rule must compile without errors.\n"
    "7. If the submitted code appears benign, still analyze it thoroughly and "
    "   note that it is likely non-malicious in your explanation."
)

# ── Pydantic schemas ──────────────────────────────────────────────────

class ScriptInput(BaseModel):
    script: str = Field(description="The raw script text to analyze")


class ThreatAnalysis(BaseModel):
    threat_name: str = Field(description="A catchy name for this malware")
    intent_explanation: str = Field(
        description="Plain English explanation of what the code does"
    )
    deobfuscated_code: str = Field(
        description="Cleaned-up, readable version of the code"
    )
    yara_rule: str = Field(
        description="A valid YARA rule to detect this script"
    )


# ── FastAPI app ───────────────────────────────────────────────────────

app = FastAPI(
    title="AXON.REV Malware Analysis API",
    description="Backend analysis engine for the SOC Workbench — powered by Gemini",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health():
    return {"status": "ok", "model": MODEL}


@app.post("/analyze", response_model=ThreatAnalysis)
async def analyze(payload: ScriptInput):
    """
    Accept a raw script, send it to Gemini for defensive analysis,
    and return structured threat intelligence.
    """
    script_text = payload.script.strip()
    if not script_text:
        raise HTTPException(status_code=400, detail="Script text must not be empty")

    logger.info(
        "Analyzing script (%d chars, first 80: %s…)",
        len(script_text),
        script_text[:80],
    )

    try:
        response = client.models.generate_content(
            model=MODEL,
            contents=f"Analyze the following script:\n\n```\n{script_text}\n```",
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_INSTRUCTION,
                response_mime_type="application/json",
                response_json_schema=ThreatAnalysis.model_json_schema(),
                temperature=0.2,
            ),
        )

        raw_json = response.text
        logger.info("Gemini response received (%d chars)", len(raw_json))

        result = ThreatAnalysis.model_validate_json(raw_json)
        return result

    except Exception as exc:
        logger.exception("Gemini analysis failed")
        raise HTTPException(
            status_code=502,
            detail=f"Upstream Gemini analysis error: {exc}",
        )
