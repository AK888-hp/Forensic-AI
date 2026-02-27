import os
import json
import shutil
from fastapi import FastAPI, UploadFile, File, Form
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
from collections import defaultdict

# ── App setup ──
app = FastAPI(title="Forensic AI API", version="1.0.0")

# Allow Streamlit to talk to FastAPI
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

# In-memory case store (fine for demo)
cases = defaultdict(list)


# ──────────────────────────────────────
# HEALTH CHECK
# ──────────────────────────────────────
@app.get("/")
async def root():
    return {"status": "Forensic AI API running", "version": "1.0.0"}


@app.get("/health")
async def health():
    return {"status": "ok"}


# ──────────────────────────────────────
# INGEST EVIDENCE
# ──────────────────────────────────────
@app.post("/ingest/{case_id}")
async def ingest_file(case_id: str, file: UploadFile = File(...)):
    filepath = UPLOAD_DIR / file.filename
    with open(filepath, "wb") as f:
        shutil.copyfileobj(file.file, f)

    try:
        from parser import parse_evidence_file_v2
        parsed = parse_evidence_file_v2(str(filepath))
    except Exception as e:
        # Fallback to basic parser if advanced fails
        try:
            from parser import parse_evidence_file
            parsed = parse_evidence_file(str(filepath))
            parsed["file_type"] = "document"
        except Exception as e2:
            return {"status": "error", "error": str(e2)}

    try:
        from ai_agent import index_evidence
        indexed = index_evidence(parsed, case_id)
    except Exception as e:
        indexed = 0

    cases[case_id].append(parsed)

    return {
        "status": "success",
        "filename": file.filename,
        "file_type": parsed.get("file_type", "unknown"),
        "iocs_found": parsed.get("iocs", {}),
        "tampering_detected": parsed.get("tampering", {}).get("tampering_likelihood", "N/A"),
        "locations_found": parsed.get("location", {}).get("total_locations_found", 0),
        "vectors_indexed": indexed
    }


# ──────────────────────────────────────
# INVESTIGATE (direct — no n8n)
# ──────────────────────────────────────
@app.post("/investigate/{case_id}")
async def investigate_case(case_id: str, query: str = Form(...)):
    all_evidence = cases.get(case_id, [])
    try:
        from ai_agent import investigate
        result = investigate(query, case_id, all_evidence)
        return result
    except Exception as e:
        return {"error": str(e), "answer": f"Investigation error: {str(e)}"}


# ──────────────────────────────────────
# WEBHOOK — called BY n8n
# ──────────────────────────────────────
@app.post("/webhook/investigate")
async def webhook_investigate(request: dict):
    query = request.get("query", "")
    case_id = request.get("case_id", "default")
    user_role = request.get("user_role", "viewer")

    try:
        from guardrails import run_guardrail_pipeline
        from ai_agent import investigate

        result = run_guardrail_pipeline(
            query=query,
            user_role=user_role,
            agent_function=investigate,
            case_id=case_id,
            all_evidence=cases.get(case_id, [])
        )
        return result

    except Exception as e:
        # Fallback if guardrails module has issues
        try:
            from ai_agent import investigate
            answer = investigate(query, case_id, cases.get(case_id, []))
            return {
                "final_response": answer.get("answer", str(answer)),
                "blocked": False,
                "warnings": [f"Guardrails bypassed due to error: {str(e)}"],
                "stages": {}
            }
        except Exception as e2:
            return {
                "final_response": f"Error: {str(e2)}",
                "blocked": True,
                "warnings": [],
                "stages": {}
            }


# ──────────────────────────────────────
# CASE SUMMARY
# ──────────────────────────────────────
@app.get("/summary/{case_id}")
async def case_summary(case_id: str):
    all_evidence = cases.get(case_id, [])
    if not all_evidence:
        return {"error": "No evidence found for this case"}
    try:
        from ai_agent import generate_case_summary
        summary = generate_case_summary(all_evidence, case_id)
        return {"summary": summary}
    except Exception as e:
        return {"error": str(e)}


# ──────────────────────────────────────
# DOWNLOAD PDF REPORT
# ──────────────────────────────────────
@app.get("/report/{case_id}")
async def download_report(case_id: str):
    all_evidence = cases.get(case_id, [])
    if not all_evidence:
        return {"error": "No evidence found"}
    try:
        from ai_agent import generate_case_summary
        from report import generate_pdf_report
        summary = generate_case_summary(all_evidence, case_id)
        path = generate_pdf_report(case_id, summary, all_evidence)
        return FileResponse(
            path,
            media_type="application/pdf",
            filename=f"forensic_report_{case_id}.pdf"
        )
    except Exception as e:
        return {"error": str(e)}


# ──────────────────────────────────────
# GET ARTIFACTS
# ──────────────────────────────────────
@app.get("/artifacts/{case_id}")
async def get_artifacts(case_id: str):
    evidence = cases.get(case_id, [])
    # Return lightweight version (no full_text to keep response small)
    lightweight = []
    for ev in evidence:
        item = {
            "metadata": ev.get("metadata", {}),
            "hashes": ev.get("hashes", {}),
            "iocs": ev.get("iocs", {}),
            "file_type": ev.get("file_type", "unknown"),
            "tampering": ev.get("tampering", {})
        }
        lightweight.append(item)
    return {"case_id": case_id, "evidence_count": len(evidence), "evidence": lightweight}


# ──────────────────────────────────────
# LOCATION MAP
# ──────────────────────────────────────
@app.get("/map/{case_id}", response_class=HTMLResponse)
async def get_location_map(case_id: str):
    map_path = f"/tmp/location_map_{case_id}.html"
    if os.path.exists(map_path):
        with open(map_path, "r") as f:
            return f.read()
    return "<h3 style='font-family:sans-serif;padding:20px'>No location data found for this case. Upload evidence with GPS data first.</h3>"


# ──────────────────────────────────────
# SERVE ANALYSIS IMAGES
# ──────────────────────────────────────
@app.get("/ela/{filename}")
async def get_ela_image(filename: str):
    path = f"/tmp/ela_{filename}.png"
    if os.path.exists(path):
        return FileResponse(path, media_type="image/png")
    return {"error": "ELA image not found"}


@app.get("/spectrogram/{filename}")
async def get_spectrogram(filename: str):
    path = f"/tmp/{filename}_spectrogram.png"
    if os.path.exists(path):
        return FileResponse(path, media_type="image/png")
    return {"error": "Spectrogram not found"}


@app.get("/fft/{filename}")
async def get_fft_plot(filename: str):
    path = f"/tmp/{filename}_fft.png"
    if os.path.exists(path):
        return FileResponse(path, media_type="image/png")
    return {"error": "FFT plot not found"}


# ──────────────────────────────────────
# AUDIT LOG
# ──────────────────────────────────────
@app.get("/audit-log")
async def get_audit_log():
    try:
        with open("forensic_audit.log", "r") as f:
            lines = f.readlines()
        entries = []
        for line in lines[-50:]:
            try:
                json_start = line.index("{")
                entry = json.loads(line[json_start:])
                entries.append(entry)
            except Exception:
                pass
        return {"logs": entries}
    except FileNotFoundError:
        return {"logs": []}
    except Exception as e:
        return {"logs": [], "error": str(e)}


# ──────────────────────────────────────
# LIST ALL CASES
# ──────────────────────────────────────
@app.get("/cases")
async def list_cases():
    return {
        "cases": [
            {
                "case_id": k,
                "evidence_count": len(v),
                "files": [e.get("metadata", {}).get("filename", "unknown") for e in v]
            }
            for k, v in cases.items()
        ]
    }