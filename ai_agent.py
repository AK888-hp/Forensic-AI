import os
import json
import uuid
import requests as req


OLLAMA_MODEL = "llama3.2:1b"
OLLAMA_URL = "http://localhost:11434/api/generate"

def call_llm(prompt):
    try:
        response = req.post(OLLAMA_URL, json={
            "model": OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False
        }, timeout=120)
        return response.json()["response"]
    except Exception as e:
        return f"LLM error: {str(e)}"

QDRANT_AVAILABLE = False
try:
    from qdrant_client import QdrantClient
    from qdrant_client.models import Distance, VectorParams, PointStruct
    qdrant = QdrantClient(host="localhost", port=6333)
    qdrant.get_collections()
    QDRANT_AVAILABLE = True
    print("✅ Qdrant connected")
except Exception as e:
    print(f"⚠️  Qdrant not available — using direct LLM mode")

COLLECTION_NAME = "forensic_evidence"

# ──────────────────────────────────────
# VECTOR STORE HELPERS
# ──────────────────────────────────────
def ensure_collection():
    if not QDRANT_AVAILABLE:
        return
    try:
        qdrant.get_collection(COLLECTION_NAME)
    except Exception:
        qdrant.create_collection(
            collection_name=COLLECTION_NAME,
            vectors_config=VectorParams(size=768, distance=Distance.COSINE)
        )


def embed_text(text):
    # Ollama embeddings
    try:
        response = req.post("http://localhost:11434/api/embeddings", json={
            "model": "llama3.2:1b",
            "prompt": text[:4000]
        }, timeout=60)
        return response.json()["embedding"]
    except Exception as e:
        print(f"Embedding error: {e}")
        return [0.0] * 768


def index_evidence(parsed_evidence, case_id="default"):
    """Index parsed evidence into Qdrant vector store"""
    if not QDRANT_AVAILABLE:
        return 0

    ensure_collection()
    points = []

    # Build summary text for embedding
    meta = parsed_evidence.get("metadata", {})
    iocs = parsed_evidence.get("iocs", {})

    summary = f"""
File: {meta.get('filename', 'unknown')}
Size: {meta.get('size_bytes', 0)} bytes
Modified: {meta.get('modified', 'unknown')}
SHA256: {parsed_evidence.get('hashes', {}).get('sha256', 'unknown')}
IPs found: {iocs.get('ips', [])}
URLs found: {iocs.get('urls', [])}
Emails found: {iocs.get('emails', [])}
Domains found: {iocs.get('domains', [])}
Hashes found: {iocs.get('hashes', [])}
"""
    points.append(PointStruct(
        id=str(uuid.uuid4()),
        vector=embed_text(summary),
        payload={
            "type": "metadata",
            "case_id": case_id,
            "content": summary,
            "filename": meta.get("filename", "unknown")
        }
    ))

    # Index full text in chunks
    full_text = parsed_evidence.get("full_text", "")
    chunk_size = 1000
    for i in range(0, min(len(full_text), 15000), chunk_size):
        chunk = full_text[i:i + chunk_size]
        if chunk.strip():
            points.append(PointStruct(
                id=str(uuid.uuid4()),
                vector=embed_text(chunk),
                payload={
                    "type": "content",
                    "case_id": case_id,
                    "content": chunk,
                    "filename": meta.get("filename", "unknown")
                }
            ))

    # Index IOCs separately for targeted search
    ioc_text = json.dumps(iocs)
    if ioc_text != "{}":
        points.append(PointStruct(
            id=str(uuid.uuid4()),
            vector=embed_text(ioc_text),
            payload={
                "type": "iocs",
                "case_id": case_id,
                "content": ioc_text,
                "filename": meta.get("filename", "unknown")
            }
        ))

    try:
        qdrant.upsert(collection_name=COLLECTION_NAME, points=points)
    except Exception as e:
        print(f"Qdrant upsert error: {e}")
        return 0

    return len(points)


def search_evidence(query, case_id="default", top_k=5):
    """Semantic search over indexed evidence"""
    if not QDRANT_AVAILABLE:
        return []

    ensure_collection()
    try:
        query_vector = embed_text(query)
        results = qdrant.search(
            collection_name=COLLECTION_NAME,
            query_vector=query_vector,
            limit=top_k,
            query_filter={
                "must": [{"key": "case_id", "match": {"value": case_id}}]
            }
        )
        return [
            {
                "content": r.payload["content"],
                "filename": r.payload["filename"],
                "type": r.payload["type"],
                "score": r.score
            }
            for r in results
        ]
    except Exception as e:
        print(f"Search error: {e}")
        return []


# ──────────────────────────────────────
# MAIN INVESTIGATION FUNCTION
# ──────────────────────────────────────
def investigate(query, case_id="default", all_evidence=None):
    """
    Core forensic AI agent.
    Uses RAG if Qdrant is available, otherwise uses
    all evidence text directly in context (fallback).
    """
    if all_evidence is None:
        all_evidence = []

    # ── Build context ──
    context = ""

    if QDRANT_AVAILABLE:
        # RAG mode — retrieve most relevant chunks
        relevant = search_evidence(query, case_id)
        if relevant:
            context = "\n\n---\n\n".join([
                f"[From: {r['filename']} | Relevance: {r['score']:.2f}]\n{r['content']}"
                for r in relevant
            ])
        sources = relevant
    else:
        sources = []

    # Fallback — use raw evidence text if no RAG results
    if not context and all_evidence:
        evidence_texts = []
        for ev in all_evidence[:5]:  # limit to 5 files to stay within token limit
            fname = ev.get("metadata", {}).get("filename", "unknown")
            sources.append({
                "filename": fname,
                "content": "Full file context used",
                "type": "fallback"
            })
            text = ev.get("full_text", "")[:2000]
            iocs = ev.get("iocs", {})
            evidence_texts.append(
                f"[File: {fname}]\n{text}\nIOCs: {json.dumps(iocs)}"
            )
        context = "\n\n---\n\n".join(evidence_texts)

    if not context:
        context = "No case-specific evidence has been uploaded yet. Answer based on general digital forensics knowledge and best practices."
    # ── File summary ──
    file_list = ", ".join([
        ev.get("metadata", {}).get("filename", "unknown")
        for ev in all_evidence
    ]) if all_evidence else "No files uploaded"

    # ── System prompt ──
    system_prompt = """You are an expert digital forensic investigator AI with 20 years of experience.
You analyze digital evidence including logs, network captures, emails, malware reports, and location data.

Your responsibilities:
- Identify suspicious activities, threats, and anomalies
- Correlate evidence across multiple files
- Identify Indicators of Compromise (IOCs): IPs, domains, hashes, emails
- Establish timelines of events
- Identify suspects and their actions
- Always cite which specific file your findings come from
- Express confidence levels for your findings
- Flag anything that requires human expert review

Rules:
- Only draw conclusions supported by the evidence provided
- Never speculate beyond what the evidence shows
- Always mention the source file for each finding
- If evidence is insufficient, say so clearly"""

    user_prompt = f"""FORENSIC INVESTIGATION QUERY: {query}

CASE ID: {case_id}
FILES IN EVIDENCE: {file_list}

RELEVANT EVIDENCE:
{context}

Provide a detailed, structured forensic analysis. Cite source files for every finding."""

    try:
        full_prompt = f"{system_prompt}\n\n{user_prompt}"
        answer = call_llm(full_prompt)
    except Exception as e:
        answer = f"LLM error: {str(e)}"

    return {
        "answer": answer,
        "sources": sources,
        "rag_used": QDRANT_AVAILABLE and len(sources) > 0,
        "evidence_files": len(all_evidence)
    }


# ──────────────────────────────────────
# CASE SUMMARY GENERATOR
# ──────────────────────────────────────
def generate_case_summary(all_evidence, case_id="default"):
    """Generate a comprehensive forensic case summary report"""

    # Aggregate all IOCs across all evidence files
    all_iocs = {
        "ips": [], "urls": [], "emails": [],
        "hashes": [], "filepaths": [], "domains": []
    }
    file_summaries = []

    for ev in all_evidence:
        fname = ev.get("metadata", {}).get("filename", "unknown")
        size = ev.get("metadata", {}).get("size_bytes", 0)
        modified = ev.get("metadata", {}).get("modified", "unknown")
        sha256 = ev.get("hashes", {}).get("sha256", "unknown")
        file_type = ev.get("file_type", "unknown")
        tampering = ev.get("tampering", {}).get("tampering_likelihood", "N/A")

        file_summaries.append(
            f"- {fname} | Type: {file_type} | Size: {size} bytes | "
            f"Modified: {modified} | SHA256: {sha256[:16]}... | "
            f"Tampering: {tampering}"
        )

        for ioc_type in all_iocs:
            vals = ev.get("iocs", {}).get(ioc_type, [])
            all_iocs[ioc_type].extend(vals)

    # Deduplicate
    all_iocs = {k: list(set(v)) for k, v in all_iocs.items()}

    # Get text context from evidence
    evidence_context = ""
    for ev in all_evidence[:3]:
        fname = ev.get("metadata", {}).get("filename", "unknown")
        text = ev.get("full_text", "")[:1500]
        if text:
            evidence_context += f"\n\n[{fname}]\n{text}"

    prompt = f"""You are a senior digital forensic investigator. 
Generate a comprehensive, professional forensic investigation report.

CASE ID: {case_id}

FILES ANALYZED:
{chr(10).join(file_summaries)}

INDICATORS OF COMPROMISE FOUND:
- IP Addresses: {all_iocs['ips']}
- Domains: {all_iocs['domains']}
- URLs: {all_iocs['urls']}
- Email Addresses: {all_iocs['emails']}
- File Hashes: {all_iocs['hashes']}
- File Paths: {all_iocs['filepaths']}

EVIDENCE CONTENT PREVIEW:
{evidence_context[:3000]}

Generate a professional forensic report with these exact sections:
1. EXECUTIVE SUMMARY (2-3 sentences overview)
2. FILES ANALYZED (list each file with key observations)
3. ATTACK TIMELINE (chronological sequence of events)
4. KEY FINDINGS (most important discoveries)
5. INDICATORS OF COMPROMISE (complete IOC list)
6. SUSPECT ANALYSIS (who, what, when, how)
7. RISK ASSESSMENT (Low/Medium/High/Critical with justification)
8. RECOMMENDED ACTIONS (prioritized response steps)
9. CONCLUSION"""

    try:
        response = call_llm(prompt)
        return response
    except Exception as e:
        return f"Summary generation error: {str(e)}"