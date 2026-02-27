import hashlib
import os
import re
import json
import pandas as pd
from datetime import datetime
from pathlib import Path


# ──────────────────────────────────────
# HASHING
# ──────────────────────────────────────
def hash_file(filepath):
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
            md5.update(chunk)
    return {"sha256": sha256.hexdigest(), "md5": md5.hexdigest()}


# ──────────────────────────────────────
# METADATA
# ──────────────────────────────────────
def extract_metadata(filepath):
    stat = os.stat(filepath)
    return {
        "filename": Path(filepath).name,
        "extension": Path(filepath).suffix,
        "size_bytes": stat.st_size,
        "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
        "accessed": datetime.fromtimestamp(stat.st_atime).isoformat(),
    }


# ──────────────────────────────────────
# IOC EXTRACTION
# ──────────────────────────────────────
def extract_iocs(text):
    iocs = {}
    iocs["ips"] = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
    iocs["emails"] = re.findall(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text)
    iocs["urls"] = re.findall(
        r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*', text)
    iocs["filepaths"] = re.findall(
        r'(?:[A-Za-z]:\\[\w\\.\- ]+|/[\w/.\-]+)', text)
    iocs["hashes"] = re.findall(
        r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b', text)
    iocs["domains"] = re.findall(
        r'\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|co|tk|info|to|onion)\b', text)
    return {k: list(set(v)) for k, v in iocs.items()}


# ──────────────────────────────────────
# LOG FILE PARSER
# ──────────────────────────────────────
def parse_log_file(filepath):
    events = []
    timestamp_patterns = [
        r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}',
        r'\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}',
        r'\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}',
    ]
    with open(filepath, 'r', errors='ignore') as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            event = {"line_number": i + 1, "raw": line}
            for pattern in timestamp_patterns:
                match = re.search(pattern, line)
                if match:
                    event["timestamp"] = match.group()
                    break
            for level in ["CRITICAL", "ERROR", "WARNING", "WARN",
                          "FAILED", "ALERT", "SUCCESS", "INFO", "DEBUG"]:
                if level in line.upper():
                    event["severity"] = level
                    break
            events.append(event)
    return events


# ──────────────────────────────────────
# CSV PARSER
# ──────────────────────────────────────
def parse_csv_file(filepath):
    try:
        df = pd.read_csv(filepath, errors='replace')
        return {
            "columns": list(df.columns),
            "row_count": len(df),
            "preview": df.head(20).to_dict(orient='records'),
        }
    except Exception as e:
        return {"error": str(e)}


# ──────────────────────────────────────
# BASIC EVIDENCE PARSER (text/log/csv)
# ──────────────────────────────────────
def parse_evidence_file(filepath):
    result = {
        "metadata": extract_metadata(filepath),
        "hashes": hash_file(filepath),
        "parsed_at": datetime.now().isoformat(),
        "artifacts": {},
        "iocs": {}
    }
    ext = Path(filepath).suffix.lower()
    try:
        with open(filepath, 'r', errors='ignore') as f:
            text_content = f.read()

        result["iocs"] = extract_iocs(text_content)
        result["text_preview"] = text_content[:2000]
        result["full_text"] = text_content

        if ext in ['.log', '.txt']:
            result["artifacts"]["events"] = parse_log_file(filepath)
        elif ext == '.csv':
            result["artifacts"]["structured_data"] = parse_csv_file(filepath)
        else:
            result["artifacts"]["raw_text"] = text_content[:5000]

    except Exception as e:
        result["parse_error"] = str(e)

    return result


# ──────────────────────────────────────
# SMART ROUTER — detects file type
# ──────────────────────────────────────
def parse_evidence_file_v2(filepath):
    ext = Path(filepath).suffix.lower()

    IMAGE_EXTS = ['.jpg', '.jpeg', '.png', '.bmp', '.tiff', '.tif', '.webp']
    AUDIO_EXTS = ['.mp3', '.wav', '.flac', '.m4a', '.ogg', '.aac']

    if ext in IMAGE_EXTS:
        try:
            from modules.image_analyzer import analyze_image
            from modules.stego_detector import detect_image_stego
            result = analyze_image(filepath)
            result["steganography"] = detect_image_stego(filepath)
            result["file_type"] = "image"
            if result.get("forensic_exif"):
                from modules.location_tracker import track_locations
                result["location"] = track_locations(
                    exif_data=result["forensic_exif"]
                )
        except Exception as e:
            result = parse_evidence_file(filepath)
            result["file_type"] = "image"
            result["module_error"] = str(e)
        return result

    elif ext in AUDIO_EXTS:
        try:
            from modules.audio_analyzer import analyze_audio
            from modules.signal_processor import process_signal
            from modules.stego_detector import detect_audio_stego
            result = analyze_audio(filepath)
            result["signal_processing"] = process_signal(filepath)
            result["steganography"] = detect_audio_stego(filepath)
            result["file_type"] = "audio"
            if result.get("transcription", {}).get("full_transcript"):
                from modules.location_tracker import track_locations
                result["location"] = track_locations(
                    text_content=result["transcription"]["full_transcript"]
                )
        except Exception as e:
            result = parse_evidence_file(filepath)
            result["file_type"] = "audio"
            result["module_error"] = str(e)
        return result

    else:
        # Text, log, CSV, JSON etc.
        result = parse_evidence_file(filepath)
        result["file_type"] = "document"
        if result.get("full_text"):
            try:
                from modules.location_tracker import track_locations
                result["location"] = track_locations(
                    text_content=result["full_text"]
                )
            except Exception:
                pass
        return result