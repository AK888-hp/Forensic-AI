import os
import numpy as np
import librosa
import whisper
from pathlib import Path
from datetime import datetime

# Load Whisper once (expensive operation)
_whisper_model = None
def get_whisper():
    global _whisper_model
    if _whisper_model is None:
        # 'base' model balances speed vs accuracy
        # Options: tiny, base, small, medium, large
        _whisper_model = whisper.load_model("base")
    return _whisper_model

# ─────────────────────────────────────────
# TRANSCRIPTION
# ─────────────────────────────────────────
def transcribe_audio(filepath):
    """
    OpenAI Whisper — state of the art speech to text.
    Works on recordings, phone calls, voicemails.
    Critical for: intercepted communications, voice notes,
    recorded meetings, ransom demands.
    """
    try:
        model = get_whisper()
        result = model.transcribe(filepath, verbose=False)
        
        return {
            "full_transcript": result["text"],
            "language_detected": result.get("language", "unknown"),
            "segments": [
                {
                    "start": seg["start"],
                    "end": seg["end"],
                    "text": seg["text"],
                    "confidence": seg.get("avg_logprob", 0)
                }
                for seg in result.get("segments", [])
            ]
        }
    except Exception as e:
        return {"error": str(e)}

# ─────────────────────────────────────────
# AUDIO PROPERTIES & METADATA
# ─────────────────────────────────────────
def extract_audio_metadata(filepath):
    """Extract technical metadata from audio file"""
    try:
        y, sr = librosa.load(filepath, sr=None)
        duration = librosa.get_duration(y=y, sr=sr)
        
        return {
            "sample_rate": sr,
            "duration_seconds": round(duration, 2),
            "duration_formatted": f"{int(duration//60)}m {int(duration%60)}s",
            "total_samples": len(y),
            "channels": "mono" if y.ndim == 1 else "stereo",
            "file_size_bytes": os.path.getsize(filepath)
        }
    except Exception as e:
        return {"error": str(e)}

# ─────────────────────────────────────────
# SPEAKER ANALYSIS
# ─────────────────────────────────────────
def analyze_speakers(filepath):
    """
    Voice activity detection and basic speaker change detection.
    In a full system this would use pyannote.audio for
    diarization — identifying WHO said WHAT and WHEN.
    Here we implement a signal-energy-based approach.
    """
    try:
        y, sr = librosa.load(filepath, sr=None)
        
        # ── Voice Activity Detection ──
        # Split audio into 0.1 second frames
        frame_length = int(sr * 0.1)
        rms_energy = librosa.feature.rms(
            y=y, frame_length=frame_length, hop_length=frame_length//2
        )[0]
        
        # Threshold: frames above 20% of max energy = speech
        threshold = 0.2 * np.max(rms_energy)
        speech_frames = rms_energy > threshold
        speech_ratio = float(np.mean(speech_frames))
        
        # ── Speaker Change Detection ──
        # MFCCs capture vocal tract characteristics unique to each speaker
        mfccs = librosa.feature.mfcc(y=y, sr=sr, n_mfcc=13)
        
        # Detect sudden changes in MFCC (= potential speaker change)
        mfcc_diff = np.diff(mfccs, axis=1)
        change_magnitude = np.sum(np.abs(mfcc_diff), axis=0)
        
        # Peaks in change magnitude = likely speaker transitions
        mean_change = np.mean(change_magnitude)
        std_change = np.std(change_magnitude)
        speaker_changes = np.where(
            change_magnitude > mean_change + 2 * std_change
        )[0]
        
        # Convert frame indices to timestamps
        hop_length = 512
        change_times = librosa.frames_to_time(
            speaker_changes, sr=sr, hop_length=hop_length
        )
        
        return {
            "speech_activity_ratio": round(speech_ratio, 3),
            "estimated_speech_duration": round(
                speech_ratio * librosa.get_duration(y=y, sr=sr), 2
            ),
            "potential_speaker_changes": len(change_times),
            "speaker_change_timestamps": [round(t, 2) for t in change_times[:20]],
            "estimated_speakers": min(len(change_times) // 3 + 1, 10)
        }
    except Exception as e:
        return {"error": str(e)}

# ─────────────────────────────────────────
# AUDIO TAMPERING DETECTION
# ─────────────────────────────────────────
def detect_audio_tampering(filepath):
    """
    Detect cuts, splices, and edits in audio recordings.
    Authentic recordings have consistent background noise.
    Edited recordings show discontinuities in noise floor.
    """
    try:
        y, sr = librosa.load(filepath, sr=None)
        
        # ── ENF Analysis (Electric Network Frequency) ──
        # Mains power hum (50Hz in India/EU, 60Hz in US)
        # embeds itself in recordings made near electrical equipment.
        # The frequency fluctuates slightly over time in a pattern
        # recorded by power companies. Discontinuities reveal edits.
        
        # Extract spectral content around 50Hz (India standard)
        stft = librosa.stft(y)
        freqs = librosa.fft_frequencies(sr=sr)
        enf_band = np.where((freqs >= 49) & (freqs <= 51))[0]
        enf_energy = np.mean(np.abs(stft[enf_band, :]), axis=0)
        enf_variation = float(np.std(enf_energy))
        
        # ── Silence Analysis ──
        # Inserted silences (editing artifacts) appear as
        # perfectly zero-amplitude sections — unnatural in real recordings
        silence_threshold = 0.001
        silence_frames = np.abs(y) < silence_threshold
        silence_runs = []
        in_silence = False
        start = 0
        for i, s in enumerate(silence_frames):
            if s and not in_silence:
                start = i
                in_silence = True
            elif not s and in_silence:
                duration = (i - start) / sr
                if duration > 0.1:  # >100ms silence = suspicious
                    silence_runs.append({
                        "start_sec": round(start/sr, 2),
                        "duration_sec": round(duration, 2)
                    })
                in_silence = False
        
        # ── Spectral Discontinuity ──
        spectral_centroids = librosa.feature.spectral_centroid(y=y, sr=sr)[0]
        centroid_diff = np.abs(np.diff(spectral_centroids))
        discontinuities = np.where(centroid_diff > np.mean(centroid_diff) + 3*np.std(centroid_diff))[0]
        disc_times = librosa.frames_to_time(discontinuities, sr=sr)
        
        tampering_score = 0
        if len(silence_runs) > 3: tampering_score += 30
        if len(discontinuities) > 10: tampering_score += 30
        if enf_variation > 0.5: tampering_score += 40
        
        return {
            "tampering_score": tampering_score,
            "tampering_likelihood": "HIGH" if tampering_score > 60 else "MEDIUM" if tampering_score > 30 else "LOW",
            "suspicious_silences": silence_runs[:10],
            "spectral_discontinuities": [round(t,2) for t in disc_times[:10]],
            "enf_variation": round(enf_variation, 4)
        }
    except Exception as e:
        return {"error": str(e)}

def analyze_audio(filepath):
    """Master audio analysis function"""
    return {
        "filepath": filepath,
        "filename": Path(filepath).name,
        "analyzed_at": datetime.now().isoformat(),
        "metadata": extract_audio_metadata(filepath),
        "transcription": transcribe_audio(filepath),
        "speaker_analysis": analyze_speakers(filepath),
        "tampering_detection": detect_audio_tampering(filepath)
    }