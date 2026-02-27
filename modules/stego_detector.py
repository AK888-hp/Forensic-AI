import numpy as np
from PIL import Image
from pathlib import Path
import librosa
import wave

# ─────────────────────────────────────────
# IMAGE STEGANOGRAPHY
# ─────────────────────────────────────────
def detect_lsb_steganography(filepath):
    """
    LSB = Least Significant Bit steganography.
    
    Every pixel in an image is stored as 8 bits.
    The last bit (LSB) contributes only 1/256 to the color value —
    imperceptible to the human eye.
    Attackers hide messages by replacing LSBs with message bits.
    
    Detection: if LSBs are random (natural image) = clean.
    If LSBs show patterns or non-randomness = hidden data.
    """
    try:
        img = Image.open(filepath).convert('RGB')
        pixels = np.array(img)
        
        results = {}
        
        for channel_idx, channel_name in enumerate(['Red', 'Green', 'Blue']):
            channel = pixels[:, :, channel_idx]
            lsbs = channel & 1  # Extract least significant bits
            
            # Chi-square test for randomness
            # True random LSBs should be ~50% 0s and ~50% 1s
            zeros = np.sum(lsbs == 0)
            ones = np.sum(lsbs == 1)
            total = zeros + ones
            expected = total / 2
            
            # Chi-square statistic
            chi_sq = ((zeros - expected)**2 + (ones - expected)**2) / expected
            
            # Ratio
            ratio = ones / total if total > 0 else 0
            
            results[channel_name] = {
                "lsb_ones_ratio": round(float(ratio), 4),
                "chi_square": round(float(chi_sq), 4),
                "suspicious": abs(ratio - 0.5) < 0.02 and chi_sq < 0.1
                # Paradox: too-perfect 50/50 split = artificial = hidden data
                # Natural images have slight bias; perfect randomness is suspicious
            }
        
        # Overall assessment
        suspicious_channels = sum(1 for c in results.values() if c["suspicious"])
        results["overall"] = {
            "hidden_data_likely": suspicious_channels >= 2,
            "suspicious_channels": suspicious_channels,
            "confidence": f"{suspicious_channels}/3 channels show LSB anomalies"
        }
        
        # ── Try to extract hidden message ──
        results["extracted_attempt"] = attempt_lsb_extraction(pixels)
        
        return results
    except Exception as e:
        return {"error": str(e)}

def attempt_lsb_extraction(pixels):
    """Attempt to read hidden message from LSBs"""
    try:
        bits = []
        flat = pixels.flatten()
        for val in flat[:10000]:  # Check first 10000 values
            bits.append(val & 1)
        
        # Convert bits to bytes to string
        chars = []
        for i in range(0, len(bits)-8, 8):
            byte = 0
            for b in range(8):
                byte = (byte << 1) | bits[i+b]
            if 32 <= byte <= 126:  # Printable ASCII
                chars.append(chr(byte))
            elif byte == 0:
                break
        
        extracted = ''.join(chars)
        return {
            "extracted_text": extracted[:200] if len(extracted) > 5 else "No readable text found",
            "readable_chars_found": len(chars)
        }
    except:
        return {"extracted_text": "Extraction failed"}

def detect_image_stego(filepath):
    """Comprehensive image steganography detection"""
    results = {
        "filepath": filepath,
        "filename": Path(filepath).name
    }
    
    try:
        img = Image.open(filepath)
        pixels = np.array(img.convert('RGB'), dtype=np.float32)
        
        # LSB analysis
        results["lsb_analysis"] = detect_lsb_steganography(filepath)
        
        # Histogram analysis
        # Stego images often show subtle histogram modifications
        for i, color in enumerate(['red', 'green', 'blue']):
            channel = pixels[:,:,i].flatten()
            hist, _ = np.histogram(channel, bins=256, range=(0,256))
            # Look for unusual pairs (LSB flipping creates paired values)
            pairs_diff = np.abs(hist[0::2] - hist[1::2])
            results[f"{color}_histogram_uniformity"] = round(
                float(np.std(pairs_diff)), 3
            )
        
        # File size anomaly
        # Stego images are often larger than expected for their dimensions
        expected_size = img.size[0] * img.size[1] * 3  # RGB bytes
        actual_size = Path(filepath).stat().st_size
        size_ratio = actual_size / expected_size
        results["size_anomaly"] = {
            "expected_min_bytes": expected_size,
            "actual_bytes": actual_size,
            "ratio": round(size_ratio, 3),
            "suspicious": size_ratio > 2.0
        }
        
    except Exception as e:
        results["error"] = str(e)
    
    return results

# ─────────────────────────────────────────
# AUDIO STEGANOGRAPHY
# ─────────────────────────────────────────
def detect_audio_stego(filepath):
    """
    Detect hidden data in audio files.
    Common techniques: LSB in WAV samples, phase coding,
    spread spectrum, echo hiding.
    """
    results = {"filepath": filepath}
    
    try:
        y, sr = librosa.load(filepath, sr=None)
        
        # ── LSB Analysis on audio samples ──
        # Convert to 16-bit integers
        samples_int = (y * 32767).astype(np.int16)
        lsbs = samples_int & 1
        
        ones_ratio = float(np.mean(lsbs))
        results["lsb_ones_ratio"] = round(ones_ratio, 4)
        results["lsb_suspicious"] = abs(ones_ratio - 0.5) < 0.01
        
        # ── Phase analysis ──
        stft = librosa.stft(y)
        phase = np.angle(stft)
        phase_diff = np.diff(phase, axis=1)
        phase_variance = float(np.var(phase_diff))
        results["phase_variance"] = round(phase_variance, 6)
        results["phase_suspicious"] = phase_variance < 0.1
        
        # ── Echo hiding detection ──
        autocorr = np.correlate(y[:10000], y[:10000], mode='full')
        autocorr = autocorr[len(autocorr)//2:]
        peaks = []
        for i in range(1, min(1000, len(autocorr)-1)):
            if (autocorr[i] > autocorr[i-1] and 
                autocorr[i] > autocorr[i+1] and
                autocorr[i] > 0.1 * autocorr[0]):
                peaks.append({"sample": i, "time_ms": round(i/sr*1000, 2)})
        
        results["echo_peaks"] = peaks[:5]
        results["echo_hiding_suspicious"] = len(peaks) > 3
        
        # Overall verdict
        suspicious_count = sum([
            results["lsb_suspicious"],
            results["phase_suspicious"],
            results["echo_hiding_suspicious"]
        ])
        results["overall_verdict"] = {
            "hidden_data_likely": suspicious_count >= 2,
            "confidence_score": suspicious_count / 3,
            "indicators": suspicious_count
        }
        
    except Exception as e:
        results["error"] = str(e)
    
    return results