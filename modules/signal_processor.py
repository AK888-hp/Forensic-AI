import numpy as np
import librosa
from scipy import signal
from scipy.fft import fft, fftfreq
from pathlib import Path
import matplotlib
matplotlib.use('Agg')  # non-interactive backend
import matplotlib.pyplot as plt

# ─────────────────────────────────────────
# FFT ANALYSIS
# ─────────────────────────────────────────
def compute_fft(filepath, output_dir="/tmp"):
    """
    Fast Fourier Transform — decomposes a signal into its
    constituent frequencies. Think of it like a prism splitting
    white light into a rainbow — FFT splits a complex signal
    into its pure frequency components.
    
    Forensic uses:
    - Identify hidden tones/signals embedded in audio
    - Detect steganographic frequency-domain watermarks
    - Analyze radio signals captured as audio
    - Identify device fingerprints (every mic has a unique
      frequency response profile)
    """
    y, sr = librosa.load(filepath, sr=None)
    
    # Compute FFT
    N = len(y)
    yf = fft(y)
    xf = fftfreq(N, 1/sr)
    
    # Only positive frequencies
    pos_mask = xf >= 0
    xf_pos = xf[pos_mask]
    magnitude = 2.0/N * np.abs(yf[pos_mask])
    
    # Find dominant frequencies
    top_indices = np.argsort(magnitude)[-10:][::-1]
    dominant_freqs = [
        {"frequency_hz": round(float(xf_pos[i]), 2),
         "magnitude": round(float(magnitude[i]), 6)}
        for i in top_indices
    ]
    
    # Plot FFT spectrum
    plt.figure(figsize=(12, 4))
    plt.plot(xf_pos[:N//4], magnitude[:N//4])
    plt.xlabel('Frequency (Hz)')
    plt.ylabel('Magnitude')
    plt.title('FFT Frequency Spectrum')
    plt.grid(True, alpha=0.3)
    fft_path = f"{output_dir}/{Path(filepath).stem}_fft.png"
    plt.savefig(fft_path, dpi=100, bbox_inches='tight')
    plt.close()
    
    return {
        "dominant_frequencies": dominant_freqs,
        "sample_rate": sr,
        "fft_plot": fft_path,
        "frequency_resolution": round(sr/N, 4)
    }

# ─────────────────────────────────────────
# SPECTROGRAM
# ─────────────────────────────────────────
def generate_spectrogram(filepath, output_dir="/tmp"):
    """
    Spectrogram = FFT over time. Shows how frequencies
    change over the duration of the signal.
    
    Forensic uses:
    - Visualize hidden messages encoded in frequency patterns
    - Identify recording environment (room acoustics)
    - Detect signal injection attacks
    - Analyze DTMF tones (phone keypad presses)
    """
    y, sr = librosa.load(filepath, sr=None)
    
    # Mel spectrogram (perceptually weighted)
    mel_spec = librosa.feature.melspectrogram(y=y, sr=sr, n_mels=128)
    mel_db = librosa.power_to_db(mel_spec, ref=np.max)
    
    # Plot
    plt.figure(figsize=(12, 6))
    plt.subplot(2, 1, 1)
    librosa.display.specshow(mel_db, sr=sr, x_axis='time', y_axis='mel')
    plt.colorbar(format='%+2.0f dB')
    plt.title('Mel Spectrogram')
    
    # Chromagram (pitch class distribution)
    chroma = librosa.feature.chroma_stft(y=y, sr=sr)
    plt.subplot(2, 1, 2)
    librosa.display.specshow(chroma, sr=sr, x_axis='time', y_axis='chroma')
    plt.colorbar()
    plt.title('Chromagram')
    
    plt.tight_layout()
    spec_path = f"{output_dir}/{Path(filepath).stem}_spectrogram.png"
    plt.savefig(spec_path, dpi=100, bbox_inches='tight')
    plt.close()
    
    return spec_path

# ─────────────────────────────────────────
# ANOMALY DETECTION IN SIGNALS
# ─────────────────────────────────────────
def detect_signal_anomalies(filepath):
    """
    Statistical anomaly detection on the signal.
    Uses z-score and isolation forest principles to find
    segments that don't belong — injected signals,
    hidden transmissions, or spliced content.
    """
    y, sr = librosa.load(filepath, sr=None)
    
    # Compute RMS energy in windows
    frame_length = sr // 10  # 100ms windows
    rms = librosa.feature.rms(y=y, frame_length=frame_length,
                               hop_length=frame_length//2)[0]
    
    # Z-score anomaly detection
    mean_rms = np.mean(rms)
    std_rms = np.std(rms)
    z_scores = (rms - mean_rms) / (std_rms + 1e-10)
    
    anomalies = []
    for i, z in enumerate(z_scores):
        if abs(z) > 3:  # 3 sigma = anomaly
            time_sec = i * (frame_length//2) / sr
            anomalies.append({
                "time_seconds": round(time_sec, 2),
                "z_score": round(float(z), 3),
                "type": "HIGH_ENERGY" if z > 0 else "SILENCE_DROP",
                "severity": "HIGH" if abs(z) > 5 else "MEDIUM"
            })
    
    # Spectral anomalies — sudden frequency content changes
    spectral_flux = librosa.onset.onset_strength(y=y, sr=sr)
    flux_mean = np.mean(spectral_flux)
    flux_std = np.std(spectral_flux)
    flux_anomalies = np.where(spectral_flux > flux_mean + 4*flux_std)[0]
    flux_times = librosa.frames_to_time(flux_anomalies, sr=sr)
    
    return {
        "energy_anomalies": anomalies[:20],
        "spectral_anomaly_count": len(flux_anomalies),
        "spectral_anomaly_times": [round(t,2) for t in flux_times[:20]],
        "signal_statistics": {
            "mean_energy": round(float(mean_rms), 6),
            "std_energy": round(float(std_rms), 6),
            "dynamic_range_db": round(float(20 * np.log10(
                np.max(np.abs(y)) / (np.mean(np.abs(y)) + 1e-10)
            )), 2)
        }
    }

# ─────────────────────────────────────────
# DTMF TONE DETECTION (Phone keypad)
# ─────────────────────────────────────────
def detect_dtmf_tones(filepath):
    """
    DTMF = Dual Tone Multi Frequency — the tones phones
    make when you press keys. Each key = two simultaneous
    frequencies. Detecting these in a recording reveals
    what phone numbers were dialed.
    """
    DTMF_TABLE = {
        (697, 1209): '1', (697, 1336): '2', (697, 1477): '3',
        (770, 1209): '4', (770, 1336): '5', (770, 1477): '6',
        (852, 1209): '7', (852, 1336): '8', (852, 1477): '9',
        (941, 1209): '*', (941, 1336): '0', (941, 1477): '#',
    }
    
    try:
        y, sr = librosa.load(filepath, sr=None)
        detected = []
        
        # Analyze in 50ms windows
        window_size = int(sr * 0.05)
        for i in range(0, len(y) - window_size, window_size//2):
            frame = y[i:i+window_size]
            yf = np.abs(fft(frame))
            xf = fftfreq(len(frame), 1/sr)
            
            # Check for DTMF frequencies
            for (low_f, high_f), digit in DTMF_TABLE.items():
                low_idx = np.argmin(np.abs(xf - low_f))
                high_idx = np.argmin(np.abs(xf - high_f))
                
                if (yf[low_idx] > np.mean(yf) * 3 and
                    yf[high_idx] > np.mean(yf) * 3):
                    time_sec = i / sr
                    if not detected or detected[-1]["digit"] != digit:
                        detected.append({
                            "digit": digit,
                            "time_seconds": round(time_sec, 2)
                        })
        
        dialed_number = ''.join([d["digit"] for d in detected])
        return {
            "dtmf_tones_detected": detected,
            "reconstructed_number": dialed_number if dialed_number else "No DTMF detected"
        }
    except Exception as e:
        return {"error": str(e)}

def process_signal(filepath):
    """Master signal processing function"""
    return {
        "filepath": filepath,
        "filename": Path(filepath).name,
        "fft_analysis": compute_fft(filepath),
        "spectrogram": generate_spectrogram(filepath),
        "anomalies": detect_signal_anomalies(filepath),
        "dtmf_detection": detect_dtmf_tones(filepath)
    }