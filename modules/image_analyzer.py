import os
import numpy as np
from PIL import Image, ImageEnhance, ImageFilter
import cv2
import exifread
from datetime import datetime
from pathlib import Path

# ─────────────────────────────────────────
# EXIF EXTRACTION
# ─────────────────────────────────────────
def extract_exif(filepath):
    """
    EXIF = Exchangeable Image File Format
    Every camera/phone embeds metadata into images.
    This is gold for forensics — device info, GPS, timestamps.
    """
    exif_data = {}
    try:
        with open(filepath, 'rb') as f:
            tags = exifread.process_file(f, details=True)
        for tag, value in tags.items():
            exif_data[tag] = str(value)
    except Exception as e:
        exif_data["error"] = str(e)
    return exif_data

def parse_exif_forensics(exif_data):
    """Extract forensically relevant fields from raw EXIF"""
    forensic = {}
    
    # Device identification
    forensic["camera_make"] = exif_data.get("Image Make", "Unknown")
    forensic["camera_model"] = exif_data.get("Image Model", "Unknown")
    forensic["software"] = exif_data.get("Image Software", "Unknown")
    
    # Timestamps — critical for establishing timeline
    forensic["date_taken"] = exif_data.get("EXIF DateTimeOriginal", 
                             exif_data.get("Image DateTime", "Unknown"))
    forensic["date_modified"] = exif_data.get("EXIF DateTimeDigitized", "Unknown")
    
    # GPS coordinates
    gps_lat = exif_data.get("GPS GPSLatitude")
    gps_lat_ref = exif_data.get("GPS GPSLatitudeRef")
    gps_lon = exif_data.get("GPS GPSLongitude")
    gps_lon_ref = exif_data.get("GPS GPSLongitudeRef")
    
    if gps_lat and gps_lon:
        forensic["gps_raw"] = {
            "latitude": str(gps_lat),
            "latitude_ref": str(gps_lat_ref),
            "longitude": str(gps_lon),
            "longitude_ref": str(gps_lon_ref)
        }
        # Convert to decimal degrees
        forensic["gps_decimal"] = convert_gps_to_decimal(
            str(gps_lat), str(gps_lat_ref),
            str(gps_lon), str(gps_lon_ref)
        )
    
    # Camera settings — can reveal if image was professionally staged
    forensic["focal_length"] = exif_data.get("EXIF FocalLength", "Unknown")
    forensic["exposure_time"] = exif_data.get("EXIF ExposureTime", "Unknown")
    forensic["iso"] = exif_data.get("EXIF ISOSpeedRatings", "Unknown")
    forensic["flash"] = exif_data.get("EXIF Flash", "Unknown")
    
    return forensic

def convert_gps_to_decimal(lat_str, lat_ref, lon_str, lon_ref):
    """Convert GPS DMS format to decimal degrees"""
    try:
        def parse_dms(dms_str):
            # Format: [deg, min, sec] as fractions
            parts = dms_str.strip('[]').split(', ')
            values = []
            for p in parts:
                if '/' in p:
                    num, den = p.split('/')
                    values.append(float(num) / float(den))
                else:
                    values.append(float(p))
            deg, mins, sec = values[0], values[1], values[2]
            return deg + (mins / 60.0) + (sec / 3600.0)
        
        lat = parse_dms(lat_str)
        lon = parse_dms(lon_str)
        
        if 'S' in lat_ref: lat = -lat
        if 'W' in lon_ref: lon = -lon
        
        return {"latitude": round(lat, 6), "longitude": round(lon, 6)}
    except:
        return None

# ─────────────────────────────────────────
# TAMPERING DETECTION
# ─────────────────────────────────────────
def detect_tampering(filepath):
    """
    Error Level Analysis (ELA) — detects image manipulation.
    
    How it works:
    JPEG compression is lossy. Each time you save a JPEG,
    areas that haven't changed compress to a uniform error level.
    Areas that HAVE been edited (copy-paste, photoshop) retain
    a different error level from the original.
    ELA reveals these inconsistencies as bright regions.
    """
    results = {}
    
    try:
        img = Image.open(filepath).convert('RGB')
        
        # ── ELA Analysis ──
        # Save at known quality
        ela_path = "/tmp/ela_temp.jpg"
        img.save(ela_path, 'JPEG', quality=90)
        
        # Reload and compute difference
        ela_img = Image.open(ela_path)
        ela_array = np.array(img, dtype=np.float32) - np.array(ela_img, dtype=np.float32)
        
        # Scale for visibility
        ela_scaled = np.abs(ela_array) * 15
        ela_scaled = np.clip(ela_scaled, 0, 255).astype(np.uint8)
        
        # Analyze ELA results
        ela_mean = float(np.mean(ela_scaled))
        ela_max = float(np.max(ela_scaled))
        ela_std = float(np.std(ela_scaled))
        
        results["ela_mean_error"] = ela_mean
        results["ela_max_error"] = ela_max
        results["ela_std_deviation"] = ela_std
        
        # High std deviation = inconsistent compression = likely tampered
        if ela_std > 25:
            results["tampering_likelihood"] = "HIGH"
            results["tampering_reason"] = "High ELA std deviation indicates inconsistent compression regions"
        elif ela_std > 12:
            results["tampering_likelihood"] = "MEDIUM"
            results["tampering_reason"] = "Moderate ELA variation detected"
        else:
            results["tampering_likelihood"] = "LOW"
            results["tampering_reason"] = "Uniform ELA pattern consistent with unmodified image"
        
        # Save ELA visualization
        ela_output = f"/tmp/ela_{Path(filepath).stem}.png"
        Image.fromarray(ela_scaled).save(ela_output)
        results["ela_visualization_path"] = ela_output
        
        # ── Noise Analysis ──
        # Authentic photos have consistent sensor noise patterns
        # Tampered regions often have different noise characteristics
        gray = cv2.imread(filepath, cv2.IMREAD_GRAYSCALE)
        if gray is not None:
            # Apply high-pass filter to isolate noise
            blurred = cv2.GaussianBlur(gray, (5, 5), 0)
            noise = cv2.subtract(gray, blurred)
            noise_std = float(np.std(noise))
            results["noise_std"] = noise_std
            
            # Analyze noise uniformity across image quadrants
            h, w = noise.shape
            quadrants = [
                noise[:h//2, :w//2],   # top-left
                noise[:h//2, w//2:],   # top-right
                noise[h//2:, :w//2],   # bottom-left
                noise[h//2:, w//2:]    # bottom-right
            ]
            quad_stds = [float(np.std(q)) for q in quadrants]
            noise_variance = float(np.var(quad_stds))
            results["noise_uniformity"] = "UNIFORM" if noise_variance < 5 else "NON-UNIFORM"
            results["quadrant_noise"] = quad_stds
        
        # ── Copy-Move Detection ──
        # Detect if parts of image were copy-pasted within itself
        results["copy_move"] = detect_copy_move(filepath)
        
    except Exception as e:
        results["error"] = str(e)
    
    return results

def detect_copy_move(filepath):
    """
    Block-matching algorithm for copy-move forgery detection.
    Divides image into overlapping blocks and finds matching blocks.
    """
    try:
        img = cv2.imread(filepath, cv2.IMREAD_GRAYSCALE)
        if img is None:
            return {"error": "Could not read image"}
        
        # Resize for performance
        img = cv2.resize(img, (256, 256))
        block_size = 16
        blocks = {}
        matches = 0
        
        for y in range(0, img.shape[0] - block_size, 8):
            for x in range(0, img.shape[1] - block_size, 8):
                block = img[y:y+block_size, x:x+block_size]
                # Simple hash of block
                block_hash = hash(block.tobytes())
                if block_hash in blocks:
                    matches += 1
                else:
                    blocks[block_hash] = (x, y)
        
        return {
            "suspicious_matches": matches,
            "copy_move_likely": matches > 10
        }
    except Exception as e:
        return {"error": str(e)}

# ─────────────────────────────────────────
# IMAGE REFORMATION / ENHANCEMENT
# ─────────────────────────────────────────
def enhance_image(filepath, output_dir="/tmp"):
    """
    Forensic image enhancement — recover details from
    degraded, blurry, dark, or damaged evidence images.
    """
    results = {}
    img = Image.open(filepath).convert('RGB')
    img_cv = cv2.imread(filepath)
    stem = Path(filepath).stem
    
    # ── Denoising ──
    # Removes noise while preserving edges (important for text/faces)
    denoised = cv2.fastNlMeansDenoisingColored(img_cv, None, 10, 10, 7, 21)
    denoised_path = f"{output_dir}/{stem}_denoised.png"
    cv2.imwrite(denoised_path, denoised)
    results["denoised"] = denoised_path
    
    # ── Sharpening ──
    # Unsharp mask — standard technique for recovering blurry images
    sharpened = img.filter(ImageFilter.UnsharpMask(radius=2, percent=150, threshold=3))
    sharp_path = f"{output_dir}/{stem}_sharpened.png"
    sharpened.save(sharp_path)
    results["sharpened"] = sharp_path
    
    # ── Brightness/Contrast Enhancement ──
    # Reveal details in dark crime scene photos
    enhancer = ImageEnhance.Contrast(img)
    contrast_img = enhancer.enhance(2.0)
    enhancer2 = ImageEnhance.Brightness(contrast_img)
    bright_img = enhancer2.enhance(1.3)
    enhanced_path = f"{output_dir}/{stem}_enhanced.png"
    bright_img.save(enhanced_path)
    results["brightness_contrast"] = enhanced_path
    
    # ── Super Resolution (EDSR via OpenCV) ──
    try:
        sr = cv2.dnn_superres.DnnSuperResImpl_create()
        # Note: requires EDSR_x4.pb model file
        # sr.readModel("EDSR_x4.pb")
        # sr.setModel("edsr", 4)
        # upscaled = sr.upsample(img_cv)
        # For demo, use simple interpolation upscaling
        h, w = img_cv.shape[:2]
        upscaled = cv2.resize(img_cv, (w*2, h*2), 
                             interpolation=cv2.INTER_CUBIC)
        upscaled_path = f"{output_dir}/{stem}_upscaled.png"
        cv2.imwrite(upscaled_path, upscaled)
        results["upscaled"] = upscaled_path
    except Exception as e:
        results["upscale_error"] = str(e)
    
    # ── Edge Enhancement (for license plates, text) ──
    gray = cv2.cvtColor(img_cv, cv2.COLOR_BGR2GRAY)
    edges = cv2.Canny(gray, 50, 150)
    edge_path = f"{output_dir}/{stem}_edges.png"
    cv2.imwrite(edge_path, edges)
    results["edge_detection"] = edge_path
    
    # ── Histogram Equalization ──
    # Dramatically improves contrast in underexposed images
    yuv = cv2.cvtColor(img_cv, cv2.COLOR_BGR2YUV)
    yuv[:,:,0] = cv2.equalizeHist(yuv[:,:,0])
    equalized = cv2.cvtColor(yuv, cv2.COLOR_YUV2BGR)
    eq_path = f"{output_dir}/{stem}_equalized.png"
    cv2.imwrite(eq_path, equalized)
    results["histogram_equalized"] = eq_path
    
    return results

def analyze_image(filepath):
    """Master function — runs all image analysis"""
    result = {
        "filepath": filepath,
        "filename": Path(filepath).name,
        "analyzed_at": datetime.now().isoformat()
    }
    
    # Basic image properties
    try:
        img = Image.open(filepath)
        result["properties"] = {
            "format": img.format,
            "mode": img.mode,
            "width": img.size[0],
            "height": img.size[1],
            "megapixels": round((img.size[0] * img.size[1]) / 1_000_000, 2)
        }
    except Exception as e:
        result["properties_error"] = str(e)
    
    result["exif"] = extract_exif(filepath)
    result["forensic_exif"] = parse_exif_forensics(result["exif"])
    result["tampering"] = detect_tampering(filepath)
    result["enhancements"] = enhance_image(filepath)
    
    return result