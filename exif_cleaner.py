from PIL import Image
import piexif
import os
import joblib
import pandas as pd

# Load the trained EXIF anomaly detection model using joblib
model = joblib.load("models/exif_model.pkl")

def extract_exif_features(input_path):
    """
    Extracts EXIF metadata features for AI classification.
    """
    try:
        exif_dict = piexif.load(Image.open(input_path).info.get("exif", b""))
    except Exception:
        return {"gps": 0, "timestamp": 0, "device_id": 0}

    gps = 1 if "GPS" in exif_dict and exif_dict["GPS"] else 0
    timestamp = 1 if "0th" in exif_dict and piexif.ImageIFD.DateTime in exif_dict["0th"] else 0
    device_id = 1 if "0th" in exif_dict and piexif.ImageIFD.Make in exif_dict["0th"] else 0

    return {"gps": gps, "timestamp": timestamp, "device_id": device_id}

def ai_classification(input_path):
    """
    Run AI model on extracted EXIF features.
    """
    features = extract_exif_features(input_path)
    df = pd.DataFrame([features])
    prediction = model.predict(df)[0]
    probability = model.predict_proba(df)[0][1]
    return prediction, probability, features

def strip_exif(input_path, output_path=None, threshold=0.7):
    """
    Strips EXIF metadata and runs AI anomaly detection.
    Returns cleaned image path + AI classification result.
    """
    img = Image.open(input_path)
    data = list(img.getdata())
    clean = Image.new(img.mode, img.size)
    clean.putdata(data)

    if not output_path:
        name, ext = os.path.splitext(input_path)
        output_path = f"{name}_clean{ext}"
    clean.save(output_path)

    prediction, prob, features = ai_classification(input_path)
    print(f"[Hackslayer] EXIF anomaly probability: {prob:.2f}")

    if prob > threshold:
        status = "Suspicious metadata"
    else:
        status = "Clean metadata"

    return output_path, {"status": status, "ai_prob": prob, **features}
