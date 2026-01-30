import joblib
import pandas as pd

# Load the trained risk aggregation model using joblib
model = joblib.load("models/risk_model.pkl")

def severity_from_score(score: float):
    """
    Fallback rule-based severity classification.
    """
    if score >= 0.8:
        return "Critical"
    if score >= 0.6:
        return "High"
    if score >= 0.4:
        return "Medium"
    return "Low"

def ai_severity(tool_scores: dict, threshold: float = 0.6):
    """
    AI-based severity classification using multiple tool scores.
    tool_scores: dict with keys like {"phishing":0.7, "malware_static":0.8, "malware_dynamic":0.5}
    """
    # Convert dict into feature vector
    df = pd.DataFrame([{
        "phishing": tool_scores.get("phishing", 0),
        "malware_static": tool_scores.get("malware_static", 0),
        "malware_dynamic": tool_scores.get("malware_dynamic", 0),
        "exif": tool_scores.get("exif", 0)
    }])

    prediction = model.predict(df)[0]
    prob = model.predict_proba(df)[0].max()

    if prob >= threshold:
        mapping = {0: "Low", 1: "Medium", 2: "High", 3: "Critical"}
        return mapping.get(prediction, "Low"), prob
    else:
        avg_score = sum(tool_scores.values()) / len(tool_scores) if tool_scores else 0
        return severity_from_score(avg_score), prob

def overall_risk(tool_scores: dict):
    """
    Unified risk assessment: returns severity + probability + raw scores.
    """
    severity, prob = ai_severity(tool_scores)
    return {
        "severity": severity,
        "confidence": prob,
        "scores": tool_scores
    }
