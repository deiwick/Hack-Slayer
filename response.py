import joblib
import pandas as pd
from risk import severity_from_score

# This model is trained on a dataset mapping incident_type + severity → recommended actions
model = joblib.load("models/response_model.pkl")

def recommend_actions(incident_type, severity, threshold: float = 0.6):
    """
    Recommend response actions using AI model + fallback rules.
    incident_type: str ("phishing", "malware", etc.)
    severity: str ("Low", "Medium", "High", "Critical")
    """
    # Prepare features for AI model
    df = pd.DataFrame([{
        "incident_type": 1 if incident_type == "phishing" else 2 if incident_type == "malware" else 0,
        "severity_level": {"Low":1, "Medium":2, "High":3, "Critical":4}.get(severity, 0)
    }])

    # AI prediction
    prediction = model.predict(df)[0]
    prob = model.predict_proba(df)[0].max()

    if prob >= threshold:
        # AI returns a label that maps to a set of actions
        if prediction == 1:  # phishing high risk
            return ["Block URL/domain", "Notify user", "Quarantine email", "Add to blacklist"]
        elif prediction == 2:  # phishing low/medium
            return ["Warn user", "Mark for review"]
        elif prediction == 3:  # malware high risk
            return ["Isolate host (simulated)", "Quarantine file", "Run full scan", "Notify admin"]
        elif prediction == 4:  # malware low/medium
            return ["Quarantine file", "Schedule scan", "Mark for review"]
        else:
            return ["Log incident", "Manual review"]
    else:
        # Fallback to rule-based actions if AI confidence is low
        actions = []
        if incident_type == "phishing":
            if severity in ["High", "Critical"]:
                actions += ["Block URL/domain", "Notify user", "Quarantine email", "Add to blacklist"]
            else:
                actions += ["Warn user", "Mark for review"]
        elif incident_type == "malware":
            if severity in ["High", "Critical"]:
                actions += ["Isolate host (simulated)", "Quarantine file", "Run full scan", "Notify admin"]
            else:
                actions += ["Quarantine file", "Schedule scan", "Mark for review"]
        return actions

def tamil_alert(severity):
    """
    Tamil language alert messages for severity levels.
    """
    mapping = {
        "Critical": "அவசரம்! மிகுந்த அபாயம்.",
        "High": "எச்சரிக்கை! உயர் அபாயம்.",
        "Medium": "கவனம்! நடுத்தர அபாயம்.",
        "Low": "சரி. குறைந்த அபாயம்."
    }
    return mapping.get(severity, "தகவல்.")
