import re
import joblib
import pandas as pd
import math

PHRASES = [
    r"urgent (?:action|required|attention)",
    r"account (?:suspended|locked|restricted)",
    r"verify (?:identity|account|details)",
    r"confirm (?:password|login|credentials)",
    r"click here",
    r"update (?:information|details|account)",
    r"security alert",
    r"unauthorized login attempt"
]

BRANDS = ["paypal","amazon","bank","microsoft","visa","apple","google","outlook","netflix","dropbox"]

SUSPICIOUS_TLDS = [".ru",".cn",".tk",".ml",".ga",".cf",".top",".xyz",".club"]

def shannon_entropy(s: str) -> float:
    if not s:
        return 0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum([p * math.log(p, 2) for p in prob])

def extract_features(text: str):
    t = text.lower()
    return {
        "length": len(t),
        "num_dots": t.count("."),
        "keyword_hits": sum(1 for p in PHRASES if re.search(p, t)),
        "brand_hits": sum(1 for b in BRANDS if b in t),
        "has_ip": int(re.search(r"\d+\.\d+\.\d+\.\d+", t) is not None),
        "has_punycode": int("xn--" in t),
        "has_at": int("@" in t),
        "has_dash": int("-" in t),
        "tld_suspicious": int(any(t.endswith(ext) for ext in SUSPICIOUS_TLDS)),
        "path_len": len(re.findall(r"/", t)),
        "query_params": len(re.findall(r"=.+", t)),
        "subdomain_len": len(t.split(".")) - 2 if "." in t else 0,
        "entropy": shannon_entropy(t),
    }

# Load the retrained model
model = joblib.load("models/phishing_model.pkl")

def email_phish_score(text: str):
    features = extract_features(text)
    df = pd.DataFrame([features])
    prediction = model.predict_proba(df)[0][1]  # probability of phishing
    return prediction

def detect_phishing_email(text: str, threshold: float = 0.7):
    score = email_phish_score(text)
    print(f"[Hackslayer] Phishing probability: {score:.2f}")
    return "Phishing suspected" if score > threshold else "Safe"
