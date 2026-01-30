import re
import math
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
-

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


df = pd.read_csv("phishing_dataset.csv")

features = df["text_snippet"].apply(extract_features)
X = pd.DataFrame(list(features))
y = df["label"].map({"phishing":1, "legitimate":0})


X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)


model = RandomForestClassifier(
    n_estimators=200,
    max_depth=15,
    random_state=42,
    class_weight="balanced"
)

model.fit(X_train, y_train)


y_pred = model.predict(X_test)
print(classification_report(y_test, y_pred, target_names=["legitimate","phishing"]))


joblib.dump(model, "models/phishing_model.pkl")
print("[Hackslayer] Model retrained and saved as models/phishing_model.pkl")


def email_phish_score(text: str):
    features = extract_features(text)
    df = pd.DataFrame([features])
    prediction = model.predict_proba(df)[0][1]  # probability of phishing
    return prediction

def detect_phishing_email(text: str, threshold: float = 0.7):
    score = email_phish_score(text)
    print(f"[Hackslayer] Phishing probability: {score:.2f}")
    return "Phishing suspected" if score > threshold else "Safe"


sample_text = "Urgent action required: verify your PayPal account immediately"
print(detect_phishing_email(sample_text))
