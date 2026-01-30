import pandas as pd
import joblib
from collections import Counter
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

def train_and_save_model(dataset_path, feature_cols, label_col, model_path, n_estimators=200):
    print(f"\n[Hackslayer] Training model for {model_path}...")
    df = pd.read_csv(dataset_path)

    X = df[feature_cols]
    y = df[label_col]

    counts = Counter(y)
    min_class_size = min(counts.values())

    test_size = 0.2
    stratify_opt = y if min_class_size >= 2 else None

    if len(df) < 10 or min_class_size < 2:
        test_size = 0.5
        stratify_opt = None
        print("[Hackslayer] Small dataset detected → using test_size=0.5 and no stratification.")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=42, stratify=stratify_opt
    )

    model = RandomForestClassifier(
        n_estimators=n_estimators, random_state=42, class_weight="balanced"
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print("Accuracy:", accuracy_score(y_test, y_pred))
    print(classification_report(y_test, y_pred, zero_division=0))

    joblib.dump(model, model_path)
    print(f"Model saved to {model_path}\n")

train_and_save_model(
    dataset_path="datasets/phishing_dataset.csv",
    feature_cols=["length","num_dots","keyword_hits","brand_hits","has_ip","has_at","has_dash",
                  "tld_suspicious","path_len","query_len","subdomain_len","entropy_flag","recent_domain"],
    label_col="label",
    model_path="models/phishing_model.pkl"
)

train_and_save_model(
    dataset_path="datasets/malware_static_dataset.csv",
    feature_cols=["net_hits","suspicious_imports","packed","entropy"],
    label_col="label",
    model_path="models/malware_static_model.pkl"
)

train_and_save_model(
    dataset_path="datasets/malware_dynamic_dataset.csv",
    feature_cols=["file_ops","reg_ops","net_ops","proc_injections"],
    label_col="label",
    model_path="models/malware_dynamic_model.pkl"
)

train_and_save_model(
    dataset_path="datasets/exif_dataset.csv",
    feature_cols=["gps","timestamp","device_id"],
    label_col="label",
    model_path="models/exif_model.pkl"
)

train_and_save_model(
    dataset_path="datasets/risk_dataset.csv",
    feature_cols=["phishing","malware_static","malware_dynamic","exif"],
    label_col="label",
    model_path="models/risk_model.pkl"
)

print("\n[Hackslayer] Training Response Recommendation model...")
df = pd.read_csv("datasets/response_dataset.csv")

incident_map = {"phishing": 1, "malware": 2}
severity_map = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}

df["incident_type"] = df["incident_type"].map(incident_map)
df["severity_level"] = df["severity_level"].map(severity_map)

X = df[["incident_type", "severity_level"]]
y = df["label"]

counts = Counter(y)
min_class_size = min(counts.values())
test_size = 0.2
stratify_opt = y if min_class_size >= 2 else None

if len(df) < 10 or min_class_size < 2:
    test_size = 0.5
    stratify_opt = None
    print("[Hackslayer] Small dataset detected → using test_size=0.5 and no stratification.")

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=test_size, random_state=42, stratify=stratify_opt
)

model = RandomForestClassifier(n_estimators=200, random_state=42, class_weight="balanced")
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
print("Accuracy:", accuracy_score(y_test, y_pred))
print(classification_report(y_test, y_pred, zero_division=0))

joblib.dump(model, "models/response_model.pkl")
print("Model saved to models/response_model.pkl\n")
