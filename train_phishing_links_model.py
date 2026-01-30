import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from phishing_features import extract_features

df = pd.read_csv("phishing_links_dataset.csv")
X = pd.DataFrame([extract_features(url) for url in df["url"]])
y = df["label"].map({"phishing": 1, "legitimate": 0})

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

model = RandomForestClassifier(n_estimators=200, max_depth=15, class_weight="balanced")
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
print(classification_report(y_test, y_pred, target_names=["legitimate", "phishing"]))

joblib.dump(model, "models/phishing_link_model.pkl")
print("[Hackslayer] Link model saved as models/phishing_link_model.pkl")
