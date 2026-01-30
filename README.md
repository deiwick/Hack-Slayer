# 🛡️ Hackslayer — AI-Powered Cybersecurity Dashboard

Hackslayer is a modular cybersecurity platform that integrates **AI-driven detection models** with **external threat intelligence tools** to provide a unified incident response dashboard. Inspired by the Matrix aesthetic, Hackslayer combines phishing detection, malware analysis, metadata cleaning, risk aggregation, and automated response recommendations into one immersive interface.

---

## ✨ Key Features

- **Phishing Email Detection**
  - AI-based classification of suspicious emails
  - External validation via Phishtank and OpenSquat
- **Malware Analysis**
  - Static and dynamic analysis modules
  - VirusTotal and YARA rule integration
- **EXIF Metadata Cleaner**
  - Detects and strips sensitive metadata from images
- **Risk Aggregator**
  - Unified severity scoring across all modules
- **Response Engine**
  - Actionable recommendations in English and Tamil
- **Matrix-Themed UI**
  - Immersive neon interface with animated digital rain

---

## ⚠️ Dataset Requirement

Hackslayer **does not ship with datasets or trained models**.  
Users must **create and provide their own datasets** to train the phishing detection models:

- `phishing_dataset.csv` — Email samples with labels (e.g., `phish` / `legit`)
- `phishing_links_dataset.csv` — Suspicious URLs with labels
- `phishing_model.pkl` — Trained model generated using the above datasets

You can retrain models using:
- `train_model.py`
- `train_phishing_model.py`
- `train_phishing_links_model.py`

This ensures flexibility and allows you to adapt Hackslayer to modern phishing and malware threats.

---

## 🛠️ Installation & Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-username/hackslayer.git
   cd hackslayer
   Create a virtual environment
   
2. **Create a virtual environment**
   ```bash
   python -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate

3. **Install dependencies**
    ```bash
    pip install -r requirements.txt
    
4. **Provide datasets and model files**
Place your datasets and trained model in the project root:

.phishing_dataset.csv

.phishing_links_dataset.csv

.phishing_model.pkl
.(other required datasets)

5. **Run the app**
  ```bash
streamlit run app.py

🌐 External Integrations
Hackslayer connects to external tools for enhanced detection:

Phishtank — phishing URL validation

OpenSquat — domain squatting detection

VirusTotal — malware file scanning

YARA — rule-based malware detection

ExifTool — metadata inspection

⚠️ Note: You must configure API keys where required (e.g., VirusTotal).

📊 Usage Workflow
Phishing Email Tab  
Paste suspicious email content and optional URLs → AI + external tools verdict.

Malware File Tab  
Upload executables → Static + dynamic analysis + VirusTotal/YARA scoring.

EXIF Cleaner Tab  
Upload images → Strip metadata and inspect suspicious fields.

Risk Aggregator Tab  
Aggregate scores → Unified severity and confidence metrics.

Response Engine Tab  
Get recommended actions → Alerts in English and Tamil.

🧠 Contributing
Contributions are welcome!
You can help by:

Expanding datasets

Improving detection logic

Adding new modules (e.g., network traffic analysis)

Enhancing UI/UX

Fork the repo, create a branch, and submit a pull request.

--Thank you!-- <3

   


