import streamlit as st
import tempfile
import streamlit.components.v1 as components
from email_phish import detect_phishing_email
from malware_static import detect_static_malware
from malware_dynamic import detect_dynamic_malware
from exif_cleaner import strip_exif
from risk import overall_risk
from response import recommend_actions, tamil_alert
from external_tools import (
    check_phishtank,
    check_opensquat,
    check_virustotal,
    check_yara,
    check_exiftool
)

# --- Matrix CSS with updated background and overlay ---
matrix_css = """
<style>
[data-testid="stAppViewContainer"] {
  background-image: url("https://i.postimg.cc/wjm5sKgH/image-2026-01-31-002318296.png");
  background-position: center;
  background-attachment: fixed;
  position: relative;
}

/* Dark overlay for readability */
[data-testid="stAppViewContainer"]::before {
  content: "";
  position: absolute;
  top: 0; left: 0; right: 0; bottom: 0;
  background: rgba(0,0,0,0.75); /* Increased opacity for better contrast */
  z-index: -1;
}

h1, h2, h3, p, .stMarkdown, label {
  color: #00ff00 !important;
  font-weight: bold;
  text-shadow: 0 0 10px #00ff00;
}

.stButton > button {
  background-color: #000;
  color: #00ff00;
  border: 1px solid #00ff00;
  border-radius: 4px;
  padding: 0.6rem 1.2rem;
  font-weight: bold;
  transition: 0.3s;
}
.stButton > button:hover {
  background-color: #00ff00;
  color: black;
  box-shadow: 0 0 10px #00ff00;
}

.stTextInput > div > input, .stTextArea textarea {
  background-color: rgba(0,0,0,0.6);
  color: #00ff00;
  border: 1px solid #00ff00;
  border-radius: 4px;
  padding: 0.5rem;
}
</style>
"""
st.markdown(matrix_css, unsafe_allow_html=True)

# --- Matrix Rain Effect ---
matrix_js = """
<canvas id="matrix"></canvas>
<script>
const canvas = document.getElementById('matrix');
const ctx = canvas.getContext('2d');
canvas.height = window.innerHeight;
canvas.width = window.innerWidth;

const letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
const fontSize = 14;
const columns = canvas.width / fontSize;
const drops = [];
for (let x = 0; x < columns; x++) drops[x] = 1;

function draw() {
  ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = 'rgba(0,255,0,0.7)';
  ctx.font = fontSize + 'px monospace';
  for (let i = 0; i < drops.length; i++) {
    const text = letters.charAt(Math.floor(Math.random() * letters.length));
    ctx.fillText(text, i * fontSize, drops[i] * fontSize);
    if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) drops[i] = 0;
    drops[i]++;
  }
}
setInterval(draw, 33);
</script>
"""
components.html(matrix_js, height=600, width=800)

# --- Header ---
st.title("🛡️ Hackslayer Incident Response — Matrix Edition")
st.subheader("AI + External Tools Unified Cybersecurity Dashboard")
st.markdown("This system combines your trained AI models with external threat intelligence tools for maximum accuracy.")

# Shared scores dictionary for risk aggregation
tool_scores = {}
incident_type = None
severity_result = None

# Tabs for each module
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "📧 Phishing Email",
    "🦠 Malware File",
    "📷 EXIF Cleaner",
    "📊 Risk Aggregator",
    "📣 Response Engine"
])

# 📧 Phishing Detection
with tab1:
    email = st.text_area("Paste suspicious email content")
    url = st.text_input("Suspicious link (optional)")
    if st.button("Analyze Email"):
        verdict = detect_phishing_email(email)
        st.success(f"AI Verdict: {verdict}")
        ai_score = 0.8 if "phish" in verdict.lower() else 0.2
        phishtank_score = check_phishtank(url) if url else 0.2
        opensquat_score = check_opensquat(url) if url else 0.2
        tool_scores["phishing"] = max(ai_score, phishtank_score, opensquat_score)
        incident_type = "phishing"

# 🦠 Malware Detection
with tab2:
    uploaded_file = st.file_uploader("Upload executable file", type=["exe"])
    if uploaded_file:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            tmp.write(uploaded_file.read())
            tmp_path = tmp.name
        st.markdown("#### Static Analysis")
        verdict_static, s_inds = detect_static_malware(tmp_path)
        st.warning(f"AI Static Verdict: {verdict_static}")
        ai_static_score = 0.8 if "malware" in verdict_static.lower() else 0.2
        st.markdown("#### Dynamic Analysis")
        verdict_dynamic, d_inds = detect_dynamic_malware(tmp_path)
        st.warning(f"AI Dynamic Verdict: {verdict_dynamic}")
        ai_dynamic_score = 0.8 if "malware" in verdict_dynamic.lower() else 0.2
        vt_score = check_virustotal(tmp_path, api_key="YOUR_API_KEY")
        yara_score = check_yara(tmp_path, "rules.yar")
        tool_scores["malware_static"] = max(ai_static_score, yara_score, vt_score)
        tool_scores["malware_dynamic"] = ai_dynamic_score
        incident_type = "malware"

# 📷 EXIF Cleaner
with tab3:
    image = st.file_uploader("Upload image", type=["jpg", "jpeg", "png"])
    if image:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".jpg") as tmp:
            tmp.write(image.read())
            tmp_path = tmp.name
        cleaned_path, metadata = strip_exif(tmp_path)
        st.info(f"AI EXIF Verdict: {metadata['status']}")
        st.json(metadata)
        st.success(f"Cleaned image saved at: {cleaned_path}")
        ai_exif_score = 0.8 if "Suspicious" in metadata["status"] else 0.2
        exiftool_score = check_exiftool(tmp_path)
        tool_scores["exif"] = max(ai_exif_score, exiftool_score)
        incident_type = "exif"

# 📊 Risk Aggregator
with tab4:
    if st.button("Aggregate Risk"):
        risk_result = overall_risk(tool_scores)
        severity_result = risk_result["severity"]
        st.metric(label="Unified Severity", value=risk_result["severity"])
        st.metric(label="Confidence", value=f"{risk_result['confidence']:.2f}")
        st.json(risk_result["scores"])
        if risk_result["severity"] in ["High", "Critical"]:
            st.error(f"⚠️ {risk_result['severity']} risk detected")
        elif risk_result["severity"] == "Medium":
            st.warning("⚠️ Moderate risk")
        else:
            st.success("✅ Low risk")

# 📣 Response Engine
with tab5:
    if st.button("Recommend Response"):
        severity = severity_result if severity_result else "Medium"
        itype = incident_type if incident_type else "general"
        actions = recommend_actions(itype, severity)
        alert_msg = tamil_alert(severity)
        st.markdown(f"**Incident Type:** {itype}")
        st.markdown(f"**Severity:** {severity}")
        st.markdown("**Recommended Actions:**")
        for act in actions:
            st.markdown(f"- {act}")
        st.markdown(f"**Tamil Alert:** {alert_msg}")
