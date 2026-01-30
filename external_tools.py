import requests
import subprocess
import tempfile
import os


def check_phishtank(url: str) -> float:
    resp = requests.get(f"https://checkurl.phishtank.com/checkurl/?url={url}")
    if "phish" in resp.text.lower():
        return 0.8
    return 0.2

def check_opensquat(domain: str) -> float:
    try:
        result = subprocess.run(["opensquat", "-d", domain], capture_output=True, text=True)
        if "suspicious" in result.stdout.lower():
            return 0.8
    except Exception:
        pass
    return 0.2


def check_virustotal(file_path: str, api_key: str) -> float:
    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": api_key}
    with open(file_path, "rb") as f:
        resp = requests.post(url, headers=headers, files={"file": f})
    if resp.status_code == 200:
        data = resp.json()
        positives = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
        total = sum(data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).values())
        ratio = positives / total if total else 0
        return 0.8 if ratio > 0.3 else 0.2
    return 0.2

def check_yara(file_path: str, rules_path: str) -> float:
    try:
        result = subprocess.run(["yara", rules_path, file_path], capture_output=True, text=True)
        if result.stdout.strip():
            return 0.8
    except Exception:
        pass
    return 0.2


def check_exiftool(image_path: str) -> float:
    try:
        result = subprocess.run(["exiftool", image_path], capture_output=True, text=True)
        if "GPS" in result.stdout or "Camera" in result.stdout:
            return 0.8
    except Exception:
        pass
    return 0.2
