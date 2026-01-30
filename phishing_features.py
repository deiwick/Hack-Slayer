import re, math, tldextract
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account", "bank", "upi", "gift", "bonus",
    "free", "win", "password", "otp", "claim", "refund", "unlock", "reset"
]

BRAND_MISUSE = [
    ("paytm", ["paytm-secure", "paytm-help", "paytm-verify"]),
    ("google", ["googl", "g00gle", "goog1e"]),
    ("amazon", ["amaz0n", "amzon", "amaazon"]),
    ("microsoft", ["micros0ft", "m1crosoft"]),
    ("apple", ["appl3", "apple-support"])
]

SUSPICIOUS_TLDS = ["tk", "ga", "ml", "cf", "gq", "xyz", "top", "club", "buzz", "click"]

def shannon_entropy(s: str) -> float:
    if not s:
        return 0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum([p * math.log(p, 2) for p in prob])

def extract_features(url: str):
    parsed = urlparse(url)
    ext = tldextract.extract(url)
    domain = f"{ext.domain}.{ext.suffix}"
    subdomain = ext.subdomain or ""
    path = parsed.path or ""
    query = parsed.query or ""

    return {
        "length": len(url),
        "has_ip": bool(re.match(r"https?://\d{1,3}(\.\d{1,3}){3}", url)),
        "num_dots": url.count("."),
        "has_at": "@" in url,
        "has_dash": "-" in url,
        "keyword_hits": sum(1 for k in SUSPICIOUS_KEYWORDS if k in url.lower()),
        "brand_hits": sum(1 for brand, variants in BRAND_MISUSE for v in variants if v in url.lower()),
        "tld_suspicious": int(ext.suffix in SUSPICIOUS_TLDS),
        "path_len": len(path),
        "query_len": len(query),
        "subdomain_len": len(subdomain.split(".")) if subdomain else 0,
        "entropy": shannon_entropy(url)
    }
