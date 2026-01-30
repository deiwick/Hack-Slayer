def phishing_risk_score(features: dict):
    score = 0.0
    score += 0.15 if features["has_ip"] else 0
    score += 0.10 if features["has_at"] else 0
    score += 0.08 if features["has_dash"] else 0
    score += 0.12 if features["num_dots"] > 3 else 0
    score += 0.18 if features["keyword_hits"] >= 2 else 0
    score += 0.15 if features["brand_hits"] >= 1 else 0
    score += 0.12 if features["tld_suspicious"] else 0
    score += min(features["length"]/3000, 0.1)
    return min(score, 1.0)
