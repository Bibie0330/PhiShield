import re
from detection.link_detection import extract_urls, normalize_domain, match_domain

def detect_phishing_elements(message: str, phishing_keywords: dict):
    """
    Detect phishing markers in message and return:
    - lists of markers
    - explanation list
    - risk_score
    - overall_result
    """
    results = {
        "suspicious_links": [],
        "safe_links": [],
        "shortforms_used": [],
        "urgency_signs": [],
        "emotional_triggers": [],
        "imperative_commands_used": [],
        "suggested_actions": [],
        "explanation": [],
        "risk_score": 0,
        "overall_result": "Safe",
        "result_color": "green"
    }

    msg_lower = message.lower()

    # Extract links and compare with JSON safe/suspicious lists
    links = extract_urls(message)

    safe_domains = phishing_keywords.get("safe_links", [])
    suspicious_domains = phishing_keywords.get("suspected_links", [])

    for link in links:
        domain = normalize_domain(link)

        if match_domain(domain, safe_domains, allow_subdomains=True):
            results["safe_links"].append(link)

        elif match_domain(domain, suspicious_domains, allow_subdomains=False):
            results["suspicious_links"].append(link)

    # Shortforms
    shortforms = phishing_keywords.get("shortforms", {})
    for shortform, full_form in shortforms.items():
        if re.search(r"\b" + re.escape(shortform) + r"\b", msg_lower):
            results["shortforms_used"].append(shortform)
            results["explanation"].append(
                f"Shortform detected: '{shortform}' → '{full_form}'. Often appears in informal phishing messages."
            )

    # Urgency signs
    urgency_signs = phishing_keywords.get("sense_of_urgency", [])
    for u in urgency_signs:
        if u.lower() in msg_lower:
            results["urgency_signs"].append(u)
            results["explanation"].append(f"Urgency phrase detected: '{u}'")

    # Emotional triggers
    emotional_triggers = phishing_keywords.get("emotional_triggers", [])
    for e in emotional_triggers:
        if e.lower() in msg_lower:
            results["emotional_triggers"].append(e)
            results["explanation"].append(f"Emotional trigger detected: '{e}'")

    # Imperative commands
    commands = phishing_keywords.get("imperative_commands", [])
    for c in commands:
        if re.search(r"\b" + re.escape(c.lower()) + r"\b", msg_lower):
            results["imperative_commands_used"].append(c)
            results["explanation"].append(f"Imperative command detected: '{c}' (pushes user to act immediately).")

    # -----------------------
    # Risk scoring (weighted)
    # -----------------------
    score = 0
    score += len(results["urgency_signs"]) * 10
    score += len(results["emotional_triggers"]) * 10
    score += len(results["imperative_commands_used"]) * 15
    score += len(results["suspicious_links"]) * 30

    results["risk_score"] = min(score, 100)

    # Overall classification (context-only)
    if results["risk_score"] >= 70:
        results["overall_result"] = "Phishing"
        results["result_color"] = "red"
        results["suggested_actions"].append("Do NOT click links. Verify with the official source.")
    elif results["risk_score"] >= 35:
        results["overall_result"] = "Suspicious"
        results["result_color"] = "yellow"
        results["suggested_actions"].append("Be cautious. Confirm the message source before acting.")
    else:
        results["overall_result"] = "Safe"
        results["result_color"] = "green"
        results["suggested_actions"].append("No strong phishing indicators detected. Stay alert anyway.")

    return results