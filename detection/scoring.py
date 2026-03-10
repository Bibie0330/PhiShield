from typing import Dict, Any, List

from detection.link_detection import detect_links_in_message
from detection.message_detection import detect_phishing_elements
from detection.explain import generate_explainable_report, pick_top_reasons
from detection.ml_predict import predict_ml
from detection.teacher_terms import simplify_term



def score_message(message: str, phishing_keywords: dict) -> Dict[str, Any]:
    safe_domains = phishing_keywords.get("safe_links", [])
    suspicious_domains = phishing_keywords.get("suspected_links", [])

    # -----------------------
    # RULE-BASED PART
    # -----------------------
    link_results = detect_links_in_message(message, safe_domains, suspicious_domains)
    link_score_total = sum(x.get("risk_score", 0) for x in link_results)

    phishing_elements = detect_phishing_elements(message, phishing_keywords) or {}

    phishing_elements.setdefault("shortforms_used", [])
    phishing_elements.setdefault("urgency_signs", [])
    phishing_elements.setdefault("emotional_triggers", [])
    phishing_elements.setdefault("imperative_commands_used", [])
    phishing_elements.setdefault("suggested_actions", [])
    phishing_elements.setdefault("explanation", [])
    phishing_elements.setdefault("risk_score", 0)

    message_score = phishing_elements.get("risk_score", 0)
    rule_score = min(link_score_total + message_score, 100)

    # -----------------------
    # ML SECOND OPINION
    # -----------------------
    ml_label, ml_probs, ml_conf = predict_ml(message)
    ml_phish = float(ml_probs.get("phishing", 0))

    # -----------------------
    # HYBRID FINAL SCORE
    # (rule is primary, ML supports)
    # -----------------------
    final_score = int(0.6 * rule_score + 0.4 * (ml_phish * 100))

    # -----------------------
    # FINAL CLASSIFICATION
    # -----------------------
    if final_score >= 70:
        final_result = "Phishing"
        confidence = "High"
        result_color = "red"
        safety_line = "High risk. Treat this message as a scam and do not interact."
    elif final_score >= 35:
        final_result = "Suspicious"
        confidence = "Medium"
        result_color = "yellow"
        safety_line = "Be careful. This message has warning signs. Verify before acting."
    else:
        final_result = "Safe"
        confidence = "Low"
        result_color = "green"
        safety_line = "Low risk. No strong scam patterns detected, but stay alert."

    suspicious_links = [x.get("url") for x in link_results if x.get("Status") == "SUSPICIOUS" and x.get("url")]
    safe_links = [x.get("url") for x in link_results if x.get("Status") == "SAFE" and x.get("url")]

    # -----------------------
    # EXPLANATIONS (teacher-friendly)
    # -----------------------
    combined_explanation: List[str] = []
    combined_explanation.extend(phishing_elements.get("explanation", []))

    for lr in link_results:
        if lr.get("url"):
            for exp in lr.get("explanations", []):
                combined_explanation.append(f"[Link: {lr['url']}] {exp}")

    combined_explanation.append(
        f"[AI Second Opinion] Result: {ml_label} "
        f"(confidence {ml_conf:.2f}). Scam likelihood: {ml_phish:.2f}"
    )

    # simplify technical wording
    combined_explanation = [simplify_term(x) for x in combined_explanation]
    top_reasons = pick_top_reasons(combined_explanation)

    suggested_actions = list(phishing_elements.get("suggested_actions", []))

    explainable = generate_explainable_report(message, {
        "final_result": final_result,
        "total_score": final_score,
        "confidence": confidence,
        "link_results": link_results,
        "phishing_elements": phishing_elements,
        "suspicious_links": suspicious_links,
        "safe_links": safe_links
    })

    # add a small "glossary" for teachers
    glossary = [
        "Website name = the main website part (example: google.com).",
        "AI Second Opinion = the system’s learning-based check from past scam patterns.",
        "Website registration check = checks basic public info about the website (if available)."
    ]

    return {
        "message": message,
        "final_result": final_result,
        "result_color": result_color,
        "confidence": confidence,
        "total_score": final_score,
        "safety_line": safety_line,

        "link_score_total": min(link_score_total, 100),
        "message_score": message_score,
        "rule_score": rule_score,

        "link_results": link_results,
        "phishing_elements": phishing_elements,
        "suspicious_links": suspicious_links,
        "safe_links": safe_links,

        "combined_explanation": combined_explanation,
        "top_reasons": top_reasons,
        "suggested_actions": suggested_actions,

        "ml_label": ml_label,
        "ml_probs": ml_probs,
        "ml_confidence": ml_conf,

        "glossary": glossary,
        "explainable": explainable,
    }