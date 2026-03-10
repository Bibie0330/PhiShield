# detection/explain.py
from typing import Dict, Any, List, Tuple

# =============================
# Friendly wording helpers
# =============================
def _risk_sentence(final_result: str) -> str:
    if final_result == "Phishing":
        return "High risk. Treat this message as a scam and do not interact."
    if final_result == "Suspicious":
        return "Be careful. This message has warning signs. Verify before you act."
    return "Low risk. No strong scam patterns detected, but stay alert."

def _dedupe_keep_order(items: List[str]) -> List[str]:
    seen = set()
    out = []
    for x in items:
        x = str(x).strip()
        if not x:
            continue
        if x not in seen:
            out.append(x)
            seen.add(x)
    return out

def _simple_reason_map(reason: str) -> str:
    r = (reason or "").strip()

    # Link-related rewrites
    if r.startswith("[Link:"):
        if "trusted safe list" in r:
            return r.replace(
                "is in the trusted safe list.",
                "is a commonly used trusted website. (But scammers may still use real websites—check what the message asks you to do.)"
            )
        if "known suspicious list" in r:
            return r.replace(
                "is in the known suspicious list.",
                "is known to be risky or frequently used in scams."
            )
        if "WHOIS: Domain is newly registered" in r:
            return r.replace("WHOIS:", "Website check:").replace("commonly used in scams", "sometimes used by scammers")
        if "WHOIS lookup could not be completed" in r:
            return "Website check: We could not confirm the website details right now (lookup/network limit)."
        if "not in PhiShield’s known lists" in r:
            return "Website check: This website is not in PhiShield’s known lists. It may be safe, but verify the sender and purpose."
        return r

    # ML-related rewrites
    if r.startswith("[ML Model]") or r.startswith("[AI Second Opinion]"):
        return r.replace("[ML Model]", "[AI Second Opinion]").replace("Phishing probability", "Scam likelihood")

    return r

def pick_top_reasons(combined_explanation: List[str]) -> List[str]:
    """
    Pick a balanced set of reasons:
    - Up to 3 link reasons
    - Up to 2 wording reasons
    - 1 AI second opinion line (if available)
    """
    if not combined_explanation:
        return ["No strong warning signs were detected."]

    ai_lines = [x for x in combined_explanation if x.startswith("[ML Model]") or x.startswith("[AI Second Opinion]")]
    non_ai = [x for x in combined_explanation if x not in ai_lines]

    link_lines = [x for x in non_ai if x.startswith("[Link:")]
    other_lines = [x for x in non_ai if x not in link_lines]

    picked: List[str] = []
    picked.extend(link_lines[:3])
    picked.extend(other_lines[:2])
    if ai_lines:
        picked.append(ai_lines[0])

    picked = picked[:6]
    return [_simple_reason_map(x) for x in picked]


# =============================
# Scenario detection (ALL)
# =============================
def _scenario_detector(message: str) -> List[Tuple[str, str]]:
    """
    Returns list of (scenario_id, scenario_title) ordered by priority.
    """
    m = (message or "").lower()

    scenarios: List[Tuple[str, str]] = []

    # Bank / finance / wallet
    bank_keys = ["maybank", "cimb", "bank islam", "bank", "tng", "touch n go", "duitnow", "refund", "transaction", "transaksi", "bayaran", "payment", "rm", "tac", "otp", "pin"]
    if any(k in m for k in bank_keys):
        scenarios.append(("bank", "🏦 Bank / Payment / OTP Scam"))

    # Government / KWSP / LHDN / PDRM etc.
    gov_keys = ["kwsp", "epf", "lhdn", "hasil", "sprm", "pdrm", "jpj", "saman", "gov", "kerajaan", "ministry", "kementerian"]
    if any(k in m for k in gov_keys):
        scenarios.append(("gov", "🏛️ Government / KWSP / LHDN / Summons Scam"))

    # School / MOE / teacher context
    school_keys = ["moe", "kpm", "apdm", "sekolah", "guru", "teacher", "pta", "ibubapa", "parent", "yuran", "fee", "kelas", "class", "murid", "student", "pta", "sk", "smk"]
    if any(k in m for k in school_keys):
        scenarios.append(("school", "🏫 School / Parent-Teacher Scam"))

    # Parcel / delivery
    parcel_keys = ["poslaju", "jne", "j&t", "jt", "dhl", "parcel", "delivery", "kurier", "courier", "tracking", "shipment", "ungkapan", "kastam", "custom"]
    if any(k in m for k in parcel_keys):
        scenarios.append(("parcel", "📦 Parcel / Delivery Scam"))

    # Telco / SIM / line
    telco_keys = ["telco", "digi", "maxis", "celcom", "unifi", "tm", "sim", "line", "nombor", "number", "prepaid", "postpaid", "billing"]
    if any(k in m for k in telco_keys):
        scenarios.append(("telco", "📱 Telco / SIM / Billing Scam"))

    # Prize / giveaway
    prize_keys = ["tahniah", "congrats", "won", "menang", "hadiah", "prize", "voucher", "reward", "gift", "lucky draw", "giveaway"]
    if any(k in m for k in prize_keys):
        scenarios.append(("prize", "🎁 Prize / Giveaway Scam"))

    # Job scam
    job_keys = ["part time", "part-time", "kerja", "job", "vacancy", "gaji", "salary", "commission", "like & share", "affiliate", "dropship"]
    if any(k in m for k in job_keys):
        scenarios.append(("job", "💼 Job / Side-Income Scam"))

    # Investment / crypto
    invest_keys = ["investment", "invest", "pelaburan", "crypto", "bitcoin", "forex", "profit", "return", "roi", "modal", "guarantee"]
    if any(k in m for k in invest_keys):
        scenarios.append(("invest", "📈 Investment / Crypto Scam"))

    # Account login / security alert / verification
    account_keys = ["verify", "pengesahan", "sahkan", "account", "akaun", "acc", "login", "password", "security alert", "suspended", "disekat", "blocked", "unusual login", "akses"]
    if any(k in m for k in account_keys):
        scenarios.append(("account", "🔐 Account Verification / Security Alert Scam"))

    # Impersonation / authority style
    impersonation_keys = ["official", "admin", "it department", "helpdesk", "support", "customer service", "cs", "pegawai", "officer"]
    if any(k in m for k in impersonation_keys):
        scenarios.append(("impersonation", "🧑‍💼 Impersonation Scam"))

    # Generic fallback
    if not scenarios:
        scenarios.append(("general", "🧾 General Scam Safety"))

    # Deduplicate while keeping order
    seen = set()
    out = []
    for sid, title in scenarios:
        if sid not in seen:
            out.append((sid, title))
            seen.add(sid)
    return out


# =============================
# Scenario-based actions
# =============================
def _scenario_actions(scenario_id: str) -> List[str]:
    if scenario_id == "bank":
        return [
            "Never share OTP/TAC/PIN/password — banks will not ask via WhatsApp/Telegram/SMS.",
            "Open the official bank app/website by typing it yourself (do not use message links).",
            "If money was transferred or details shared, call the bank hotline immediately.",
            "Change your password and enable 2FA if available."
        ]
    if scenario_id == "gov":
        return [
            "Do not pay fines/tax/fees through links sent by messages.",
            "Check through the official portal by typing the official website yourself.",
            "If it claims a summons or tax issue, verify using official hotline/portal.",
            "Ignore threats like “final warning” until verified."
        ]
    if scenario_id == "school":
        return [
            "Verify with the school office/teacher through the official school contact (not the number in the message).",
            "Be careful with urgent fee/payment requests — confirm via official channels first.",
            "If the sender claims to be a teacher/admin but behaves oddly, pause and verify.",
            "Do not share student info, IC number, or any personal data via chat."
        ]
    if scenario_id == "parcel":
        return [
            "Do not pay “delivery/customs fee” from a link in a message.",
            "Check the tracking using the courier’s official website/app (type it yourself).",
            "Scammers often use fake “address update” pages — avoid entering your card details.",
            "If unsure, contact the courier using their official hotline."
        ]
    if scenario_id == "telco":
        return [
            "Do not click links asking you to “reactivate” your line or “confirm billing.”",
            "Check bills and account status via the telco official app/website.",
            "If your number is at risk, contact telco support from their official site.",
            "Never share TAC/OTP for telco accounts."
        ]
    if scenario_id == "prize":
        return [
            "Ignore random prize/voucher messages — legit prizes usually come from channels you joined.",
            "Do not click claim links or fill personal details to “redeem” a prize.",
            "If it’s from a brand, verify by checking their official page/app first.",
            "Never pay a “processing fee” to claim a prize."
        ]
    if scenario_id == "job":
        return [
            "Be careful with offers promising high salary for simple tasks (like/share).",
            "Do not pay “registration/training fee” or share bank details to get a job.",
            "Check the company name and recruiter identity through official sources.",
            "If they push you to act fast, that’s a strong scam sign."
        ]
    if scenario_id == "invest":
        return [
            "Avoid “guaranteed profit” or “no risk” investment offers — common scam tactic.",
            "Do not send money to personal accounts or unknown platforms.",
            "Verify the company and license before investing.",
            "If you already paid, contact your bank and report the scam."
        ]
    if scenario_id == "account":
        return [
            "Do not click “verify account/login now” links from messages.",
            "Open the official app/website by typing it yourself and check alerts there.",
            "Change your password if you suspect compromise.",
            "Enable 2FA and review recent logins if available."
        ]
    if scenario_id == "impersonation":
        return [
            "Scammers may pretend to be admin, IT, customer service, or an officer.",
            "Verify identity using an official contact method (not the number/link given).",
            "Do not send screenshots of OTP/TAC or personal documents.",
            "If they threaten consequences, pause and verify first."
        ]
    # general
    return [
        "Do not rush — scammers use urgency to make you act without thinking.",
        "Avoid clicking links or downloading files until verified.",
        "Never share OTP/TAC/password or personal information through messages.",
        "If unsure, confirm via official channels (official website/app/hotline)."
    ]


# =============================
# Evidence-based extra actions
# =============================
def _evidence_actions(final_result: str, evidence: Dict[str, Any], message: str) -> List[str]:
    warning_words = evidence.get("warning_words", []) or []
    pushy = evidence.get("pushy_commands", []) or []
    emotion = evidence.get("emotion_tricks", []) or []
    suspicious_links = evidence.get("suspicious_links", []) or []
    trusted_links = evidence.get("trusted_links", []) or []

    msg_lower = (message or "").lower()
    otp_like = any(k in msg_lower for k in ["otp", "tac", "password", "kata laluan", "pin", "kod", "code"])

    out: List[str] = []

    # result-based top rule
    if final_result == "Phishing":
        out.append("🚫 Do NOT click links, download files, or reply to this message.")
    elif final_result == "Suspicious":
        out.append("⚠️ Pause and verify before taking any action.")
    else:
        out.append("✅ Low risk, but still verify if it asks for money/OTP/personal info.")

    if otp_like:
        out.append("If you shared OTP/TAC, contact the official service immediately and change your password.")

    if warning_words or pushy:
        out.append("This message uses pressure/commands — take a moment to verify before acting.")

    if suspicious_links:
        out.append("Treat the link as risky. Check the website name carefully for look-alike spelling.")

    if (not suspicious_links) and trusted_links and final_result in ("Phishing", "Suspicious"):
        out.append("Trusted websites can appear in scams — the danger is usually what the message asks you to do.")

    if not (suspicious_links or trusted_links):
        out.append("No link found. Still be careful if the message requests sensitive information.")

    return _dedupe_keep_order(out)


# =============================
# Main API
# =============================
def generate_explainable_report(message: str, report: Dict[str, Any]) -> Dict[str, Any]:
    final_result = report.get("final_result", "Safe")
    total_score = int(report.get("total_score", 0))
    confidence = report.get("confidence", "Low")

    phishing_elements = report.get("phishing_elements", {}) or {}
    urgency = phishing_elements.get("urgency_signs", []) or []
    commands = phishing_elements.get("imperative_commands_used", []) or []
    emotion = phishing_elements.get("emotional_triggers", []) or []

    suspicious_links = report.get("suspicious_links", []) or []
    safe_links = report.get("safe_links", []) or []

    summary = (
        f"This message is classified as **{final_result}** "
        f"(Risk Score: {total_score}/100, Confidence: {confidence}). "
        "PhiShield checks both message wording and links to detect scam patterns."
    )

    evidence = {
        "warning_words": urgency[:10],
        "pushy_commands": commands[:10],
        "emotion_tricks": emotion[:10],
        "suspicious_links": suspicious_links[:10],
        "trusted_links": safe_links[:10],
    }

    # Scenario detection (ALL)
    scenarios = _scenario_detector(message)
    primary_scenario_id, primary_scenario_title = scenarios[0]

    # Actions = scenario actions + evidence actions (merged & trimmed)
    actions = []
    actions.append(f"Main concern: {primary_scenario_title}")
    actions.extend(_scenario_actions(primary_scenario_id))
    actions.extend(_evidence_actions(final_result, evidence, message))
    actions = _dedupe_keep_order(actions)[:10]

    # Categories (for "More Details")
    categories: List[Dict[str, Any]] = []

    if urgency:
        categories.append({
            "title": "🚨 Pressure / Urgency Words Found",
            "why": "Scammers rush you so you act without checking.",
            "items": urgency[:12]
        })
    if commands:
        categories.append({
            "title": "👉 Strong Commands Found",
            "why": "Scam messages often command: click, verify, pay, or send a code.",
            "items": commands[:12]
        })
    if emotion:
        categories.append({
            "title": "🎭 Emotional Tricks Found",
            "why": "Scammers use fear (“account blocked”) or reward (“prize”) to influence you.",
            "items": emotion[:12]
        })
    if suspicious_links:
        categories.append({
            "title": "🔗 Suspicious Link(s) Found",
            "why": "Unknown or risky links are common in scams. Always check the website name carefully.",
            "items": suspicious_links[:12]
        })
    if safe_links:
        categories.append({
            "title": "✅ Trusted Website(s) Mentioned",
            "why": "Trusted websites can still appear in scam messages—what matters is what the message asks you to do.",
            "items": safe_links[:12]
        })

    if not categories:
        categories.append({
            "title": "✅ No Strong Red Flags Detected",
            "why": "PhiShield did not find strong scam patterns in words or links.",
            "items": [
                "If the message asks for OTP, money, or personal info—verify through official channels first."
            ]
        })

    return {
        "summary": summary,
        "risk_sentence": _risk_sentence(final_result),
        "actions": actions,
        "evidence": evidence,
        "categories": categories,
        "primary_scenario": {"id": primary_scenario_id, "title": primary_scenario_title},
        "all_scenarios": [{"id": sid, "title": title} for sid, title in scenarios]
    }


__all__ = ["generate_explainable_report", "pick_top_reasons"]