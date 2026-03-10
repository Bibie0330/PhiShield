import re
from urllib.parse import urlparse
from datetime import datetime, timezone

# WHOIS is optional (system will still run without it)
try:
    import whois  # python-whois
except Exception:
    whois = None


def extract_urls(text: str):
    """
    Extract URLs / domains from text.
    Supports: https://..., http://..., www..., and bare domains like google.com
    """
    url_pattern = r"(?i)\b((?:https?://|www\.)?[a-z0-9-]+(?:\.[a-z]{2,})+(?:/[^\s]*)?)\b"
    matches = re.findall(url_pattern, text)

    cleaned = []
    for m in matches:
        m = m.rstrip(".,!?);:]\"'")
        cleaned.append(m)

    return cleaned


def normalize_domain(url_or_domain: str) -> str:
    """
    Convert 'google.com', 'www.google.com', 'https://google.com/path' → 'google.com'
    """
    u = url_or_domain.strip()

    if not u.startswith(("http://", "https://")):
        u_for_parse = "http://" + u
    else:
        u_for_parse = u

    parsed = urlparse(u_for_parse)
    domain = parsed.netloc.lower()
    domain = re.sub(r"^www\.", "", domain)
    domain = domain.strip(".")
    return domain


def match_domain(domain: str, patterns: list, allow_subdomains: bool = True) -> bool:
    """
    Match 'mail.google.com' against 'google.com'
    """
    domain = domain.lower().strip(".")
    for p in patterns:
        p = str(p).lower().strip(".")
        if domain == p:
            return True
        if allow_subdomains and domain.endswith("." + p):
            return True
    return False


def _safe_first_date(value):
    """
    WHOIS fields may return datetime, list, or string
    """
    if value is None:
        return None

    if isinstance(value, list) and value:
        return _safe_first_date(value[0])

    if isinstance(value, datetime):
        return value

    try:
        return datetime.fromisoformat(str(value))
    except Exception:
        return None


def whois_lookup(domain: str):
    """
    Safe WHOIS lookup
    """
    if whois is None:
        return {"ok": False, "created": None, "registrar": None, "error": "python-whois not installed"}

    try:
        w = whois.whois(domain)

        created = _safe_first_date(getattr(w, "creation_date", None))
        registrar = getattr(w, "registrar", None)

        return {
            "ok": True,
            "created": created,
            "registrar": registrar,
            "error": None
        }

    except Exception as e:
        return {
            "ok": False,
            "created": None,
            "registrar": None,
            "error": str(e)
        }


def analyze_single_url(url: str, safe_domains: list, suspicious_domains: list,
                      enable_whois: bool = True, young_days: int = 90):

    domain = normalize_domain(url)

    risk_score = 0
    explanations = []
    details = {"whois": None}

    # SAFE DOMAIN CHECK
    if match_domain(domain, safe_domains, allow_subdomains=True):
        return {
            "url": url,
            "domain": domain,
            "Status": "SAFE",
            "risk_score": 0,
            "explanations": [
                f"This website ({domain}) is a commonly used legitimate site.",
                "However, scammers can still send links from real platforms.",
                "Always check the message context before clicking."
            ],
            "details": details
        }

    # SUSPICIOUS DOMAIN LIST
    if match_domain(domain, suspicious_domains, allow_subdomains=False):
        risk_score += 80
        explanations.append(f"Website name '{domain}' appears in known suspicious lists.")

    # Suspicious TLD
    suspicious_tlds = (".xyz", ".top", ".site", ".click", ".ru", ".zip")

    if domain.endswith(suspicious_tlds):
        risk_score += 20
        explanations.append("This website uses an unusual domain ending often seen in scams.")

    # Too many subdomains
    if domain.count(".") >= 4:
        risk_score += 10
        explanations.append("This website name contains many subdomains which may imitate real services.")

    # WHOIS CHECK
    if enable_whois:

        who = whois_lookup(domain)

        details["whois"] = {
            "ok": who["ok"],
            "registrar": who["registrar"],
            "created": who["created"].isoformat() if isinstance(who["created"], datetime) else None,
            "error": who["error"]
        }

        if who["ok"]:

            created = who["created"]

            if created:

                now = datetime.now(timezone.utc)

                if created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)

                age_days = (now - created).days

                details["whois"]["age_days"] = age_days

                if age_days < young_days:
                    risk_score += 25
                    explanations.append(
                        f"Website registration check: domain is newly registered (~{age_days} days old)."
                    )
                else:
                    explanations.append(
                        f"Website registration check: domain age is ~{age_days} days."
                    )

            else:
                explanations.append("Website registration date could not be determined.")

        else:
            explanations.append("Website registration information could not be retrieved.")

    # Clamp score
    risk_score = min(risk_score, 100)

    # Status
    if risk_score >= 70:
        status = "SUSPICIOUS"
    elif risk_score > 0:
        status = "SUSPICIOUS"
    else:
        status = "UNKNOWN"

    if not explanations:
        explanations.append(
            "This website is not in PhiShield’s known lists. It may be safe, but please verify the sender."
        )

    return {
        "url": url,
        "domain": domain,
        "Status": status,
        "risk_score": risk_score,
        "explanations": explanations,
        "details": details
    }


def detect_links_in_message(message: str, safe_domains: list, suspicious_domains: list,
                            enable_whois: bool = True):

    urls = extract_urls(message)
    results = []

    if not urls:
        return [{
            "url": None,
            "domain": None,
            "Status": "NO_LINK",
            "risk_score": 0,
            "explanations": ["No links detected in the message."],
            "details": {"whois": None}
        }]

    for url in urls:
        results.append(
            analyze_single_url(url, safe_domains, suspicious_domains, enable_whois)
        )

    return results