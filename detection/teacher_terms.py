# detection/teacher_terms.py

def simplify_term(text: str) -> str:
    """
    Replace technical words with teacher-friendly terms.
    """
    replacements = {
        "domain": "website name",
        "whois": "website registration check",
        "ml": "AI second opinion",
        "model": "AI checker",
        "vectorizer": "AI text reader",
        "probability": "scam likelihood",
        "confidence": "confidence level",
        "tld": "website ending (e.g., .com, .xyz)",
        "subdomain": "extra website part",
    }

    out = text
    for k, v in replacements.items():
        out = out.replace(k, v)
        out = out.replace(k.upper(), v)
        out = out.replace(k.capitalize(), v)

    return out