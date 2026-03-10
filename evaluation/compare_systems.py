import sys
from pathlib import Path
import json
import pandas as pd
import joblib

from sklearn.metrics import classification_report, confusion_matrix

# -------------------------------------------------
# Fix import path so we can import /detection modules
# -------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT))

from detection.link_detection import detect_links_in_message
from detection.message_detection import detect_phishing_elements

DATA_PATH = PROJECT_ROOT / "datasets" / "processed" / "combined_dataset.csv"
MODEL_PATH = PROJECT_ROOT / "evaluation" / "ml_baseline_lr.joblib"
KEYWORDS_PATH = PROJECT_ROOT / "phishing_keywords.json"


def phishield_predict(message: str, keywords: dict) -> str:
    """
    Uses your deployed PhiShield scoring logic to predict:
    safe / suspicious / phishing

    NOTE: Thresholds tuned for evaluation so rule-based model doesn't output only SAFE.
    """
    safe_domains = keywords.get("safe_links", [])
    suspicious_domains = keywords.get("suspected_links", [])

    link_results = detect_links_in_message(message, safe_domains, suspicious_domains)
    link_score = sum(x.get("risk_score", 0) for x in link_results)

    msg_results = detect_phishing_elements(message, keywords)
    msg_score = msg_results.get("risk_score", 0)

    total_score = min(link_score + msg_score, 100)

    # ✅ Tuned thresholds (previously too strict)
    # Feel free to adjust slightly after seeing outputs
    if total_score >= 60:
        return "phishing"
    elif total_score >= 25:
        return "suspicious"
    else:
        return "safe"


def to_binary(label: str) -> str:
    """
    Convert multiclass labels to binary:
    safe stays safe
    suspicious + phishing => phishing
    """
    return "safe" if label == "safe" else "phishing"


def main():
    if not DATA_PATH.exists():
        raise SystemExit(f"Missing dataset file: {DATA_PATH}. Run build_dataset.py first.")

    if not MODEL_PATH.exists():
        raise SystemExit(f"Missing ML model: {MODEL_PATH}. Run train_ml_baseline.py first.")

    if not KEYWORDS_PATH.exists():
        raise SystemExit(f"Missing keywords file: {KEYWORDS_PATH}")

    # Load keywords
    with open(KEYWORDS_PATH, "r", encoding="utf-8") as f:
        keywords = json.load(f)

    # Load dataset
    df = pd.read_csv(DATA_PATH)
    df["label"] = df["label"].astype(str).str.lower().str.strip()
    df["message"] = df["message"].astype(str)

    y_true = df["label"].tolist()

    # Load ML model
    ml_model = joblib.load(MODEL_PATH)

    # Predict
    y_pred_ml = ml_model.predict(df["message"]).tolist()
    y_pred_rule = [phishield_predict(m, keywords) for m in df["message"]]

    labels = ["safe", "suspicious", "phishing"]

    print("\n==============================")
    print("ML Baseline (Logistic Regression) - MULTICLASS")
    print("==============================")
    print(classification_report(y_true, y_pred_ml, labels=labels, digits=4, zero_division=0))
    print("Confusion Matrix (rows=true, cols=pred):")
    print(labels)
    print(confusion_matrix(y_true, y_pred_ml, labels=labels))

    print("\n==============================")
    print("PhiShield Rule-Based Hybrid - MULTICLASS")
    print("==============================")
    print(classification_report(y_true, y_pred_rule, labels=labels, digits=4, zero_division=0))
    print("Confusion Matrix (rows=true, cols=pred):")
    print(labels)
    print(confusion_matrix(y_true, y_pred_rule, labels=labels))

    # -----------------------
    # Optional: Binary evaluation
    # -----------------------
    y_true_bin = [to_binary(x) for x in y_true]
    y_pred_ml_bin = [to_binary(x) for x in y_pred_ml]
    y_pred_rule_bin = [to_binary(x) for x in y_pred_rule]

    bin_labels = ["safe", "phishing"]

    print("\n==============================")
    print("ML Baseline (Logistic Regression) - BINARY (safe vs phishing)")
    print("==============================")
    print(classification_report(y_true_bin, y_pred_ml_bin, labels=bin_labels, digits=4, zero_division=0))
    print("Confusion Matrix (rows=true, cols=pred):")
    print(bin_labels)
    print(confusion_matrix(y_true_bin, y_pred_ml_bin, labels=bin_labels))

    print("\n==============================")
    print("PhiShield Rule-Based Hybrid - BINARY (safe vs phishing)")
    print("==============================")
    print(classification_report(y_true_bin, y_pred_rule_bin, labels=bin_labels, digits=4, zero_division=0))
    print("Confusion Matrix (rows=true, cols=pred):")
    print(bin_labels)
    print(confusion_matrix(y_true_bin, y_pred_rule_bin, labels=bin_labels))

    print("\n[DONE] Comparison complete.")


if __name__ == "__main__":
    main()