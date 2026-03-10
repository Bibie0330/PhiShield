import pandas as pd
from pathlib import Path

RAW_DIR = Path("datasets/raw")
OUT_DIR = Path("datasets/processed")
OUT_DIR.mkdir(parents=True, exist_ok=True)

def normalize_labels(df: pd.DataFrame, source: str) -> pd.DataFrame:
    df = df.copy()

    # Ensure the required columns exist
    if "label" not in df.columns or "message" not in df.columns:
        raise ValueError(f"[ERROR] Dataset '{source}' must contain 'label' and 'message' columns.")

    # Normalize labels depending on dataset source
    if source == "sms_spam":
        df["label"] = df["label"].astype(str).str.lower().str.strip()
        df["label"] = df["label"].replace({"ham": "safe", "spam": "phishing"})
    elif source in ("malay", "phishield_custom"):
        df["label"] = df["label"].astype(str).str.lower().str.strip()

    # Clean messages
    df["message"] = df["message"].astype(str).str.strip()

    # Keep only expected labels
    df = df[df["label"].isin(["safe", "suspicious", "phishing"])]

    return df[["label", "message"]]

def main():
    combined = []

    # -------------------------
    # 1) English SMS spam dataset
    # -------------------------
    sms_path = RAW_DIR / "sms_spam.csv"
    if sms_path.exists():
        sms = pd.read_csv(sms_path, encoding="ISO-8859-1")

        # Your file seems to be: label,message,...
        # But some datasets use Label/Message. We support both.
        if "Label" in sms.columns and "Message" in sms.columns:
            sms = sms.rename(columns={"Label": "label", "Message": "message"})
        elif "label" not in sms.columns or "message" not in sms.columns:
            # fallback: try first 2 columns
            sms = sms.iloc[:, :2]
            sms.columns = ["label", "message"]

        sms = normalize_labels(sms, "sms_spam")
        combined.append(sms)
        print(f"[OK] English dataset loaded: {len(sms)} rows")
    else:
        print("[WARN] datasets/raw/sms_spam.csv not found")

    # -------------------------
    # 2) Malay phishing dataset
    # -------------------------
    malay_path = RAW_DIR / "malay_phishing.csv"
    if malay_path.exists():
        malay = pd.read_csv(malay_path)

        # Ensure correct columns (if needed)
        if "Label" in malay.columns and "Message" in malay.columns:
            malay = malay.rename(columns={"Label": "label", "Message": "message"})

        malay = normalize_labels(malay, "malay")
        combined.append(malay)
        print(f"[OK] Malay dataset loaded: {len(malay)} rows")
    else:
        print("[WARN] datasets/raw/malay_phishing.csv not found")

    # -------------------------
    # 3) PhiShield custom phishing dataset (NEW)
    # -------------------------
    custom_path = RAW_DIR / "phishield_phishing_messages_50.csv"
    if custom_path.exists():
        custom = pd.read_csv(custom_path, encoding="utf-8")

        # In case the file uses different headers
        if "Label" in custom.columns and "Message" in custom.columns:
            custom = custom.rename(columns={"Label": "label", "Message": "message"})

        custom = normalize_labels(custom, "phishield_custom")
        combined.append(custom)
        print(f"[OK] PhiShield custom dataset loaded: {len(custom)} rows")
    else:
        print("[WARN] datasets/raw/phishield_phishing_messages_50.csv not found (optional)")

    # -------------------------
    # Merge + Save
    # -------------------------
    if not combined:
        raise SystemExit("No datasets found. Add CSVs into datasets/raw/ first.")

    df = pd.concat(combined, ignore_index=True)

    # Remove exact duplicates
    df = df.drop_duplicates(subset=["label", "message"])

    # Shuffle (optional but good for training)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    out_path = OUT_DIR / "combined_dataset.csv"
    df.to_csv(out_path, index=False, encoding="utf-8")

    print(f"[DONE] Saved: {out_path} ({len(df)} rows)")
    print(df["label"].value_counts())

if __name__ == "__main__":
    main()