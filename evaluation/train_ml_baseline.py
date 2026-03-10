import os
import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix


DATA_PATH = "datasets/processed/combined_dataset.csv"
MODEL_OUT = "evaluation/ml_model.joblib"
VECT_OUT = "evaluation/ml_vectorizer.joblib"


def main():
    if not os.path.exists(DATA_PATH):
        raise FileNotFoundError(f"Dataset not found: {DATA_PATH}")

    df = pd.read_csv(DATA_PATH)

    # Must have these columns:
    # label, message
    if "label" not in df.columns or "message" not in df.columns:
        raise ValueError("combined_dataset.csv must contain columns: label, message")

    df = df.dropna(subset=["label", "message"])
    df["message"] = df["message"].astype(str)

    X = df["message"]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    vectorizer = TfidfVectorizer(
        lowercase=True,
        stop_words=None,
        ngram_range=(1, 2),
        min_df=2,
        max_features=30000
    )

    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    model = LogisticRegression(
        max_iter=300,
        class_weight="balanced",
        n_jobs=None
    )

    model.fit(X_train_vec, y_train)

    preds = model.predict(X_test_vec)

    print("\n==============================")
    print("ML Baseline (Logistic Regression) - MULTICLASS")
    print("==============================")
    print(classification_report(y_test, preds, digits=4))
    print("Confusion Matrix (rows=true, cols=pred):")
    labels_sorted = sorted(df["label"].unique())
    print(labels_sorted)
    print(confusion_matrix(y_test, preds, labels=labels_sorted))

    # Save model + vectorizer
    joblib.dump(model, MODEL_OUT)
    joblib.dump(vectorizer, VECT_OUT)
    print(f"\n[SAVED] Model -> {MODEL_OUT}")
    print(f"[SAVED] Vectorizer -> {VECT_OUT}")


if __name__ == "__main__":
    main()