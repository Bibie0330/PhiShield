import os
import joblib

MODEL_PATH = "evaluation/ml_model.joblib"
VECT_PATH = "evaluation/ml_vectorizer.joblib"

_model = None
_vectorizer = None


def _load():
    global _model, _vectorizer

    if _model is None or _vectorizer is None:
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(f"ML model not found: {MODEL_PATH}")
        if not os.path.exists(VECT_PATH):
            raise FileNotFoundError(f"Vectorizer not found: {VECT_PATH}")

        _model = joblib.load(MODEL_PATH)
        _vectorizer = joblib.load(VECT_PATH)


def predict_ml(message: str):
    """
    Returns:
      pred_label: 'safe'/'suspicious'/'phishing'
      prob_dict:  dict of class -> probability
      top_prob:   float probability of pred_label
    """
    _load()
    X = _vectorizer.transform([message])

    probs = _model.predict_proba(X)[0]
    classes = list(_model.classes_)

    prob_dict = {classes[i]: float(probs[i]) for i in range(len(classes))}
    pred_label = max(prob_dict, key=prob_dict.get)
    top_prob = prob_dict[pred_label]

    return pred_label, prob_dict, top_prob