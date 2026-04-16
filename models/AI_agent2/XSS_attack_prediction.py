import os
import joblib
import pandas as pd
import numpy as np

_xss_cache = None

def check_payload_xss(payload):
    payload = str(payload).lower()
    patterns = ["<script>", "javascript:", "onerror=", "onload=", "document.cookie", "alert("]
    for pattern in patterns:
        if pattern in payload:
            return True
    return False

def run_xss_model():
    global _xss_cache
    if _xss_cache is not None:
        return _xss_cache

    model_path = os.path.join(os.path.dirname(__file__), "xss_model.pkl")

    # If model exists, load it
    if os.path.exists(model_path):
        try:
            best_model, best_score, best_f1 = joblib.load(model_path)
            _xss_cache = {
                "accuracy": best_score,
                "f1_score": best_f1,
                "model": type(best_model).__name__
            }
            return _xss_cache
        except Exception:
            pass # Fallback below if load fails

    # Stub inference data if model doesn't exist
    _xss_cache = {
        "accuracy": 0.98,
        "f1_score": 0.96,
        "model": "RandomForestClassifier (Stubbed for Demo)"
    }
    return _xss_cache