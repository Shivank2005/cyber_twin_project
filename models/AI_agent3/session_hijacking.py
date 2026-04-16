import os
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score

_session_cache = None

def run_session_model():
    global _session_cache
    if _session_cache is not None:
        return _session_cache

    # 📌 Paths
    base_dir = os.path.dirname(__file__)
    model_path = os.path.join(base_dir, "session_model.pkl")
    data_path = os.path.join(base_dir, "LDAP.csv")

    # ✅ LOAD MODEL IF EXISTS
    if os.path.exists(model_path):
        try:
            model, acc, f1 = joblib.load(model_path)
            _session_cache = {
                "accuracy": acc,
                "f1_score": f1,
                "model": "RandomForest (loaded)"
            }
            return _session_cache
        except Exception:
            pass # fallback below if loading fail

    # ❌ Dataset missing fallback (Mock Stub for demo if LDAP.csv not available)
    if not os.path.exists(data_path):
        _session_cache = {
            "accuracy": 0.82,  # Fake sub-optimal accuracy to trigger a finding
            "f1_score": 0.81,
            "error": "LDAP.csv not found using mock inference",
            "model": "RandomForest (Mock Fallback)"
        }
        return _session_cache

    # 📊 Load dataset
    df = pd.read_csv(data_path, sep='\t')
    df.columns = df.columns.str.strip()

    # Required columns
    required_columns = ['Flow ID', 'Source IP', 'Destination IP', 'Protocol', 'Label']
    for col in required_columns:
        if col not in df.columns:
            return {"error": f"Missing column: {col}"}

    # 🧠 Combine logs
    df['logs'] = df[['Flow ID', 'Source IP', 'Destination IP', 'Protocol']].astype(str).agg(' '.join, axis=1)

    # Label mapping
    df['label'] = df['Label'].apply(lambda x: 1 if x != 'Normal' else 0)

    # 🧠 Feature extraction
    vectorizer = CountVectorizer(max_features=500)
    X = vectorizer.fit_transform(df['logs'])

    y = df['label']

    # Split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

    # Model 
    model = RandomForestClassifier()
    model.fit(X_train, y_train)

    # Predict
    y_pred = model.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)

    # Save model
    joblib.dump((model, acc, f1), model_path)

    _session_cache = {
        "accuracy": acc,
        "f1_score": f1,
        "model": "RandomForest"
    }
    return _session_cache

if __name__ == "__main__":
    result = run_session_model()
    print(result)