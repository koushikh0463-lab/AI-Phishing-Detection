"""
app.py
------
Flask web application for the AI-Powered Phishing Detection System.

Run:
    python3 app.py
Then open http://127.0.0.1:5000 in your browser.
"""

from flask import Flask, render_template, request, jsonify
import joblib
import json
import os
from datetime import datetime

import pandas as pd
from feature_extraction import extract_features, extract_features_dict, explain_reasons, FEATURE_NAMES

app = Flask(__name__)

MODEL_PATH = "model/phishing_model.pkl"
FEATURES_PATH = "model/feature_names.pkl"
HISTORY_PATH = "model/history.json"

model = joblib.load(MODEL_PATH) if os.path.exists(MODEL_PATH) else None
feature_names = joblib.load(FEATURES_PATH) if os.path.exists(FEATURES_PATH) else None


def load_history():
    if os.path.exists(HISTORY_PATH):
        with open(HISTORY_PATH) as f:
            return json.load(f)
    return []


def save_history(history):
    with open(HISTORY_PATH, "w") as f:
        json.dump(history[-200:], f, indent=2)  # keep last 200 scans


def risk_bucket(score):
    if score < 30:
        return "Low Risk"
    elif score < 61:
        return "Medium Risk"
    else:
        return "High Risk"


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/predict", methods=["POST"])
def predict():
    if model is None:
        return jsonify({"error": "Model not found. Run train.py first."}), 500

    data = request.get_json(force=True) if request.is_json else request.form
    url = (data.get("url") or "").strip()

    if not url:
        return jsonify({"error": "Please enter a URL."}), 400

    feats_list = extract_features(url)
    feats_dict = extract_features_dict(url)

    # predict_proba gives [P(legitimate), P(phishing)]
    X = pd.DataFrame([feats_list], columns=FEATURE_NAMES)
    proba = model.predict_proba(X)[0]
    phishing_score = round(float(proba[1]) * 100, 1)
    prediction = "Phishing" if phishing_score >= 50 else "Legitimate"

    reasons = explain_reasons(url, feats_dict)

    result = {
        "url": url,
        "prediction": prediction,
        "risk_score": phishing_score,
        "risk_level": risk_bucket(phishing_score),
        "reasons": reasons,
        "features": feats_dict,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }

    history = load_history()
    history.append(result)
    save_history(history)

    return jsonify(result)


@app.route("/dashboard")
def dashboard():
    history = load_history()
    total = len(history)
    phishing_count = sum(1 for h in history if h["prediction"] == "Phishing")
    legit_count = total - phishing_count
    detection_rate = round((phishing_count / total) * 100, 1) if total else 0.0

    return jsonify({
        "total_scanned": total,
        "phishing_detected": phishing_count,
        "legitimate": legit_count,
        "detection_rate": detection_rate,
        "recent": history[-15:][::-1],
    })


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000, use_reloader=False)
