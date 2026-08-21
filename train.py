"""
train.py
--------
Loads dataset/phishing.csv, extracts features for every URL, trains and
compares Logistic Regression, Random Forest, and (if available) XGBoost,
prints an evaluation report for each, and saves the best-performing model
plus the exact feature order to model/phishing_model.pkl and
model/feature_names.pkl
"""

import pandas as pd
import joblib
import json

from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report,
)

from feature_extraction import extract_features, FEATURE_NAMES

try:
    from xgboost import XGBClassifier
    HAS_XGB = True
except ImportError:
    HAS_XGB = False
    print("xgboost not installed -- skipping XGBoost comparison "
          "(pip install xgboost --break-system-packages to enable it)")


def build_feature_matrix(csv_path="dataset/phishing.csv"):
    df = pd.read_csv(csv_path)
    print(f"Loaded {len(df)} rows from {csv_path}")

    feature_rows = [extract_features(u) for u in df["url"]]
    X = pd.DataFrame(feature_rows, columns=FEATURE_NAMES)
    y = df["label"]
    return X, y


def evaluate(name, model, X_test, y_test):
    preds = model.predict(X_test)
    acc = accuracy_score(y_test, preds)
    prec = precision_score(y_test, preds, zero_division=0)
    rec = recall_score(y_test, preds, zero_division=0)
    f1 = f1_score(y_test, preds, zero_division=0)
    cm = confusion_matrix(y_test, preds)

    print(f"\n=== {name} ===")
    print(f"Accuracy : {acc:.4f}")
    print(f"Precision: {prec:.4f}")
    print(f"Recall   : {rec:.4f}")
    print(f"F1-score : {f1:.4f}")
    print("Confusion matrix [ [TN FP] [FN TP] ]:")
    print(cm)
    print(classification_report(y_test, preds, zero_division=0))

    return {"name": name, "accuracy": acc, "precision": prec,
            "recall": rec, "f1": f1, "model": model}


def main():
    X, y = build_feature_matrix()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"Train size: {len(X_train)}  Test size: {len(X_test)}")

    results = []

    # Logistic Regression (baseline)
    lr = LogisticRegression(max_iter=1000)
    lr.fit(X_train, y_train)
    results.append(evaluate("Logistic Regression", lr, X_test, y_test))

    # Random Forest
    rf = RandomForestClassifier(n_estimators=200, random_state=42)
    rf.fit(X_train, y_train)
    results.append(evaluate("Random Forest", rf, X_test, y_test))

    # XGBoost (optional)
    if HAS_XGB:
        xgb = XGBClassifier(
            n_estimators=200, use_label_encoder=False,
            eval_metric="logloss", random_state=42,
        )
        xgb.fit(X_train, y_train)
        results.append(evaluate("XGBoost", xgb, X_test, y_test))

    # Pick best by F1 score (better than raw accuracy for imbalanced classes)
    best = max(results, key=lambda r: r["f1"])
    print(f"\n>>> Best model: {best['name']} (F1={best['f1']:.4f}) <<<")

    joblib.dump(best["model"], "model/phishing_model.pkl")
    joblib.dump(FEATURE_NAMES, "model/feature_names.pkl")

    summary = {
        "best_model": best["name"],
        "comparison": [
            {"model": r["name"], "accuracy": round(r["accuracy"], 4),
             "precision": round(r["precision"], 4),
             "recall": round(r["recall"], 4), "f1": round(r["f1"], 4)}
            for r in results
        ],
    }
    with open("model/training_summary.json", "w") as f:
        json.dump(summary, f, indent=2)

    print("\nSaved model/phishing_model.pkl, model/feature_names.pkl, "
          "model/training_summary.json")


if __name__ == "__main__":
    main()
