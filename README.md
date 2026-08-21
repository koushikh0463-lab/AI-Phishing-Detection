# 🔐 AI-Powered Phishing Detection System

A machine-learning web app that analyzes any URL and predicts whether it's
**Legitimate** or **Phishing** — based purely on the structure of the URL
itself (no page is ever visited). It returns a 0–100% risk score, plain-English
reasons for the verdict, and a small SOC-style dashboard tracking every scan.

**🔗 Live demo:** https://ai-phishing-detection-ntud.onrender.com/
*(free-tier hosting — first load after inactivity can take 20–30 seconds to wake up)*

## Features

- **20-feature URL analysis** — length, HTTPS, IP-address hosts, `@` tricks,
  suspicious keywords, hyphen/subdomain counts, risky TLDs, link shorteners, and more
- **Model comparison** — trains and evaluates Logistic Regression, Random Forest,
  and (optionally) XGBoost, picks the best by F1-score
- **Risk score + explanation** — not just a label, but *why* a URL was flagged
- **Live dashboard** — total scans, phishing detection rate, recent scan history
- **No page fetching** — every check is done offline from the URL text alone, so
  scanning a suspicious link is safe

## Tech stack

`Python` · `Flask` · `scikit-learn` · `pandas` · `HTML/CSS/JS` · deployed on `Render`

## What's actually in this project

```
AI-Phishing-Detection/
├── dataset/
│   └── phishing.csv          <- STARTER dataset (see warning below)
├── model/
│   ├── phishing_model.pkl    <- trained model (created by train.py)
│   ├── feature_names.pkl     <- exact feature order the model expects
│   └── training_summary.json <- accuracy/precision/recall/F1 per model
├── generate_dataset.py       <- builds the starter dataset
├── feature_extraction.py     <- turns a URL string into 20 numeric features
├── train.py                  <- trains + compares Logistic Regression /
│                                 Random Forest / (optional) XGBoost
├── app.py                    <- Flask backend (/, /predict, /dashboard)
├── templates/index.html
├── static/style.css
├── static/script.js
└── requirements.txt
```

## ⚠️ Important — read before you submit this as coursework

1. **The dataset is synthetic, not real.** `generate_dataset.py` builds
   `dataset/phishing.csv` from ~50 real legitimate domains and pattern-based
   fake phishing URLs (IP hosts, brand-lookalike hyphenated domains, `.tk`/`.xyz`
   TLDs, `@` tricks). This lets the whole pipeline run immediately, but it is
   **not a real-world dataset** and the model hasn't seen real phishing traffic.
2. **The 100% accuracy you'll see is inflated**, precisely because the
   synthetic classes are easy to separate. A real project should **not** report
   this number as-is — replace the CSV with a genuine public dataset (same
   `url,label` format) before you evaluate or write up results. Good sources to
   look for: PhishTank feeds, OpenPhish, or curated phishing-URL datasets on
   Kaggle/UCI. Just keep the two-column `url,label` (0=legit, 1=phishing) format
   and everything else (`train.py`, `app.py`) works unchanged.
3. This is a **URL-structure classifier only** — it never fetches the page,
   so it can't catch phishing sites that use a clean-looking, newly registered
   domain. Say this explicitly as a limitation in your report; it's realistic
   and reviewers will respect it more than an unqualified accuracy claim.

## Run it locally

```bash
git clone https://github.com/koushikh0463-lab/AI-Phishing-Detection.git
cd AI-Phishing-Detection
pip install -r requirements.txt
python3 generate_dataset.py   # only needed once, or to regenerate
python3 train.py              # trains models, prints comparison, saves best
python3 app.py                # starts the web app at http://127.0.0.1:5000
```

Open http://127.0.0.1:5000 — paste a URL, hit Analyze. Switch to the
**Dashboard** tab to see aggregate stats for everything scanned this session
(stored in `model/history.json`, capped at the last 200 scans).

## How it works

1. `feature_extraction.py` extracts 20 features purely from the URL text:
   length stats, dot/hyphen/slash/digit counts, HTTPS presence, raw-IP host
   detection, `@` trick detection, subdomain count, suspicious keyword count
   (login, verify, secure, account, …), suspicious TLD flag, link-shortener
   flag, digit-to-letter ratio, and a few more (see `FEATURE_NAMES`).
2. `train.py` builds the feature matrix from the CSV, does an 80/20 stratified
   split, trains Logistic Regression and Random Forest (XGBoost too if
   installed), evaluates each on accuracy/precision/recall/F1 + confusion
   matrix, and saves whichever scores highest on **F1** (better than raw
   accuracy when classes are imbalanced).
3. `app.py` loads the saved model and, for each submitted URL, extracts the
   same features, gets `predict_proba`, converts to a 0–100% risk score, and
   generates rule-based "reasons" (a lightweight stand-in for the SHAP-based
   explainability mentioned as a stretch goal in the original plan).

## Extending it (matches the "Level 2 → Level 4" roadmap)

- **More features**: add favicon/domain-age/WHOIS lookups (needs network calls).
- **XGBoost**: `pip install xgboost` — `train.py` already detects and includes
  it automatically if present.
- **Real explainability**: swap the rule-based `explain_reasons()` for SHAP
  values (`pip install shap`) against the Random Forest/XGBoost model.
- **Persistent database**: swap `model/history.json` for MySQL/MongoDB — the
  `save_history`/`load_history` functions in `app.py` are the only places
  that need to change.
- **Charts**: pipe the `/dashboard` JSON into Chart.js on the dashboard tab.

## Deployment

Deployed on [Render](https://render.com) (free tier) using:

- **Build command:** `pip install -r requirements.txt`
- **Start command:** `gunicorn app:app`

Any push to the `main` branch on GitHub automatically triggers a redeploy.

## License

This project is for educational purposes as part of an MCA coursework
submission. Feel free to fork and extend it.
