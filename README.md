# CyberGuard — Phishing & Scam Risk Checker

A hybrid phishing and scam detection demo that analyzes suspicious messages and URLs using machine learning and rule-based security checks.

## Overview

CyberGuard combines two detection approaches:

1. **Machine Learning:** A TF-IDF + Logistic Regression classifier categorizes SMS messages into Ham, Spam, or Smishing.
2. **Rule-Based Analysis:** Heuristic checks inspect message patterns and URL structures for suspicious indicators.

The application combines these signals to provide a risk assessment, supporting evidence, and a safety recommendation.

## Features

- SMS classification into Ham, Spam, and Smishing.
- URL structure analysis.
- Detection of suspicious language patterns.
- Hybrid risk assessment.
- Class probability distribution.
- Explainable AI feature contributions.
- Interactive web interface.
- REST API for scanning.
- Automated backend tests.

## Technology Stack

| Component | Technology |
|---|---|
| Backend | Python, Flask |
| Machine Learning | Scikit-learn |
| Text representation | TF-IDF |
| Classifier | Logistic Regression |
| Data processing | Pandas, NumPy |
| Model serialization | Joblib |
| Frontend | HTML, CSS, JavaScript |
| Testing | Python unittest |

## System Architecture

```text
             User Input
          (SMS / URL)
                 |
                 v
          Flask REST API
                 |
          +------+------+
          |             |
          v             v
     Text Analysis   URL Analysis
          |             |
          v             v
     ML Classifier   URL Heuristics
          |             |
          +------+------+
                 |
                 v
       Combined Assessment
                 |
          +------+------+
          |             |
          v             v
     Risk Verdict   Explanations
          |             |
          +------+------+
                 |
                 v
           Web Interface
```

## Machine Learning Approach

The SMS classifier uses:

- **TF-IDF:** Converts text into numerical features.
- **Unigrams and bigrams:** Captures individual words and two-word combinations.
- **Logistic Regression:** Predicts one of three message categories:
  - `ham` — legitimate-style message
  - `spam` — spam message
  - `smishing` — SMS phishing message

The trained model is stored at:

```text
models/sms_classifier.joblib
```

Training script:

```text
train_model.py
```

Training dataset:

[SMS Phishing Dataset for Machine Learning and Pattern Recognition](https://data.mendeley.com/datasets/f45bkkt8pr/1)

## Explainable AI

CyberGuard uses the trained Logistic Regression model's feature weights to show which message terms support or oppose its predicted class.

This helps users inspect the model's reasoning rather than seeing only a predicted label.

These contributions explain the model's learned feature associations. They do not establish malicious intent or causation.

## Rule-Based URL Analysis

The URL analyzer checks structural indicators such as:

- Non-HTTPS URLs.
- IP addresses used as hostnames.
- Known URL shorteners.
- Multiple hyphens in hostnames.
- Deep subdomain structures.
- Unusually long hostnames.
- Deceptive `@` symbols in URL authority sections.

**Important:** The URL analyzer performs structural checks. It does not visit URLs, verify domain ownership, or query live threat-intelligence databases.

## Risk Assessment

The rule-based score is capped at 100.

| Score | Risk |
|---|---|
| 0–19 | Low |
| 20–49 | Medium |
| 50–100 | High |

The machine-learning prediction is considered separately by the combined assessment layer. A legitimate-style ML prediction cannot cancel strong rule-based warnings.

The model's class confidence is not a calibrated probability that a message is fraudulent.

## Project Structure

CyberGuard/
├── app.py
├── train_model.py
├── requirements.txt
├── models/
│   └── sms_classifier.joblib
├── data/                 # Local dataset, excluded from Git
├── templates/
│   ├── index.html
│   └── awareness.html
├── static/
│   ├── css/
│   │   └── style.css
│   ├── js/
│   │   └── app.js
│   └── images/
└── tests/
    └── test_app.py

## Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/bountyhunteranup/CyberGuard.git
cd cyberguard
```

### 2. Create a virtual environment

```bash
python -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the application

```bash
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

### 5. Run automated tests

```bash
python -m unittest discover -s tests -v
```

## API Usage

**Endpoint**

```text
POST /api/scan
```

**Example request**

```json
{
  "message": "URGENT! Your bank account is suspended. Verify your OTP immediately.",
  "url": "http://192.168.1.100/login"
}
```

**Example response fields**

- `score`
- `risk`
- `findings`
- `recommendation`
- `ml_analysis`
- `combined_assessment`

## Testing Status

The current backend test suite contains seven automated tests covering:

- Empty request rejection.
- Safe structural URL handling.
- Suspicious IP-based URL detection.
- Strong phishing message detection.
- Legitimate-style message combined with a suspicious URL.
- Input length restrictions.
- Deceptive URLs containing an `@` symbol.

All seven tests have passed in the current development environment.

## Model Evaluation

The classifier was evaluated using an 80/20 stratified train-test split.

### Dataset statistics

| Metric | Value |
|---|---:|
| Original usable messages | 5,971 |
| Conflicting message groups removed | 34 |
| Cleaned messages | 5,797 |
| Training samples | 4,637 |
| Testing samples | 1,160 |

### Test-set results

| Class | Precision | Recall | F1-score | Support |
|---|---:|---:|---:|---:|
| Ham | 0.98 | 0.99 | 0.99 | 967 |
| Spam | 0.83 | 0.77 | 0.80 | 87 |
| Smishing | 0.94 | 0.88 | 0.91 | 106 |
| Macro average | 0.92 | 0.88 | 0.90 | 1,160 |
| Weighted average | 0.96 | 0.97 | 0.96 | 1,160 |

**Overall accuracy: 96.55%**

### Confusion Matrix

Rows represent actual classes; columns represent predicted classes.

Class order: ham, spam, smishing.

| Actual / Predicted | Ham | Spam | Smishing |
|---|---:|---:|---:|
| Ham | 960 | 6 | 1 |
| Spam | 15 | 67 | 5 |
| Smishing | 5 | 8 | 93 |

The classifier correctly identified 93 of 106 smishing messages,
achieving approximately 88% recall for smishing.

The dataset is imbalanced, with ham messages substantially
outnumbering spam and smishing messages. Accuracy alone is
therefore insufficient to describe model performance.

These results represent one held-out split and do not guarantee
equivalent performance on unseen real-world messages.

## Limitations

- The model is trained on a specific SMS dataset and may not generalize to every language, region, or scam technique.
- URL analysis is structural, not live reputation analysis.
- The rule-based score is a heuristic, not a fraud probability.
- Machine-learning confidence is not a verified probability of fraud.
- A Low-risk result does not guarantee safety.
- The current system is a demonstration and should not be used as the sole basis for real-world security decisions.

## Future Improvements

- Integrate live URL reputation services.
- Add phishing email classification.
- Evaluate multilingual scam detection.
- Improve model generalization using more diverse datasets.
- Add model calibration and threshold analysis.
- Expand adversarial and edge-case testing.
- Add an analysis history and reporting dashboard.

## Disclaimer

CyberGuard is an educational cybersecurity project developed for demonstration and research purposes. Always verify suspicious messages through official channels. Never share OTPs, passwords, or sensitive personal information based solely on a message or link.