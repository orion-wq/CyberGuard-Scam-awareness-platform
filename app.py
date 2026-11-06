from flask import Flask, render_template, request, jsonify
from urllib.parse import urlparse
from pathlib import Path
import joblib
import re
import ipaddress

app = Flask(__name__)

# Load the trained SMS machine-learning model
BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "models" / "sms_classifier.joblib"

ml_model = joblib.load(MODEL_PATH)

print("CyberGuard ML model loaded successfully.")

# Suspicious message patterns and their weights
TEXT_RULES = [
    (r"\burgent\b|\bimmediately\b|\bact now\b",
     15, "Creates artificial urgency"),

    (r"\bverify\s+(your\s+)?(otp|account|identity)\b",
     25, "Requests sensitive verification"),

    (r"\botp\b|\bpin\b|\bpassword\b",
     15, "Mentions sensitive authentication data"),

    (r"\baccount.{0,30}(blocked|suspended|frozen)\b",
     25, "Uses an account-threat tactic"),

    (r"\bwon\b|\bprize\b|\blottery\b|\bfree gift\b",
     15, "Uses a prize or reward lure"),

    (r"\bclaim.{0,25}(prize|reward|gift)\b",
     10, "Encourages claiming an unexpected reward"),

    (r"\bpersonal information\b|\bidentity details\b",
     20, "Requests personal or identity information"),

    (r"\bclick here\b|\bclaim now\b",
     15, "Pressures the user to take action"),

    (r"\bpolice\b|\barrest\b|\bdigital arrest\b",
     25, "Uses an authority or arrest threat"),

    (r"\bbank\b.{0,40}\b(verify|blocked|suspended)\b",
     20, "Uses a banking-related threat"),
]

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd",
    "cutt.ly", "rb.gy", "shorturl.at"
}


def analyze_text(text):
    findings = []
    score = 0
    content = text.lower()

    for pattern, weight, explanation in TEXT_RULES:
        if re.search(pattern, content):
            score += weight
            findings.append({
                "type": "Text pattern",
                "reason": explanation,
                "points": weight
            })

    return score, findings


def analyze_url(url):
    findings = []
    score = 0

    url = url.strip()
    if not url:
        return score, findings

    candidate = url if "://" in url else "https://" + url

    try:
        parsed = urlparse(candidate)
        hostname = parsed.hostname

        if not hostname:
            return 30, [{
                "type": "URL",
                "reason": "Invalid or unrecognized URL structure",
                "points": 30
            }]

        hostname = hostname.lower().rstrip(".")

        if parsed.scheme != "https":
            score += 10
            findings.append({
                "type": "URL",
                "reason": "URL does not use HTTPS",
                "points": 10
            })

        is_ip_address = False

        try:
            ipaddress.ip_address(hostname)
            is_ip_address = True

            score += 30
            findings.append({
                "type": "URL",
                "reason": "Uses an IP address instead of a domain name",
                "points": 30
            })

        except ValueError:
            pass

        if hostname in SHORTENERS:
            score += 20
            findings.append({
                "type": "URL",
                "reason": "Uses a shortened URL that hides its destination",
                "points": 20
            })

        if hostname.count("-") >= 2:
            score += 15
            findings.append({
                "type": "URL",
                "reason": "Contains multiple hyphens in its hostname",
                "points": 15
            })

        if not is_ip_address and len(hostname.split(".")) >= 4:
            score += 10
            findings.append({
                "type": "URL",
                "reason": "Contains an unusually deep subdomain structure",
                "points": 10
            })

        if len(hostname) > 45:
            score += 10
            findings.append({
                "type": "URL",
                "reason": "Hostname is unusually long",
                "points": 10
            })

        if "@" in parsed.netloc:
            score += 25
            findings.append({
                "type": "URL",
                "reason": "Contains an @ symbol in its authority section",
                "points": 25
            })

    except ValueError:
        score += 30
        findings.append({
            "type": "URL",
            "reason": "Malformed URL",
            "points": 30
        })

    return score, findings


def classify_risk(score):
    if score >= 50:
        return "High"
    elif score >= 20:
        return "Medium"
    return "Low"

def combine_assessment(rule_risk, ml_result):
    """
    Conservative hybrid decision layer.

    Rule-based evidence cannot be cancelled by ML.
    ML can raise the risk level but cannot lower it.
    """

    combined_risk = rule_risk

    # Case 1: Strong rule-based evidence
    if rule_risk == "High":
        verdict = "High-risk indicators detected"
        reason = (
            "Strong rule-based warning indicators were detected. "
            "Treat the content as suspicious."
        )

    # Case 2: Medium rule-based evidence
    elif rule_risk == "Medium":
        verdict = "Suspicious indicators detected"
        reason = (
            "The rule engine detected suspicious characteristics. "
            "Verify the sender and destination independently."
        )

    # Case 3: No configured rule-based warnings
    else:
        verdict = "No major threat indicators detected"
        reason = (
            "No major configured warning indicators were detected. "
            "This does not establish that the content is safe."
        )

    # URL-only scans have no ML prediction.
    if ml_result:
        prediction = ml_result["prediction"]
        confidence = ml_result["confidence"]

        # ML predicts smishing
        if prediction == "smishing":

            if confidence >= 90:
                combined_risk = "High"
                verdict = "Strong smishing signal"
                reason = (
                    "The ML model strongly predicts smishing. "
                    "Treat this message as suspicious."
                )

            elif confidence >= 70:
                if combined_risk == "Low":
                    combined_risk = "Medium"

                verdict = "Possible smishing"
                reason = (
                    "The ML model predicts smishing with sufficient "
                    "confidence to warrant independent verification."
                )

            elif combined_risk == "Low":
                verdict = "Uncertain smishing signal"
                reason = (
                    "The model detected some smishing characteristics, "
                    "but its confidence is limited."
                )

        # ML predicts spam
        elif prediction == "spam" and confidence >= 70:

            if combined_risk == "Low":
                combined_risk = "Medium"

            verdict = "Spam-like message"
            reason = (
                "The model predicts spam. Spam is not necessarily "
                "phishing, so verify the sender and context."
            )

        # ML predicts ham
        elif prediction == "ham":

            if combined_risk == "Low":
                verdict = "No strong smishing signal"
                reason = (
                    "The model predicts a legitimate-style message. "
                    "This does not establish that the message is safe."
                )

            else:
                reason = (
                    "The model predicts a legitimate-style message, "
                    "but rule-based warnings remain. Verify independently."
                )

    return {
        "risk": combined_risk,
        "verdict": verdict,
        "reason": reason,
        "rule_risk": rule_risk,
        "ml_prediction": (
            ml_result["prediction"] if ml_result else None
        )
    }

def analyze_with_ml(message):
    if not message:
        return None

    # Predict message category
    prediction = ml_model.predict([message])[0]

    # Get class probabilities
    probabilities = ml_model.predict_proba([message])[0]

    classes = ml_model.classes_

    class_probabilities = {
        label: round(float(probability) * 100, 2)
        for label, probability in zip(classes, probabilities)
    }

    confidence = round(float(max(probabilities)) * 100, 2)

    # ==================================
    # EXPLAINABLE AI: FEATURE CONTRIBUTIONS
    # ==================================

    vectorizer = ml_model.named_steps["tfidf"]
    classifier = ml_model.named_steps["classifier"]

    # Convert message into TF-IDF features
    vector = vectorizer.transform([message])

    # Identify predicted class
    predicted_index = list(classes).index(prediction)

    # Find strongest competing class
    competitor_indices = [
        i for i in range(len(classes))
        if i != predicted_index
    ]

    competitor_index = max(
        competitor_indices,
        key=lambda i: probabilities[i]
    )

    # Compare learned weights between both classes
    weight_difference = (
        classifier.coef_[predicted_index]
        - classifier.coef_[competitor_index]
    )

    # Calculate each feature's contribution
    contributions = (
        vector.multiply(weight_difference).toarray().ravel()
    )

    feature_names = vectorizer.get_feature_names_out()

    # Sort positive and negative contributions
    positive_indices = sorted(
        range(len(contributions)),
        key=lambda i: contributions[i],
        reverse=True
    )

    negative_indices = sorted(
        range(len(contributions)),
        key=lambda i: contributions[i]
    )

    # Keep the strongest meaningful contributions
    supporting_terms = [
        {
            "term": str(feature_names[i]),
            "contribution": round(float(contributions[i]), 4)
        }
        for i in positive_indices
        if contributions[i] > 0.0001
    ][:5]

    opposing_terms = [
        {
            "term": str(feature_names[i]),
            "contribution": round(float(contributions[i]), 4)
        }
        for i in negative_indices
        if contributions[i] < -0.0001
    ][:5]

    explanation = {
        "compared_against": str(classes[competitor_index]),
        "supporting_terms": supporting_terms,
        "opposing_terms": opposing_terms
    }

    return {
        "prediction": str(prediction),
        "confidence": confidence,
        "probabilities": class_probabilities,
        "explanation": explanation
    }

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True) or {}
    message = str(data.get("message", "")).strip()
    url = str(data.get("url", "")).strip()

    if len(message) > 5000 or len(url) > 2048:
        return jsonify({"error": "Input exceeds the allowed length."}), 400

    if not message and not url:
        return jsonify({"error": "Enter a message or URL to analyze."}), 400

    text_score, text_findings = analyze_text(message)
    url_score, url_findings = analyze_url(url)

    # Machine-learning prediction
    ml_result = analyze_with_ml(message)

    findings = text_findings + url_findings

    # Rule-based assessment
    total_score = min(100, text_score + url_score)
    risk = classify_risk(total_score)

    # Combined rule-based + ML decision
    combined_assessment = combine_assessment(risk, ml_result)

    recommendations = {
        "High": "Do not click links, share OTPs, or provide personal information. Verify through official channels.",
        "Medium": "Verify the sender and destination independently before taking action.",
        "Low": "No major configured red flags were detected. This does not prove the content is safe."
    }

    return jsonify({
    "score": total_score,
    "risk": risk,
    "findings": findings,
    "recommendation": recommendations[risk],
    "analysis_type": "Hybrid Rule-Based + Machine Learning",
    "ml_analysis": ml_result,
    "combined_assessment": combined_assessment
})


if __name__ == "__main__":
    app.run(debug=True)