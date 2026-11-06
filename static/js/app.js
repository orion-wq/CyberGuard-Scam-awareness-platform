const form = document.getElementById("scanForm");
const messageInput = document.getElementById("message");
const urlInput = document.getElementById("url");
const scanButton = document.getElementById("scanButton");
const results = document.getElementById("results");

const examples = {
    phishing: {
        message: "URGENT! Your bank account has been suspended. Verify your OTP immediately to avoid permanent blocking.",
        url: "http://192.168.1.100/bank-verify"
    },
    legitimate: {
        message: "Hello, your appointment is confirmed for tomorrow at 10 AM. Thank you for choosing our service.",
        url: ""
    },
    prize: {
        message: "Congratulations! You have won a free smartphone. Claim your prize now by verifying your personal information.",
        url: ""
    }
};

messageInput.addEventListener("input", () => {
    document.getElementById("charCount").textContent =
        `${messageInput.value.length} / 5000`;
});

document.querySelectorAll("[data-example]").forEach(button => {
    button.addEventListener("click", () => {
        const example = examples[button.dataset.example];

        messageInput.value = example.message;
        urlInput.value = example.url;

        document.getElementById("charCount").textContent =
            `${messageInput.value.length} / 5000`;

        messageInput.focus();
    });
});

form.addEventListener("submit", async (event) => {
    event.preventDefault();

    const message = messageInput.value.trim();
    const url = urlInput.value.trim();

    if (!message && !url) {
        alert("Please enter a message or URL to analyze.");
        return;
    }

    scanButton.disabled = true;
    scanButton.textContent = "Analyzing threats...";

    try {
        const response = await fetch("/api/scan", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ message, url })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Analysis failed.");
        }

        displayResults(data);

    } catch (error) {
        alert(error.message);
    } finally {
        scanButton.disabled = false;
        scanButton.innerHTML = "<span>⌕</span> Analyze for threats";
    }
});

function displayResults(data) {
    results.classList.remove("hidden");

    const badge = document.getElementById("riskBadge");
    const circle = document.getElementById("scoreCircle");

    badge.textContent = `${data.risk.toUpperCase()} RISK`;

    const colors = {
        Low: "#53e6a6",
        Medium: "#ffbd67",
        High: "#ff6b75"
    };

    badge.style.color = colors[data.risk];
    badge.style.background = `${colors[data.risk]}20`;

    circle.style.borderColor = colors[data.risk];
    circle.style.background = `${colors[data.risk]}12`;

    document.getElementById("scoreValue").textContent = data.score;

    document.getElementById("riskTitle").textContent =
        `${data.risk} risk detected`;

    document.getElementById("riskDescription").textContent =
        data.findings.length
            ? `The system identified ${data.findings.length} suspicious indicator(s).`
            : "No major configured warning indicators were detected.";

    document.getElementById("findingCount").textContent =
        `${data.findings.length} indicators`;

    const findingsList = document.getElementById("findingsList");
    findingsList.replaceChildren();

    if (data.findings.length === 0) {
        const empty = document.createElement("div");
        empty.className = "finding-item";

        const message = document.createElement("p");
        message.textContent = "No configured red flags were triggered.";

        empty.appendChild(message);
        findingsList.appendChild(empty);
    }

    data.findings.forEach(finding => {
        const item = document.createElement("div");
        item.className = "finding-item";

        const content = document.createElement("div");
        const title = document.createElement("strong");
        const reason = document.createElement("p");

        title.textContent = finding.type;
        reason.textContent = finding.reason;

        content.append(title, reason);

        const points = document.createElement("span");
        points.className = "finding-points";
        points.textContent = `+${finding.points} pts`;

        item.append(content, points);
        findingsList.appendChild(item);
    });

    document.getElementById("recommendationText").textContent =
    data.recommendation;

    // Render combined intelligence assessment
    renderCombinedAssessment(data.combined_assessment);

    // Render machine-learning analysis
    renderMLAnalysis(data.ml_analysis);

    results.scrollIntoView({
        behavior: "smooth",
        block: "start"
    });
}

function renderCombinedAssessment(assessment) {
    const badge = document.getElementById("combinedRiskBadge");
    const ruleRisk = document.getElementById("ruleRisk");
    const mlPrediction = document.getElementById("combinedMLPrediction");
    const verdict = document.getElementById("combinedVerdict");
    const reason = document.getElementById("combinedReason");

    if (!assessment) {
        verdict.textContent = "Unavailable";
        reason.textContent = "Combined assessment was not returned.";
        return;
    }

    const colors = {
        High: "#ff6b75",
        Medium: "#ffbd67",
        Low: "#53e6a6"
    };

    const color = colors[assessment.risk] || "#9ba9b9";

    badge.textContent = `${assessment.risk.toUpperCase()} RISK`;
    badge.style.color = color;
    badge.style.borderColor = color;

    ruleRisk.textContent = assessment.rule_risk || "Unavailable";
    ruleRisk.style.color = colors[assessment.rule_risk] || "#ffffff";

    mlPrediction.textContent =
        (assessment.ml_prediction || "Unavailable").toUpperCase();

    verdict.textContent =
        assessment.verdict || "Assessment unavailable";

    verdict.style.color = color;

    reason.textContent =
        assessment.reason || "No additional explanation available.";
}

function renderMLAnalysis(ml) {
    const prediction = document.getElementById("mlPrediction");
    const confidence = document.getElementById("mlConfidence");

    const classes = {
        ham: {
            label: "Legitimate (Ham)",
            color: "#53e6a6"
        },
        spam: {
            label: "Spam",
            color: "#ffbd67"
        },
        smishing: {
            label: "Smishing",
            color: "#ff6b75"
        }
    };

    const probabilityElements = {
        ham: {
            text: document.getElementById("hamProbability"),
            bar: document.getElementById("hamBar")
        },
        spam: {
            text: document.getElementById("spamProbability"),
            bar: document.getElementById("spamBar")
        },
        smishing: {
            text: document.getElementById("smishingProbability"),
            bar: document.getElementById("smishingBar")
        }
    };

    // Handle URL-only scans where no SMS was supplied
    if (!ml) {
        prediction.textContent = "Not analyzed";
        prediction.style.color = "#9ba9b9";
        confidence.textContent = "N/A";

        Object.values(probabilityElements).forEach(item => {
            item.text.textContent = "N/A";
            item.bar.style.width = "0%";
        });

        return;
    }

    const result = classes[ml.prediction];

    if (!result || !ml.probabilities) {
        prediction.textContent = "Unavailable";
        confidence.textContent = "N/A";
        return;
    }

    // Display predicted class
    prediction.textContent = result.label;
    prediction.style.color = result.color;

    // Display highest class probability
    confidence.textContent = `${Number(ml.confidence).toFixed(2)}%`;

    // Update all three probability bars
    Object.entries(probabilityElements).forEach(([label, elements]) => {
        const value = Number(ml.probabilities[label]);

        const safeValue = Number.isFinite(value)
            ? Math.min(100, Math.max(0, value))
            : 0;

        elements.text.textContent = `${safeValue.toFixed(2)}%`;
        elements.bar.style.width = `${safeValue}%`;
    });

    // Render explainable AI contributions
    renderContributionList(
        "xaiSupporting",
        ml.explanation?.supporting_terms,
        "positive"
    );

    renderContributionList(
        "xaiOpposing",
        ml.explanation?.opposing_terms,
        "negative"
    );
}

function renderContributionList(containerId, terms, type) {
    const container = document.getElementById(containerId);

    container.replaceChildren();

    if (!Array.isArray(terms) || terms.length === 0) {
        const empty = document.createElement("p");
        empty.className = "xai-empty";

        empty.textContent = type === "positive"
            ? "No significant supporting features found."
            : "No significant opposing features found.";

        container.appendChild(empty);
        return;
    }

    terms.forEach(item => {
        const row = document.createElement("div");
        row.className = "xai-term";

        const name = document.createElement("span");
        name.className = "xai-term-name";
        name.textContent = item.term;

        const value = Number(item.contribution);

        const contribution = document.createElement("span");
        contribution.className =
            `xai-term-value ${type}`;

        contribution.textContent =
            `${value > 0 ? "+" : ""}${value.toFixed(4)}`;

        row.append(name, contribution);
        container.appendChild(row);
    });
}