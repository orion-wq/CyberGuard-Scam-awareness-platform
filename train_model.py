import pandas as pd
import joblib

from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score
)

# 1. Load dataset
DATA_PATH = (
    "data/SMS PHISHING DATASET FOR MACHINE LEARNING "
    "AND PATTERN RECOGNITION/Dataset_5971.csv"
)

df = pd.read_csv(DATA_PATH)

# 2. Normalize data
df["LABEL"] = df["LABEL"].str.strip().str.lower()
df["TEXT"] = df["TEXT"].fillna("").str.strip()

df = df[df["LABEL"].isin(["ham", "spam", "smishing"])]
df = df[df["TEXT"] != ""]

print("Original usable rows:", len(df))

# 3. Identify messages with conflicting labels
label_counts = df.groupby("TEXT")["LABEL"].nunique()
conflicting_texts = label_counts[label_counts > 1].index

print("Conflicting message groups:", len(conflicting_texts))

# Remove every occurrence of conflicting messages
df = df[~df["TEXT"].isin(conflicting_texts)]

# 4. Remove duplicate messages
df = df.drop_duplicates(subset=["TEXT"])

print("\nCleaned dataset:", len(df))
print("\nClass distribution:")
print(df["LABEL"].value_counts())

# 5. Separate features and labels
X = df["TEXT"]
y = df["LABEL"]

# 6. Split into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("\nTraining samples:", len(X_train))
print("Testing samples:", len(X_test))

# 7. Build machine learning pipeline
model = Pipeline([
    (
        "tfidf",
        TfidfVectorizer(
            lowercase=True,
            stop_words="english",
            ngram_range=(1, 2),
            min_df=2,
            max_features=20000,
            sublinear_tf=True
        )
    ),
    (
        "classifier",
        LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
            random_state=42
        )
    )
])

# 8. Train
print("\nTraining model...")
model.fit(X_train, y_train)

# 9. Evaluate on unseen test data
predictions = model.predict(X_test)

print("\n========== MODEL EVALUATION ==========")
print("Accuracy:", round(accuracy_score(y_test, predictions), 4))

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        predictions,
        labels=["ham", "spam", "smishing"],
        zero_division=0
    )
)

print("Confusion Matrix:")
print(
    confusion_matrix(
        y_test,
        predictions,
        labels=["ham", "spam", "smishing"]
    )
)

# 10. Save trained model
Path("models").mkdir(exist_ok=True)

joblib.dump(model, "models/sms_classifier.joblib")

print("\nModel saved to models/sms_classifier.joblib")