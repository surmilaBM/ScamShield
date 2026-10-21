
from pathlib import Path
import json
import time

import joblib
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay,
    precision_score,
    recall_score,
    f1_score,
)

BASE_DIR = Path(__file__).resolve().parent
DATA_PATH = BASE_DIR / "data" / "spam.csv"
OUTPUT_DIR = BASE_DIR / "outputs"
OUTPUT_DIR.mkdir(exist_ok=True)

# Load the existing original dataset only.
df = pd.read_csv(DATA_PATH, encoding="latin-1")
df = df[["v1", "v2"]].copy()
df.columns = ["label", "message"]

df = df.dropna()
df["label"] = df["label"].astype(str).str.strip().str.lower()
df["message"] = df["message"].astype(str).str.strip()
df = df[df["label"].isin(["ham", "spam"])]
df = df[df["message"] != ""]
df = df.drop_duplicates(subset=["message"]).reset_index(drop=True)

X = df["message"]
y = df["label"]

# Deterministic, stratified holdout split.
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y,
)

# Preserve the existing algorithm and hyperparameters.
model = Pipeline([
    (
        "tfidf",
        TfidfVectorizer(
            ngram_range=(1, 2),
            lowercase=True,
        ),
    ),
    (
        "classifier",
        CalibratedClassifierCV(
            estimator=LinearSVC(
                class_weight="balanced",
                random_state=42,
            ),
            method="sigmoid",
            cv=5,
        ),
    ),
])

print("Training calibrated Linear SVM...")
start = time.perf_counter()
model.fit(X_train, y_train)
training_seconds = time.perf_counter() - start

# Evaluate on the untouched holdout set.
predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)
precision = precision_score(
    y_test, predictions, pos_label="spam", zero_division=0
)
recall = recall_score(
    y_test, predictions, pos_label="spam", zero_division=0
)
f1 = f1_score(
    y_test, predictions, pos_label="spam", zero_division=0
)

report = classification_report(
    y_test, predictions, output_dict=True, zero_division=0
)

labels = ["ham", "spam"]
cm = confusion_matrix(y_test, predictions, labels=labels)

print("\nSCAMSHIELD INDIA — MODEL EVALUATION")
print("=" * 45)
print(f"Dataset size: {len(df)}")
print(f"Training size: {len(X_train)}")
print(f"Testing size: {len(X_test)}")
print(f"Training time: {training_seconds:.2f} seconds")
print(f"Accuracy: {accuracy:.4f}")
print(f"Spam precision: {precision:.4f}")
print(f"Spam recall: {recall:.4f}")
print(f"Spam F1-score: {f1:.4f}")
print("\nConfusion matrix:")
print(cm)
print("\nClassification report:")
print(classification_report(y_test, predictions, zero_division=0))

# Save the complete pipeline and its fitted vectorizer.
joblib.dump(model, BASE_DIR / "scam_model.joblib")
joblib.dump(
    model.named_steps["tfidf"],
    BASE_DIR / "vectorizer.joblib",
)

# Save evaluation metrics in the requested metrics.json.
metrics = {
    "model": "Calibrated Linear SVM",
    "random_state": 42,
    "dataset_size": int(len(df)),
    "training_size": int(len(X_train)),
    "testing_size": int(len(X_test)),
    "training_seconds": round(training_seconds, 3),
    "accuracy": round(float(accuracy), 4),
    "spam_precision": round(float(precision), 4),
    "spam_recall": round(float(recall), 4),
    "spam_f1": round(float(f1), 4),
    "classification_report": report,
    "confusion_matrix": cm.tolist(),
    "confusion_matrix_labels": labels,
    "probability_note": (
        "Model-estimated spam score; not a verified probability of fraud."
    ),
    "dataset_limitation": (
        "Evaluation uses the original SMS dataset and does not establish "
        "performance on all real-world Indian scams."
    ),
}

with open(BASE_DIR / "metrics.json", "w", encoding="utf-8") as file:
    json.dump(metrics, file, indent=4)

# Preserve the existing confusion matrix output.
display = ConfusionMatrixDisplay(
    confusion_matrix=cm,
    display_labels=["Legitimate (ham)", "Spam"],
)
display.plot(values_format="d")
plt.title("ScamShield India — Calibrated SVM")
plt.tight_layout()
plt.savefig(OUTPUT_DIR / "confusion_matrix.png", dpi=200)
plt.close()

print("\nSaved:")
print("- scam_model.joblib")
print("- vectorizer.joblib")
print("- metrics.json")
print("- outputs/confusion_matrix.png")
