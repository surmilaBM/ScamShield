
from pathlib import Path
import json

import joblib
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay,
)

# Create output folder
Path("outputs").mkdir(exist_ok=True)

# Load and clean dataset
df = pd.read_csv("data/spam.csv", encoding="latin-1")
df = df[["v1", "v2"]].copy()
df.columns = ["label", "message"]

df = df.dropna()
df["label"] = df["label"].str.strip().str.lower()
df["message"] = df["message"].astype(str).str.strip()
df = df[df["label"].isin(["ham", "spam"])]
df = df[df["message"] != ""]
df = df.drop_duplicates(subset=["message"])

X = df["message"]
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y,
)

# Build and train the model
model = Pipeline([
    ("tfidf", TfidfVectorizer(ngram_range=(1, 2), lowercase=True)),
    ("classifier", LogisticRegression(
        max_iter=1000,
        class_weight="balanced"
    )),
])

model.fit(X_train, y_train)
predictions = model.predict(X_test)

# Evaluate model
accuracy = accuracy_score(y_test, predictions)
report = classification_report(
    y_test, predictions, output_dict=True, zero_division=0
)

print("\nSCAMSHIELD INDIA - MODEL EVALUATION")
print("=" * 45)
print("Dataset messages:", len(df))
print("Training messages:", len(X_train))
print("Testing messages:", len(X_test))
print(f"Accuracy: {accuracy:.4f} ({accuracy * 100:.2f}%)")
print("\nClassification report:")
print(classification_report(y_test, predictions, zero_division=0))

# Save confusion matrix figure
labels = ["ham", "spam"]
cm = confusion_matrix(y_test, predictions, labels=labels)

display = ConfusionMatrixDisplay(
    confusion_matrix=cm,
    display_labels=["Legitimate (ham)", "Spam"],
)

display.plot(values_format="d")
plt.title("ScamShield India - Confusion Matrix")
plt.tight_layout()
plt.savefig("outputs/confusion_matrix.png", dpi=200)
plt.close()

# Save metrics as JSON
metrics = {
    "dataset_size": int(len(df)),
    "training_size": int(len(X_train)),
    "testing_size": int(len(X_test)),
    "accuracy": round(float(accuracy), 4),
    "classification_report": report,
    "confusion_matrix": cm.tolist(),
    "confusion_matrix_labels": labels,
}

with open("outputs/evaluation_metrics.json", "w", encoding="utf-8") as file:
    json.dump(metrics, file, indent=4)

# Save trained model
joblib.dump(model, "scam_model.joblib")

print("\nSaved model: scam_model.joblib")
print("Saved confusion matrix: outputs/confusion_matrix.png")
print("Saved metrics: outputs/evaluation_metrics.json")
print("\nNote: This dataset evaluates SMS spam detection,")
print("not all Indian scam types or real-world fraud.")
