
from pathlib import Path
import json
import time

import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split, StratifiedKFold, cross_validate
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    make_scorer,
    confusion_matrix,
)

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
df = df.drop_duplicates(subset=["message"]).reset_index(drop=True)

X = df["message"]
y = df["label"]

# Fixed holdout split
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y,
)

models = {
    "Logistic Regression": LogisticRegression(
        max_iter=1000,
        class_weight="balanced",
    ),
    "Linear SVM": LinearSVC(
        class_weight="balanced",
        random_state=42,
    ),
}

cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

scoring = {
    "accuracy": "accuracy",
    "spam_precision": make_scorer(
        precision_score, pos_label="spam", zero_division=0
    ),
    "spam_recall": make_scorer(
        recall_score, pos_label="spam", zero_division=0
    ),
    "spam_f1": make_scorer(
        f1_score, pos_label="spam", zero_division=0
    ),
}

cv_results = []
holdout_results = []
threshold_results = []

for name, classifier in models.items():
    model = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), lowercase=True)),
        ("classifier", classifier),
    ])

    print(f"\nEvaluating {name}...")

    start = time.perf_counter()
    scores = cross_validate(
        model,
        X_train,
        y_train,
        cv=cv,
        scoring=scoring,
        n_jobs=-1,
        return_train_score=False,
    )
    cv_seconds = time.perf_counter() - start

    cv_row = {
        "model": name,
        "cv_training_seconds": round(cv_seconds, 3),
    }

    for metric in scoring:
        values = scores[f"test_{metric}"]
        cv_row[f"{metric}_mean"] = round(float(values.mean()), 4)
        cv_row[f"{metric}_std"] = round(float(values.std()), 4)

    cv_results.append(cv_row)

    # Fit using training data only
    start = time.perf_counter()
    model.fit(X_train, y_train)
    fit_seconds = time.perf_counter() - start

    predictions = model.predict(X_test)

    holdout_results.append({
        "model": name,
        "accuracy": round(float(accuracy_score(y_test, predictions)), 4),
        "spam_precision": round(float(precision_score(
            y_test, predictions, pos_label="spam", zero_division=0
        )), 4),
        "spam_recall": round(float(recall_score(
            y_test, predictions, pos_label="spam", zero_division=0
        )), 4),
        "spam_f1": round(float(f1_score(
            y_test, predictions, pos_label="spam", zero_division=0
        )), 4),
        "fit_seconds": round(fit_seconds, 3),
    })

    # Test alternative decision thresholds for Linear SVM
    if name == "Linear SVM":
        decision_scores = model.decision_function(X_test)

        for threshold in [-0.5, -0.25, 0.0, 0.25, 0.5]:
            adjusted = np.where(
                decision_scores >= threshold, "spam", "ham"
            )

            tn, fp, fn, tp = confusion_matrix(
                y_test, adjusted, labels=["ham", "spam"]
            ).ravel()

            threshold_results.append({
                "threshold": threshold,
                "accuracy": round(float(accuracy_score(
                    y_test, adjusted
                )), 4),
                "spam_precision": round(float(precision_score(
                    y_test, adjusted, pos_label="spam", zero_division=0
                )), 4),
                "spam_recall": round(float(recall_score(
                    y_test, adjusted, pos_label="spam", zero_division=0
                )), 4),
                "spam_f1": round(float(f1_score(
                    y_test, adjusted, pos_label="spam", zero_division=0
                )), 4),
                "false_positives": int(fp),
                "missed_spam": int(fn),
            })

# Save all experiment results
cv_df = pd.DataFrame(cv_results)
holdout_df = pd.DataFrame(holdout_results)
threshold_df = pd.DataFrame(threshold_results)

cv_df.to_csv("outputs/cross_validation_results.csv", index=False)
holdout_df.to_csv("outputs/holdout_comparison.csv", index=False)
threshold_df.to_csv("outputs/svm_threshold_results.csv", index=False)

summary = {
    "dataset_size": int(len(df)),
    "training_size": int(len(X_train)),
    "holdout_size": int(len(X_test)),
    "cross_validation_folds": 5,
    "cross_validation": cv_results,
    "holdout_test": holdout_results,
    "svm_threshold_experiment": threshold_results,
    "note": (
        "Results measure performance on this SMS spam dataset, "
        "not all real-world Indian scams."
    ),
}

with open("outputs/validation_summary.json", "w", encoding="utf-8") as file:
    json.dump(summary, file, indent=4)

print("\nSCAMSHIELD — CROSS-VALIDATION")
print("=" * 75)
print(cv_df.to_string(index=False))

print("\nHOLDOUT TEST RESULTS")
print("=" * 75)
print(holdout_df.to_string(index=False))

print("\nLINEAR SVM — THRESHOLD EXPERIMENT")
print("=" * 90)
print(threshold_df.to_string(index=False))

print("\nSaved results:")
print("- outputs/cross_validation_results.csv")
print("- outputs/holdout_comparison.csv")
print("- outputs/svm_threshold_results.csv")
print("- outputs/validation_summary.json")

print("\nReminder: these results apply to this SMS spam dataset,")
print("not all real-world Indian scams.")
