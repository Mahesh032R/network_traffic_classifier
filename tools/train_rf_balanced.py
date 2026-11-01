
import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    f1_score,
)

TRAIN_FILE = Path("data/train_flows.csv")
TEST_FILE = Path("data/test_flows.csv")
OUTPUT_DIR = Path("models/experiments/rf_balanced")

EXCLUDED = {"label", "source_pcap"}
RANDOM_STATE = 42
MAX_PER_CLASS = 85


def main():
    train = pd.read_csv(TRAIN_FILE)
    test = pd.read_csv(TEST_FILE)

    features = [
        col for col in train.columns
        if col not in EXCLUDED
    ]

    # Keep one row per unique feature vector within each class.
    unique_train = train.drop_duplicates(
        subset=features + ["label"]
    ).copy()

    # Sample the same number of unique examples per class.
    counts = unique_train["label"].value_counts()
    sample_size = min(MAX_PER_CLASS, int(counts.min()))

    balanced = (
        unique_train.groupby("label", group_keys=False)
        .sample(n=sample_size, random_state=RANDOM_STATE)
        .reset_index(drop=True)
    )

    X_train = (
        balanced[features]
        .apply(pd.to_numeric, errors="coerce")
        .replace([float("inf"), -float("inf")], float("nan"))
        .fillna(0)
    )
    y_train = balanced["label"].astype(str)

    X_test = (
        test[features]
        .apply(pd.to_numeric, errors="coerce")
        .replace([float("inf"), -float("inf")], float("nan"))
        .fillna(0)
    )
    y_test = test["label"].astype(str)

    model = RandomForestClassifier(
        n_estimators=300,
        class_weight="balanced",
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    print("Training rows:", len(balanced))
    print("\nTraining samples per class:")
    print(y_train.value_counts().sort_index())
    print("\nTest samples:", len(test))
    print("Accuracy:", round(accuracy_score(y_test, predictions), 4))
    print(
        "Balanced accuracy:",
        round(balanced_accuracy_score(y_test, predictions), 4),
    )
    print(
        "Macro F1:",
        round(f1_score(y_test, predictions, average="macro"), 4),
    )
    print("\nClassification report:")
    print(classification_report(y_test, predictions, zero_division=0))

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, OUTPUT_DIR / "rf_model.pkl")
    joblib.dump(features, OUTPUT_DIR / "feature_names.pkl")

    with open(OUTPUT_DIR / "classes.json", "w", encoding="utf-8") as file:
        json.dump(sorted(y_train.unique().tolist()), file, indent=2)

    print("\nExperimental model saved to:", OUTPUT_DIR)


if __name__ == "__main__":
    main()
