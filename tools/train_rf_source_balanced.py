
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
OUTPUT_DIR = Path("models/experiments/rf_source_balanced")

EXCLUDED = {"label", "source_pcap"}
MAX_ROWS_PER_SOURCE = 500
RANDOM_STATE = 42


def main():
    train = pd.read_csv(TRAIN_FILE)
    test = pd.read_csv(TEST_FILE)

    features = [
        c for c in train.columns
        if c not in EXCLUDED
    ]

    # Remove exact duplicates within each source and label.
    unique = train.drop_duplicates(
        subset=["source_pcap", "label"] + features
    ).copy()

    # Cap the influence of each source PCAP.
    parts = []
    for _, group in unique.groupby(
        ["source_pcap", "label"], sort=True
    ):
        if len(group) > MAX_ROWS_PER_SOURCE:
            group = group.sample(
                n=MAX_ROWS_PER_SOURCE,
                random_state=RANDOM_STATE,
            )
        parts.append(group)

    balanced = pd.concat(parts, ignore_index=True)

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

    print("Original training rows:", len(train))
    print("Experimental training rows:", len(balanced))
    print("\nRows per class:")
    print(y_train.value_counts().sort_index())
    print("\nRows per source PCAP:")
    print(balanced.groupby("source_pcap").size().to_string())

    print("\nAccuracy:", round(accuracy_score(y_test, predictions), 4))
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
