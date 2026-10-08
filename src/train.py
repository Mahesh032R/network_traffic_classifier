import os
import json
import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)


TRAIN_FILE = "data/train_flows.csv"
TEST_FILE = "data/test_flows.csv"
MODEL_DIR = "models"


EXCLUDED_COLUMNS = {
    "label",
    "source_pcap",
}


def main():

    print("=" * 60)
    print("TRAINING RANDOM FOREST MODEL")
    print("=" * 60)

    os.makedirs(MODEL_DIR, exist_ok=True)

    # ---------------------------------------------------------
    # Load datasets
    # ---------------------------------------------------------

    train_df = pd.read_csv(TRAIN_FILE)
    test_df = pd.read_csv(TEST_FILE)

    print(f"Training samples: {len(train_df)}")
    print(f"Testing samples:  {len(test_df)}")

    # ---------------------------------------------------------
    # Separate features and labels
    # ---------------------------------------------------------

    feature_columns = [
        column
        for column in train_df.columns
        if column not in EXCLUDED_COLUMNS
    ]

    X_train = train_df[feature_columns]
    y_train = train_df["label"]

    X_test = test_df[feature_columns]
    y_test = test_df["label"]

    print(f"Features: {len(feature_columns)}")

    # ---------------------------------------------------------
    # Train Random Forest
    # ---------------------------------------------------------

    print("\nTraining Random Forest...")

    model = RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        class_weight="balanced",
        n_jobs=-1,
    )

    model.fit(X_train, y_train)

    print("Training complete.")

    # ---------------------------------------------------------
    # Evaluate
    # ---------------------------------------------------------

    predictions = model.predict(X_test)

    accuracy = accuracy_score(
        y_test,
        predictions
    )

    print("\n" + "=" * 60)
    print("MODEL EVALUATION")
    print("=" * 60)

    print(f"\nAccuracy: {accuracy:.4f}")

    print("\nClassification Report:")
    print(
        classification_report(
            y_test,
            predictions,
            zero_division=0
        )
    )

    print("Confusion Matrix:")
    print(
        confusion_matrix(
            y_test,
            predictions
        )
    )

    # ---------------------------------------------------------
    # Feature importance
    # ---------------------------------------------------------

    importance = pd.DataFrame({
        "feature": feature_columns,
        "importance": model.feature_importances_
    })

    importance = importance.sort_values(
        "importance",
        ascending=False
    )

    print("\nTop 15 Features:")
    print(
        importance.head(15).to_string(
            index=False
        )
    )

    # ---------------------------------------------------------
    # Save model
    # ---------------------------------------------------------

    joblib.dump(
        model,
        os.path.join(
            MODEL_DIR,
            "rf_model.pkl"
        )
    )

    joblib.dump(
        feature_columns,
        os.path.join(
            MODEL_DIR,
            "feature_names.pkl"
        )
    )

    # Save class names.
    class_names = sorted(
        y_train.unique().tolist()
    )

    with open(
        os.path.join(
            MODEL_DIR,
            "classes.json"
        ),
        "w"
    ) as file:

        json.dump(
            class_names,
            file,
            indent=2
        )

    print("\nModel files saved:")
    print("  models/rf_model.pkl")
    print("  models/feature_names.pkl")
    print("  models/classes.json")


if __name__ == "__main__":
    main()