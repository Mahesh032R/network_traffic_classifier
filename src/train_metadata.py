import os
import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)


TRAIN_FILE = "data/train_flows_metadata.csv"
TEST_FILE = "data/test_flows_metadata.csv"

MODEL_DIR = "models"


def main():

    print("=" * 60)
    print("TRAINING METADATA RANDOM FOREST")
    print("=" * 60)

    os.makedirs(MODEL_DIR, exist_ok=True)

    train_df = pd.read_csv(TRAIN_FILE)
    test_df = pd.read_csv(TEST_FILE)

    feature_columns = [
        column
        for column in train_df.columns
        if column not in {"label", "source_pcap"}
    ]

    X_train = train_df[feature_columns]
    y_train = train_df["label"]

    X_test = test_df[feature_columns]
    y_test = test_df["label"]

    print(f"Training samples: {len(X_train)}")
    print(f"Testing samples:  {len(X_test)}")
    print(f"Features: {len(feature_columns)}")

    print("\nTraining Random Forest...")

    model = RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        class_weight="balanced",
        n_jobs=-1,
    )

    model.fit(X_train, y_train)

    print("Training complete.")

    predictions = model.predict(X_test)

    accuracy = accuracy_score(
        y_test,
        predictions
    )

    print("\n" + "=" * 60)
    print("METADATA MODEL EVALUATION")
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

    importance = pd.DataFrame({
        "feature": feature_columns,
        "importance": model.feature_importances_
    }).sort_values(
        "importance",
        ascending=False
    )

    print("\nTop 15 Features:")
    print(
        importance.head(15).to_string(
            index=False
        )
    )

    joblib.dump(
        model,
        os.path.join(
            MODEL_DIR,
            "rf_metadata_model.pkl"
        )
    )

    joblib.dump(
        feature_columns,
        os.path.join(
            MODEL_DIR,
            "metadata_feature_names.pkl"
        )
    )

    print("\nSaved:")
    print("  models/rf_metadata_model.pkl")
    print("  models/metadata_feature_names.pkl")


if __name__ == "__main__":
    main()