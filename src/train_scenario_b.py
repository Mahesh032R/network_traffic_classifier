import os
import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split

from scenario_b import load_scenario_b, FEATURE_NAMES


MODEL_DIR = "models"


def main():

    print("=" * 60)
    print("SCENARIO B - RANDOM FOREST BASELINE")
    print("=" * 60)

    df = load_scenario_b()

    X = df[FEATURE_NAMES]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y,
    )

    print(f"Total samples: {len(df)}")
    print(f"Training samples: {len(X_train)}")
    print(f"Testing samples: {len(X_test)}")
    print(f"Features: {len(FEATURE_NAMES)}")

    print("\nTraining class distribution:")
    print(y_train.value_counts())

    print("\nTesting class distribution:")
    print(y_test.value_counts())

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
    print("SCENARIO B MODEL EVALUATION")
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
        "feature": FEATURE_NAMES,
        "importance": model.feature_importances_,
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

    os.makedirs(MODEL_DIR, exist_ok=True)

    joblib.dump(
        model,
        os.path.join(
            MODEL_DIR,
            "scenario_b_rf_model.pkl"
        )
    )

    joblib.dump(
        FEATURE_NAMES,
        os.path.join(
            MODEL_DIR,
            "scenario_b_feature_names.pkl"
        )
    )

    print("\nSaved:")
    print("  models/scenario_b_rf_model.pkl")
    print("  models/scenario_b_feature_names.pkl")


if __name__ == "__main__":
    main()