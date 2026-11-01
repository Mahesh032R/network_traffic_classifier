
import joblib
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    f1_score,
)

test = pd.read_csv("data/test_flows.csv")

feature_names = joblib.load("models/feature_names.pkl")

X = (
    test[feature_names]
    .apply(pd.to_numeric, errors="coerce")
    .replace([float("inf"), -float("inf")], float("nan"))
    .fillna(0)
)

y = test["label"].astype(str)

models = {
    "Original RF": "models/rf_model.pkl",
    "Source-balanced RF": (
        "models/experiments/rf_source_balanced/rf_model.pkl"
    ),
}

for name, path in models.items():
    model = joblib.load(path)
    predictions = model.predict(X)

    print(f"\n{name}")
    print("-" * 35)
    print(f"Accuracy: {accuracy_score(y, predictions):.4f}")
    print(
        "Balanced accuracy: "
        f"{balanced_accuracy_score(y, predictions):.4f}"
    )
    print(
        f"Macro F1: {f1_score(y, predictions, average='macro'):.4f}"
    )
