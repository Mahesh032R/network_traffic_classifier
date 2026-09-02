import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder


def generate_synthetic_data(n_samples=1000, n_features=20, n_classes=3):
    rng = np.random.RandomState(42)
    X = rng.randn(n_samples, n_features)
    y = rng.randint(0, n_classes, size=n_samples)
    feature_names = [f"f{i}" for i in range(n_features)]
    df = pd.DataFrame(X, columns=feature_names)
    df["label"] = y
    return df, feature_names


def train_and_save(model_dir="models"):
    os.makedirs(model_dir, exist_ok=True)
    df, feature_names = generate_synthetic_data()

    X = df[feature_names]
    y = df["label"].astype(str)

    le = LabelEncoder()
    y_enc = le.fit_transform(y)

    clf = RandomForestClassifier(n_estimators=50, random_state=42)
    clf.fit(X, y_enc)

    # Save artifacts
    joblib.dump(clf, os.path.join(model_dir, "rf_model.pkl"))
    joblib.dump(le, os.path.join(model_dir, "label_encoder.pkl"))
    joblib.dump(feature_names, os.path.join(model_dir, "feature_names.pkl"))

    print("Training complete. Models saved to:")
    print(f"  {os.path.join(model_dir, 'rf_model.pkl')}")
    print(f"  {os.path.join(model_dir, 'label_encoder.pkl')}")
    print(f"  {os.path.join(model_dir, 'feature_names.pkl')}")


if __name__ == "__main__":
    train_and_save()
