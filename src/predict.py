import os
import joblib
import pandas as pd
import numpy as np


def load_model(model_dir="models"):
    clf = joblib.load(os.path.join(model_dir, "rf_model.pkl"))
    le = joblib.load(os.path.join(model_dir, "label_encoder.pkl"))
    feature_names = joblib.load(os.path.join(model_dir, "feature_names.pkl"))
    return clf, le, feature_names


def predict_df(df, model_dir="models"):
    clf, le, feature_names = load_model(model_dir)
    # Ensure all expected features exist; fill missing with 0
    df = df.copy()
    for f in feature_names:
        if f not in df.columns:
            df[f] = 0
    X = df[feature_names].replace([np.inf, -np.inf], np.nan).fillna(0)
    preds = clf.predict(X)
    probs = clf.predict_proba(X).max(axis=1)
    df = df.copy()
    df["pred_label"] = le.inverse_transform(preds.astype(int))
    df["pred_confidence"] = (probs * 100).round(1)
    return df


if __name__ == "__main__":
    # quick local test
    import pandas as pd
    df = pd.DataFrame([ { 'f0': 0.1, 'f1': -0.2 } ])
    try:
        out = predict_df(df)
        print(out)
    except Exception as e:
        print("Prediction failed:", e)
