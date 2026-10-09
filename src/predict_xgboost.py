
import os
import joblib
import pandas as pd
import numpy as np


def load_xgboost_model(model_dir="models"):
    model = joblib.load(
        os.path.join(model_dir, "scenario_b_xgb_model.pkl")
    )
    feature_names = joblib.load(
        os.path.join(model_dir, "scenario_b_xgb_feature_names.pkl")
    )
    label_encoder = joblib.load(
        os.path.join(model_dir, "scenario_b_xgb_label_encoder.pkl")
    )

    return model, feature_names, label_encoder


def predict_xgboost_df(df, model_dir="models"):
    model, feature_names, label_encoder = load_xgboost_model(model_dir)

    df = df.copy()

    # Ensure the model receives the same features and order as training.
    for feature in feature_names:
        if feature not in df.columns:
            df[feature] = 0

    X = df[list(feature_names)].copy()
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0)

    predictions = model.predict(X).astype(int)
    probabilities = model.predict_proba(X).max(axis=1)

    df["pred_label"] = label_encoder.inverse_transform(predictions)
    df["pred_confidence"] = (probabilities * 100).round(1)

    return df
