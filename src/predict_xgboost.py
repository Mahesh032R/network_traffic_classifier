
import numpy as np

if __package__:
    from .model_utils import MODEL_DIR, load_artifact, prepare_features, validate_model_features
else:
    from model_utils import MODEL_DIR, load_artifact, prepare_features, validate_model_features


def load_xgboost_model(model_dir=MODEL_DIR):
    model = load_artifact(model_dir, "scenario_b_xgb_model.pkl")
    feature_names = validate_model_features(
        model, load_artifact(model_dir, "scenario_b_xgb_feature_names.pkl")
    )
    label_encoder = load_artifact(model_dir, "scenario_b_xgb_label_encoder.pkl")
    if not np.array_equal(model.classes_, np.arange(len(label_encoder.classes_))):
        raise ValueError("XGBoost model and label encoder classes do not match.")

    return model, feature_names, label_encoder


def predict_xgboost_df(df, model_dir=MODEL_DIR):
    model, feature_names, label_encoder = load_xgboost_model(model_dir)

    X = prepare_features(df, feature_names)
    df = df.copy()

    predictions = model.predict(X).astype(int)
    probabilities = model.predict_proba(X).max(axis=1)

    df["pred_label"] = label_encoder.inverse_transform(predictions)
    df["pred_confidence"] = (probabilities * 100).round(1)

    return df
