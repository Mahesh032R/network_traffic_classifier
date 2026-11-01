import pandas as pd
import numpy as np

if __package__:
    from .model_utils import MODEL_DIR, load_artifact, prepare_features, validate_model_features
else:
    from model_utils import MODEL_DIR, load_artifact, prepare_features, validate_model_features


def load_model(model_dir=MODEL_DIR):
    clf = load_artifact(model_dir, "rf_model.pkl")
    feature_names = validate_model_features(
        clf, load_artifact(model_dir, "feature_names.pkl")
    )
    # Current RF training stores application names directly in classes_.
    # Only legacy classifiers with integer-encoded classes need an encoder.
    le = None
    if np.issubdtype(np.asarray(clf.classes_).dtype, np.integer):
        le = load_artifact(model_dir, "label_encoder.pkl")
        if not np.array_equal(clf.classes_, np.arange(len(le.classes_))):
            raise ValueError("Random Forest and label encoder classes do not match.")
    return clf, le, feature_names


def predict_df(df, model_dir=MODEL_DIR):
    return predict_with_model(df, load_model(model_dir))


def predict_with_model(df, model_bundle):
    """Predict with a loaded bundle using the existing PCAP preprocessing."""
    clf, le, feature_names = model_bundle
    X = prepare_features(df, feature_names)
    df = df.copy()
    preds = clf.predict(X)
    probs = clf.predict_proba(X).max(axis=1)
    df = df.copy()
    df["pred_label"] = le.inverse_transform(preds.astype(int)) if le is not None else preds
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
