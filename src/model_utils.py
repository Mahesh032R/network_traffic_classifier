"""Artifact paths and input checks shared by the prediction entry points."""
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MODEL_DIR = PROJECT_ROOT / "models"


def load_artifact(model_dir, filename):
    path = Path(model_dir) / filename
    if not path.is_file():
        raise FileNotFoundError(f"Required model file not found: {path.resolve()}")
    try:
        return joblib.load(path)
    except Exception as exc:
        raise RuntimeError(
            f"Could not load model file {path.resolve()}: {exc}. "
            "Use the Python dependencies compatible with the trained model."
        ) from exc


def validate_model_features(model, feature_names):
    if not all(callable(getattr(model, method, None)) for method in ("predict", "predict_proba")):
        raise ValueError("The model file must contain a fitted probabilistic classifier.")
    if not hasattr(model, "classes_"):
        raise ValueError("The classifier is not fitted: classes_ is missing.")
    if not isinstance(feature_names, (list, tuple, np.ndarray, pd.Index)):
        raise ValueError("Model feature names must be a sequence of column names.")
    names = list(feature_names)
    if not names or not all(isinstance(name, str) for name in names) or len(names) != len(set(names)):
        raise ValueError("Model feature names must be nonempty and unique.")
    if getattr(model, "n_features_in_", len(names)) != len(names):
        raise ValueError("Model and feature_names.pkl have different feature counts.")
    trained = getattr(model, "feature_names_in_", None)
    if trained is not None and list(trained) != names:
        raise ValueError("Model and saved feature names have different names or order.")
    return names


def prepare_features(df, feature_names):
    if not isinstance(df, pd.DataFrame) or df.empty:
        raise ValueError("The dataset is empty. Provide at least one flow.")
    if not df.columns.is_unique:
        raise ValueError("The dataset contains duplicate column names.")
    missing = [name for name in feature_names if name not in df.columns]
    if missing:
        raise ValueError(f"Missing required features: {', '.join(missing)}")
    values = df[list(feature_names)]
    numeric = values.apply(pd.to_numeric, errors="coerce")
    invalid = values.notna() & numeric.isna()
    if invalid.any().any():
        columns = invalid.columns[invalid.any()].tolist()
        raise ValueError(f"Features must contain numeric values: {', '.join(columns)}")
    # Undefined flow statistics are handled consistently with PCAP inference.
    return numeric.replace([np.inf, -np.inf], np.nan).fillna(0)
