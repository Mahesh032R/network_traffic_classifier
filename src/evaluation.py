"""Reproducible, model-specific evaluation helpers; no model is changed here."""
from pathlib import Path
import re

import numpy as np
import pandas as pd
from sklearn.metrics import (accuracy_score, classification_report,
                             confusion_matrix, f1_score)
from sklearn.model_selection import train_test_split

from .model_utils import prepare_features


def rf_session_key(source_pcap):
    """Keep adjacent a/b PCAP segments of one recording in the same session."""
    stem = Path(str(source_pcap)).stem.lower()
    return re.sub(r"(?<=\d)[ab]$", "", stem)


def session_holdout(frame, seed=42):
    """Select one whole source session per RF class using a fixed seed."""
    if not {"label", "source_pcap"}.issubset(frame.columns):
        raise ValueError("RF data needs label and source_pcap columns.")
    sessions = frame["source_pcap"].map(rf_session_key)
    session_labels = pd.DataFrame({"session": sessions, "label": frame["label"]}).drop_duplicates()
    if session_labels.groupby("session")["label"].nunique().gt(1).any():
        raise ValueError("A source session has multiple labels; review the PCAP grouping.")
    rng = np.random.default_rng(seed)
    selected = {}
    for label, group in session_labels.groupby("label", sort=True):
        choices = sorted(group["session"].unique())
        if len(choices) < 2:
            raise ValueError(f"Class {label} needs at least two source sessions for a holdout.")
        selected[str(label)] = str(rng.choice(choices))
    test_mask = sessions.isin(selected.values())
    train, test = frame.loc[~test_mask].copy(), frame.loc[test_mask].copy()
    if set(train["source_pcap"].map(rf_session_key)) & set(test["source_pcap"].map(rf_session_key)):
        raise AssertionError("Training and test sessions overlap.")
    return train, test, selected


def curated_rf_training(frame, feature_names, max_rows_per_source=500, seed=42):
    """Deduplicate, reject contradictory vectors, and cap each PCAP's weight.

    This operates on training sessions only. It never reads the held-out set.
    """
    if max_rows_per_source < 1:
        raise ValueError("max_rows_per_source must be positive.")
    features = prepare_features(frame, feature_names)
    rows = pd.concat([frame[["source_pcap", "label"]].reset_index(drop=True),
                      features.reset_index(drop=True)], axis=1)
    unique = rows.drop_duplicates(subset=["source_pcap", "label"] + list(feature_names))
    conflicting = unique.groupby(list(feature_names), dropna=False)["label"].transform("nunique").gt(1)
    unique = unique.loc[~conflicting]
    if unique.empty:
        raise ValueError("No unambiguous Random Forest training vectors remain.")
    parts = []
    for _, group in unique.groupby(["source_pcap", "label"], sort=True):
        if len(group) > max_rows_per_source:
            group = group.sample(n=max_rows_per_source, random_state=seed)
        parts.append(group)
    return pd.concat(parts, ignore_index=True)


def seen_feature_vectors(train_features, test_features):
    """Mark test rows whose *complete* preprocessed vector appears in training."""
    if list(train_features.columns) != list(test_features.columns):
        raise ValueError("Training and test features must have identical names and order.")
    train_vectors = set(train_features.drop_duplicates().itertuples(index=False, name=None))
    return np.fromiter((row in train_vectors for row in test_features.itertuples(index=False, name=None)),
                       dtype=bool, count=len(test_features))


def scenario_b_split_indices(labels, seed=42):
    """Reproduce the saved XGBoost training script's stratified flow split."""
    return train_test_split(np.arange(len(labels)), test_size=0.2,
                            stratify=labels, random_state=seed)


def classification_metrics(actual, predicted, labels):
    """Return stable scalar, per-class, and confusion-matrix results."""
    actual = np.asarray(actual, dtype=str)
    predicted = np.asarray(predicted, dtype=str)
    labels = list(labels)
    if not len(actual) or len(actual) != len(predicted):
        raise ValueError("Evaluation needs matching nonempty labels and predictions.")
    if not set(actual).issubset(labels) or not set(predicted).issubset(labels):
        raise ValueError("Evaluation labels must match the supplied class list.")
    report = classification_report(actual, predicted, labels=labels,
                                   output_dict=True, zero_division=0)
    present = [name for name in labels if report[name]["support"] > 0]
    return {
        "rows": int(len(actual)),
        "accuracy": float(accuracy_score(actual, predicted)),
        "balanced_accuracy": float(np.mean([report[name]["recall"] for name in present])),
        "macro_f1": float(f1_score(actual, predicted, labels=labels, average="macro", zero_division=0)),
        "per_class": {name: {key: float(value) if key != "support" else int(value)
                             for key, value in report[name].items()} for name in labels},
        "labels": labels,
        "confusion_matrix": confusion_matrix(actual, predicted, labels=labels).tolist(),
    }
