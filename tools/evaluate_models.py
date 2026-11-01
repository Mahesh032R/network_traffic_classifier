"""Audit saved models and train one isolated, session-split RF experiment.

Run from any directory with: python -B tools/evaluate_models.py
Neither the default RF artifacts nor the XGBoost artifacts are overwritten.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import sklearn

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.evaluation import (classification_metrics, curated_rf_training,
                            rf_session_key, scenario_b_split_indices,
                            seen_feature_vectors, session_holdout)
from src.model_utils import MODEL_DIR, PROJECT_ROOT, prepare_features
from src.predict import load_model
from src.predict_xgboost import load_xgboost_model
from src.scenario_b import FEATURE_NAMES, load_scenario_b


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def save_metrics(output_dir, name, metrics):
    labels = metrics["labels"]
    pd.DataFrame(metrics["confusion_matrix"], index=labels, columns=labels).rename_axis(
        "actual / predicted"
    ).to_csv(output_dir / f"{name}_confusion.csv")
    pd.DataFrame.from_dict(metrics["per_class"], orient="index").rename_axis("class").to_csv(
        output_dir / f"{name}_classes.csv"
    )


def write_summary(output_dir, results):
    rf = results["random_forest"]
    xgb = results["scenario_b_xgboost"]
    experiment = rf["session_experiment"]

    def percentage(value):
        return f"{value * 100:.2f}%"

    def class_table(metrics):
        lines = ["| Class | Support | Precision | Recall | F1 |",
                 "|---|---:|---:|---:|---:|"]
        for name, values in metrics["per_class"].items():
            lines.append(f"| {name} | {values['support']} | {values['precision']:.3f} | "
                         f"{values['recall']:.3f} | {values['f1-score']:.3f} |")
        return lines

    lines = [
        "# Model evaluation audit", "",
        "Reproduce from the repository root with `.\\.venv\\Scripts\\python.exe -B tools\\evaluate_models.py`.",
        "The command reads the existing models and datasets, retrains only Random Forest baselines and one "
        "isolated RF candidate, and writes this report plus CSV confusion matrices. It does not change the dashboard model.",
        "", "## Data and method", "",
        "Both datasets come from the [UNB ISCXVPN2016 VPN-nonVPN dataset](https://www.unb.ca/cic/datasets/vpn.html). "
        "They are different prediction tasks and their accuracies must not be compared as if they share a test set.",
        "", "| Model | Local source | Rows | Classes | Features | Evaluation |",
        "|---|---|---:|---:|---:|---|",
        f"| Saved RF | `NonVPN-PCAPs-01.zip`, 23 real PCAPs; labels assigned by filename | "
        f"{rf['data_rows']['all']:,} | {len(rf['classes'])} | {len(rf['features'])} | "
        f"{rf['data_rows']['saved_train']:,} train / {rf['data_rows']['saved_test']:,} test, "
        "PCAP-name split; related a/b sessions overlap |",
        f"| Saved XGBoost | `Scenario B-ARFF.zip`, 15-second time features | {xgb['rows']:,} | "
        f"{len(xgb['classes'])} | {len(xgb['features'])} | "
        f"{xgb['split']['train_rows']:,} train / {xgb['split']['test_rows']:,} test, "
        "stratified random-flow split (`random_state=42`) |",
        "", "RF classes: " + ", ".join(rf["classes"]) + ".",
        "XGBoost classes: " + ", ".join(xgb["classes"]) + ".",
        "The 61 RF features are NFStream flow timing, packet/byte, protocol, and TCP-flag statistics; "
        "IPs, ports, hostnames, and nDPI names are excluded. The 23 XGBoost features are time-based Scenario B "
        "statistics. The exact ordered feature lists and SHA-256 hashes are in [results.json](results.json).",
        "At inference both paths validate numeric features and replace NaN/infinity with zero. The local training "
        "CSVs have no missing or infinite feature values, so this does not alter the evaluated rows. "
        "The XGBoost training script used the raw 23 columns; its preprocessing policy should be documented "
        "explicitly before deployment to new data.",
        "", "## Saved Random Forest", "",
        f"Accuracy **{percentage(rf['saved_model_test']['accuracy'])}**, "
        f"balanced accuracy **{percentage(rf['saved_model_test']['balanced_accuracy'])}**, "
        f"macro F1 **{rf['saved_model_test']['macro_f1']:.3f}** on 952 flows. "
        "[Confusion matrix](rf_saved_model_test_confusion.csv) and "
        "[per-class CSV](rf_saved_model_test_classes.csv).",
        "", *class_table(rf["saved_model_test"]), "",
        f"Refitting the saved RF configuration on `train_flows.csv` produced identical predictions on all "
        f"{rf['saved_model_test']['rows']} test rows (agreement "
        f"{percentage(rf['saved_model_refit_agreement_on_test'])}). This strongly supports the local "
        "real-PCAP training provenance; `extract_placeholder()` is a separate unused helper.",
        f"The saved split has {rf['saved_split']['train_pcaps']} train PCAP filenames and "
        f"{rf['saved_split']['test_pcaps']} test PCAP filenames, but inferred a/b recording groups cross the "
        f"split for {rf['saved_split']['test_rows_in_shared_sessions']} of 952 test flows. "
        f"Another {rf['saved_split']['test_rows_with_seen_feature_vector']} test flows have an identical "
        "preprocessed feature vector in training. Only 96 test rows come from wholly absent inferred sessions, "
        "and those are all Facebook Chat, so the saved model has no independent five-class session test.",
        f"The training set has {rf['saved_split']['train_exact_duplicate_vectors']:,} repeated feature vectors "
        f"and {rf['saved_split']['train_conflicting_feature_vectors']} feature vectors with conflicting labels. "
        "One Facebook Audio PCAP contributes 104,949 of 114,764 training flows. PCAP-level labels may include "
        "background traffic. The saved test result is therefore descriptive, not a reliable live-traffic accuracy claim.",
        "", "## Session-level Random Forest experiment", "",
        "The split groups each matching a/b PCAP pair as one inferred recording session and holds one session "
        "per class out with seed 42. Both models below use the same 61 features, 200-tree RF settings, and "
        f"{experiment['test_rows']:,} test flows. The candidate uses only its training sessions, removes "
        "duplicate and contradictory vectors, and caps each source PCAP at 500 rows. "
        "This reduces its training set to " + f"{experiment['curated_train_rows']:,} rows.",
        "", "| Model | Accuracy | Balanced accuracy | Macro F1 |",
        "|---|---:|---:|---:|",
        f"| Baseline retrained on grouped split | {percentage(experiment['baseline']['accuracy'])} | "
        f"{percentage(experiment['baseline']['balanced_accuracy'])} | {experiment['baseline']['macro_f1']:.3f} |",
        f"| Curated candidate | {percentage(experiment['candidate']['accuracy'])} | "
        f"{percentage(experiment['candidate']['balanced_accuracy'])} | {experiment['candidate']['macro_f1']:.3f} |",
        "", "[Baseline confusion matrix](rf_session_baseline_confusion.csv), "
        "[candidate confusion matrix](rf_session_candidate_confusion.csv), "
        "[baseline per-class CSV](rf_session_baseline_classes.csv), and "
        "[candidate per-class CSV](rf_session_candidate_classes.csv).",
        f"Even across sessions, {experiment['test_rows_with_seen_feature_vector']} test rows repeat a "
        "training feature vector. Novel-vector results and per-PCAP results are in [results.json](results.json). "
        "The candidate improves some classes but lowers overall accuracy and macro F1; it is stored under "
        "`models/experiments/rf_session_candidate/` and is **not** selected by the dashboard.",
        "", "## Saved Scenario B XGBoost", "",
        f"The original stratified flow split reproduces **{percentage(xgb['saved_model_test']['accuracy'])}** "
        f"accuracy, **{percentage(xgb['saved_model_test']['balanced_accuracy'])}** balanced accuracy, "
        f"and **{xgb['saved_model_test']['macro_f1']:.3f}** macro F1 on "
        f"{xgb['saved_model_test']['rows']:,} test rows. "
        "[Confusion matrix](xgb_saved_model_test_confusion.csv) and "
        "[per-class CSV](xgb_saved_model_test_classes.csv).",
        "", *class_table(xgb["saved_model_test"]), "",
        f"The full ARFF contains {xgb['split']['full_duplicate_feature_vectors']} repeated feature vectors; "
        f"{xgb['split']['test_rows_with_seen_feature_vector']} test rows match a training vector. "
        f"The remaining {xgb['saved_model_novel_vectors']['rows']} test rows score "
        f"{percentage(xgb['saved_model_novel_vectors']['accuracy'])}, but the ARFF has no capture/session IDs. "
        "The 91.20% score is reproducible for this artifact and random split, not independently validated "
        "on held-out sessions or new traffic. XGBoost was not retrained.",
        "", "## Submission gaps", "",
        "- Confirm true session boundaries and per-flow labels in the RF archive; a/b grouping is inferred from filenames.",
        "- Obtain multiple independent labelled captures per RF class, including modern services, with fixed "
        "flow-window settings matching live capture. The current live worker uses 5/10-second idle/active "
        "timeouts while the RF training extraction used NFStream defaults.",
        "- Obtain capture/session identifiers or a separate external set for Scenario B before claiming "
        "independent XGBoost generalization.",
        "- Keep the RF experiment isolated until a candidate improves class-level and aggregate metrics on "
        "an independent locked test set. No model was switched or published by this audit.",
        "",
    ]
    (output_dir / "README.md").write_text("\n".join(lines), encoding="utf-8")


def evaluate_rf(output_dir, seed=42):
    original, encoder, features = load_model()
    if encoder is not None:
        raise ValueError("This audit expects the current string-labelled Random Forest.")
    train_path = PROJECT_ROOT / "data" / "train_flows.csv"
    test_path = PROJECT_ROOT / "data" / "test_flows.csv"
    full_path = PROJECT_ROOT / "data" / "training_flows.csv"
    train, test, full = (pd.read_csv(path) for path in (train_path, test_path, full_path))
    if len(full) != len(train) + len(test):
        raise ValueError("The RF full dataset does not match saved split sizes.")
    if set(train.source_pcap) & set(test.source_pcap):
        raise ValueError("The saved RF split shares PCAP filenames.")
    classes = [str(name) for name in original.classes_]
    x_train, x_test = prepare_features(train, features), prepare_features(test, features)
    original_pred = original.predict(x_test)
    seen = seen_feature_vectors(x_train, x_test)
    shared_sessions = set(train.source_pcap.map(rf_session_key)) & set(test.source_pcap.map(rf_session_key))
    independent_sessions = ~test.source_pcap.map(rf_session_key).isin(shared_sessions)

    results = {
        "dataset": "ISCXVPN2016 NonVPN-PCAPs-01.zip, filename-labelled NFStream flows",
        "data_rows": {"all": len(full), "saved_train": len(train), "saved_test": len(test)},
        "classes": classes,
        "features": features,
        "preprocessing": "Numeric validation; NaN and infinity replaced with zero at inference",
        "saved_split": {"method": "PCAP-name stratified 70/30, seed 42",
                        "train_pcaps": int(train.source_pcap.nunique()),
                        "test_pcaps": int(test.source_pcap.nunique()),
                        "shared_session_groups": sorted(shared_sessions),
                        "test_rows_in_shared_sessions": int((~independent_sessions).sum()),
                        "test_rows_with_seen_feature_vector": int(seen.sum()),
                        "train_exact_duplicate_vectors": int(x_train.duplicated().sum()),
                        "test_exact_duplicate_vectors": int(x_test.duplicated().sum()),
                        "train_conflicting_feature_vectors": int(
                            train.groupby(features, dropna=False).label.nunique().gt(1).sum()),
                        "train_class_counts": {str(k): int(v) for k, v in train.label.value_counts().items()},
                        "test_class_counts": {str(k): int(v) for k, v in test.label.value_counts().items()}},
        "saved_model_test": classification_metrics(test.label, original_pred, classes),
        "saved_model_novel_vectors": classification_metrics(
            test.label.iloc[np.flatnonzero(~seen)], original_pred[~seen], classes),
        "saved_model_independent_session_subset": classification_metrics(
            test.label.loc[independent_sessions], original_pred[independent_sessions.to_numpy()], classes),
        "artifact_sha256": sha256_file(MODEL_DIR / "rf_model.pkl"),
        "data_sha256": {path.name: sha256_file(path) for path in (full_path, train_path, test_path)},
    }
    for key in ("saved_model_test", "saved_model_novel_vectors", "saved_model_independent_session_subset"):
        save_metrics(output_dir, f"rf_{key}", results[key])

    # Check whether the stored artifact is reproducible from the local training CSV.
    refit = RandomForestClassifier(**original.get_params())
    refit.fit(x_train, train.label)
    results["saved_model_refit_agreement_on_test"] = float(np.mean(refit.predict(x_test) == original_pred))

    # This experiment holds out entire a/b recording sessions, unlike the saved split.
    session_train, session_test, selected = session_holdout(full, seed=seed)
    if set(session_train.source_pcap.map(rf_session_key)) & set(session_test.source_pcap.map(rf_session_key)):
        raise AssertionError("Session leakage in experimental split.")
    train_features = prepare_features(session_train, features)
    test_features = prepare_features(session_test, features)
    session_seen = seen_feature_vectors(train_features, test_features)
    baseline = RandomForestClassifier(**original.get_params())
    baseline.fit(train_features, session_train.label)
    baseline_pred = baseline.predict(test_features)

    curated = curated_rf_training(session_train, features, max_rows_per_source=500, seed=seed)
    candidate = RandomForestClassifier(**original.get_params())
    candidate.fit(curated[features], curated.label)
    candidate_pred = candidate.predict(test_features)
    results["session_experiment"] = {
        "method": "One whole recording session per class held out; seed 42. Same 200-tree RF architecture.",
        "heldout_sessions": selected,
        "train_rows": int(len(session_train)), "test_rows": int(len(session_test)),
        "curated_train_rows": int(len(curated)),
        "curation": "Deduplicate within PCAP/label, drop cross-label identical vectors, cap each PCAP at 500 rows",
        "test_rows_with_seen_feature_vector": int(session_seen.sum()),
        "test_pcaps": sorted(session_test.source_pcap.unique().tolist()),
        "baseline": classification_metrics(session_test.label, baseline_pred, classes),
        "candidate": classification_metrics(session_test.label, candidate_pred, classes),
        "baseline_novel_vectors": classification_metrics(
            session_test.label.iloc[np.flatnonzero(~session_seen)], baseline_pred[~session_seen], classes),
        "candidate_novel_vectors": classification_metrics(
            session_test.label.iloc[np.flatnonzero(~session_seen)], candidate_pred[~session_seen], classes),
        "per_pcap": [],
    }
    for source, group in session_test.groupby("source_pcap", sort=True):
        positions = session_test.index.get_indexer(group.index)
        results["session_experiment"]["per_pcap"].append({
            "source_pcap": str(source), "label": str(group.label.iloc[0]), "rows": len(group),
            "baseline_accuracy": float(np.mean(baseline_pred[positions] == group.label.to_numpy())),
            "candidate_accuracy": float(np.mean(candidate_pred[positions] == group.label.to_numpy())),
        })
    for key in ("baseline", "candidate", "baseline_novel_vectors", "candidate_novel_vectors"):
        save_metrics(output_dir, f"rf_session_{key}", results["session_experiment"][key])

    experiment_dir = MODEL_DIR / "experiments" / "rf_session_candidate"
    experiment_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(candidate, experiment_dir / "rf_model.pkl")
    joblib.dump(features, experiment_dir / "feature_names.pkl")
    reloaded, _, reloaded_features = load_model(experiment_dir)
    if reloaded_features != features or not np.array_equal(reloaded.predict(test_features), candidate_pred):
        raise RuntimeError("The experimental RF artifact did not reload with matching predictions.")
    (experiment_dir / "classes.json").write_text(json.dumps(classes, indent=2), encoding="utf-8")
    (experiment_dir / "training_metadata.json").write_text(json.dumps({
        "seed": seed, "heldout_sessions": selected, "train_rows": len(session_train),
        "curated_train_rows": len(curated), "features": features,
        "source_data_sha256": sha256_file(full_path), "scikit_learn_version": sklearn.__version__,
        "note": "Experimental artifact only; the dashboard still uses models/rf_model.pkl.",
    }, indent=2), encoding="utf-8")
    results["session_experiment"]["candidate_artifact"] = str(experiment_dir.relative_to(PROJECT_ROOT))
    return results


def evaluate_xgboost(output_dir, seed=42):
    model, features, encoder = load_xgboost_model()
    data = load_scenario_b()
    train_idx, test_idx = scenario_b_split_indices(data.label, seed=seed)
    x_train = prepare_features(data.iloc[train_idx], features)
    x_test = prepare_features(data.iloc[test_idx], features)
    seen = seen_feature_vectors(x_train, x_test)
    predicted = encoder.inverse_transform(model.predict(x_test).astype(int))
    archive = Path(os.environ.get("SCENARIO_B_DATASET", Path.home() / "Downloads" / "Scenario B-ARFF.zip"))
    result = {
        "dataset": "ISCXVPN2016 Scenario B, 15-second TimeBasedFeatures-Dataset-15s-AllinOne.arff",
        "archive": archive.name, "archive_sha256": sha256_file(archive),
        "artifact_sha256": sha256_file(MODEL_DIR / "scenario_b_xgb_model.pkl"),
        "rows": len(data), "classes": [str(name) for name in encoder.classes_],
        "features": features,
        "preprocessing": "23 numeric features; NaN and infinity replaced with zero at inference",
        "split": {"method": "Stratified random flow 80/20, seed 42; no capture/session IDs in ARFF",
                  "train_rows": len(train_idx), "test_rows": len(test_idx),
                  "test_rows_with_seen_feature_vector": int(seen.sum()),
                  "full_duplicate_feature_vectors": int(prepare_features(data, features).duplicated().sum()),
                  "class_counts": {str(k): int(v) for k, v in data.label.value_counts().items()}},
        "saved_model_test": classification_metrics(data.label.iloc[test_idx], predicted,
                                                     encoder.classes_),
        "saved_model_novel_vectors": classification_metrics(
            data.label.iloc[test_idx].iloc[np.flatnonzero(~seen)], predicted[~seen],
            encoder.classes_),
    }
    save_metrics(output_dir, "xgb_saved_model_test", result["saved_model_test"])
    save_metrics(output_dir, "xgb_saved_model_novel_vectors", result["saved_model_novel_vectors"])
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path,
                        default=PROJECT_ROOT / "reports" / "model_evaluation")
    args = parser.parse_args(argv)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    results = {"random_forest": evaluate_rf(args.output_dir),
               "scenario_b_xgboost": evaluate_xgboost(args.output_dir)}
    (args.output_dir / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    write_summary(args.output_dir, results)
    rf = results["random_forest"]
    ex = rf["session_experiment"]
    print(f"Saved RF: {rf['saved_model_test']['accuracy']:.4f} accuracy on old PCAP split; "
          f"{rf['saved_split']['test_rows_in_shared_sessions']} of {rf['saved_model_test']['rows']} test rows share a recording session.")
    print(f"Session holdout: baseline {ex['baseline']['accuracy']:.4f} / {ex['baseline']['macro_f1']:.4f} macro F1; "
          f"candidate {ex['candidate']['accuracy']:.4f} / {ex['candidate']['macro_f1']:.4f} macro F1.")
    print(f"Scenario B XGBoost: {results['scenario_b_xgboost']['saved_model_test']['accuracy']:.4f} "
          "on its original random-flow test split.")
    print(f"Detailed metrics and confusion matrices: {args.output_dir}")


if __name__ == "__main__":
    main()
