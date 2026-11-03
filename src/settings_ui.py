"""Settings controls retained from the original dashboard."""
import os
import pandas as pd
import streamlit as st
from sklearn.metrics import confusion_matrix, classification_report
from sklearn.model_selection import train_test_split
from src.scenario_b import load_scenario_b
from src.blocking_ui import render_blocking_center
from src.model_utils import prepare_features, PROJECT_ROOT
from src.activity_ui import render_activity_settings
from src.streamlit_compat import alt_text


def render_settings(model, le, feature_names, detect_capture_interfaces, recent_flows=(), activity=None):
    st.caption("Adapter preferences, model evaluation, and local security controls.")
    with st.expander("Network adapter preference"):
        try:
            interfaces = detect_capture_interfaces()
            names = [item["name"] for item in interfaces]
            descriptions = {item["name"]: item["description"] for item in interfaces}
            if names:
                current = st.session_state.get("preferred_interface")
                index = names.index(current) if current in names else 0
                st.selectbox("Preferred Npcap adapter", names, index=index,
                             format_func=lambda name: descriptions[name], key="preferred_interface")
            else:
                st.info("No Npcap adapters detected.")
        except Exception as exc:
            st.warning(str(exc))
    with st.expander("Model evaluation and academic limitations"):
        st.markdown("**Saved Random Forest:** 56.72% on the recorded test PCAP split. Related recording segments overlap the split; this is not a generalization score.")
        st.markdown("**Scenario B XGBoost:** 91.20% on the recorded random-flow split. The data has no session identifiers; new-capture performance is unknown.")
        report = PROJECT_ROOT / "reports/model_evaluation"
        for prefix, title in (("rf_saved_model_test", "Random Forest"),
                              ("xgb_saved_model_test", "Scenario B XGBoost")):
            with st.expander(title + " recorded class metrics"):
                for suffix, caption in (("classes", "Per-class precision, recall, F1, support"),
                                        ("confusion", "Confusion matrix")):
                    path = report / f"{prefix}_{suffix}.csv"
                    if path.is_file():
                        st.caption(caption)
                        st.dataframe(pd.read_csv(path), width="stretch", hide_index=True,
                                     **alt_text(st.dataframe, f"{title} {caption.lower()}"))
        if st.button("Recalculate Scenario B recorded split", key="run_scenario_b_eval"):
            st.session_state["show_scenario_b_eval"] = True
        if st.session_state.get("show_scenario_b_eval"):
            st.subheader("Scenario B XGBoost evaluation: recorded flow split")
            st.caption("The metrics below reproduce a stratified random-flow split from historical Scenario B data. The ARFF lacks session identifiers, so this score does not guarantee performance on independent captures or live traffic.")

            @st.cache_data
            def get_evaluation_results(dataset_path):
                if model is None:
                    raise RuntimeError("Load the Scenario B XGBoost model before evaluating.")
                dataset = load_scenario_b(dataset_path)
                _, test = train_test_split(
                    dataset,
                    test_size=0.2,
                    random_state=42,
                    stratify=dataset["label"]
                )

                X_test = prepare_features(test, feature_names)
                predictions = le.inverse_transform(model.predict(X_test).astype(int))
                actual = test["label"].astype(str)
                predicted = pd.Series(predictions, index=test.index, dtype=str)
                classes = list(le.classes_)
                unknown = sorted(set(actual) - set(classes))
                if unknown:
                    raise ValueError(f"Evaluation labels are not in the trained model: {unknown}")

                matrix = confusion_matrix(actual, predicted, labels=classes)
                report = classification_report(
                    actual,
                    predicted,
                    labels=classes,
                    output_dict=True,
                    zero_division=0
                )
                accuracy = (actual == predicted).mean()
                report_df = pd.DataFrame(report).T

                return matrix, report_df, classes, accuracy

            try:
                matrix, report_df, classes, accuracy = get_evaluation_results(os.environ.get("SCENARIO_B_DATASET"))
            except Exception as exc:
                st.warning(f"Scenario B evaluation unavailable: {exc}")
            else:
                st.metric("Overall Accuracy", f"{accuracy:.2%}")

                st.write("Confusion Matrix — rows: actual, columns: predicted")
                st.dataframe(
                    pd.DataFrame(matrix, index=classes, columns=classes),
                    width="stretch"
                )

                st.write("Per-class Precision, Recall and F1-score")
                metrics_df = report_df.loc[
                    classes, ["precision", "recall", "f1-score", "support"]
                ].copy()

                metrics_df.index.name = "Traffic Class"
                st.dataframe(
                    metrics_df.round(3),
                    width="stretch"
                )

                st.write("Macro and Weighted Averages")
                st.dataframe(
                    report_df.loc[["macro avg", "weighted avg"]].round(3),
                    width="stretch"
                )

    render_blocking_center(recent_flows)

    with st.expander("Project information and troubleshooting"):
        st.markdown("Service names use nDPI or observed hostnames. Process names require a matching local socket; browser process attribution does not reveal a tab. Random Forest and Scenario B are separate historical tasks. Encrypted DNS, ECH, QUIC, and shared infrastructure can leave flows unknown or ambiguous.")
        st.markdown("For capture errors, verify Npcap, the chosen adapter, and permissions. For model errors, check the saved artifacts and Python dependencies. See README.md for reproducible setup and data requirements.")
    if activity is not None:
        render_activity_settings(activity)
