# dashboard.py — Full Streamlit Dashboard
from sklearn.metrics import confusion_matrix, classification_report
import plotly.figure_factory as ff
from src.firewall import block_ip, unblock_ip, firewall_rule_exists
from src.blocklist import add_target, remove_target, list_blocked, list_events
from src.domain_blocker import (
    block_domain,
    unblock_domain,
    is_domain_blocked,
)
import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import joblib
import threading
import time
from nfstream import NFStreamer
import os
import sys
# ensure project `src` package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
from extract import extract_from_pcap_zip
from predict_xgboost import predict_xgboost_df
from datetime import datetime
import json
from src.scenario_b import FEATURE_NAMES

# ── PAGE CONFIG ──────────────────────────────
st.set_page_config(
    page_title="🔍 Traffic Classifier",
    layout="wide",
    page_icon="🌐"
)

# ── LOAD MODEL ───────────────────────────────
@st.cache_resource
def load_model():
    model = joblib.load("models/scenario_b_xgb_model.pkl")
    feature_names = joblib.load(
        "models/scenario_b_xgb_feature_names.pkl"
    )
    le = joblib.load(
        "models/scenario_b_xgb_label_encoder.pkl"
    )
    return model, le, feature_names

model, le, feature_names = load_model()

@st.cache_resource
def load_pcap_model():
    pcap_model = joblib.load("models/rf_model.pkl")
    pcap_features = joblib.load("models/feature_names.pkl")
    return pcap_model, pcap_features

pcap_model, pcap_feature_names = load_pcap_model()

# Load optional label->app-name mapping
label_map = {}
try:
    with open("models/label_map.json", "r", encoding="utf-8") as mf:
        label_map = json.load(mf)
except Exception:
    label_map = {}

# ── HEADER ───────────────────────────────────
st.title("🔍 AI-Powered Encrypted Traffic Classifier")
st.markdown("**Real-time network traffic classification using Machine Learning**")
st.divider()

# ── SIDEBAR ──────────────────────────────────
with st.sidebar:
    st.header("⚙️ Settings")
    mode = st.radio(
        "Mode",
        ["📂 Upload PCAP File", "📊 Upload ARFF/CSV", "🔴 Live Capture"]
        )
    confidence_threshold = st.slider(
        "Alert if confidence below:", 0.5, 1.0, 0.7
    )
    st.divider()
    st.info(
    "🧠 Model: XGBoost\n\n"
    "📊 Features: 23 Scenario B features\n\n"
    "🔒 Encrypted traffic classification"
)
if mode == "📊 Upload ARFF/CSV":
    uploaded = st.file_uploader(
        "Upload Scenario B ARFF or CSV",
        type=["arff", "csv"]
    )

    if uploaded is not None:
        try:
            if uploaded.name.lower().endswith(".csv"):
                input_df = pd.read_csv(uploaded)
            else:
                from scipy.io import arff
                import io

                arff_text = uploaded.getvalue().decode("utf-8", errors="replace")
                records, _ = arff.loadarff(io.StringIO(arff_text))
                input_df = pd.DataFrame(records)
                input_df = input_df.map(
                    lambda value: value.decode("utf-8")
                    if isinstance(value, bytes) else value
                )

            if "label" in input_df.columns:
                actual_labels = input_df["label"].astype(str)
                input_df = input_df.drop(columns=["label"])

            missing = [
                feature for feature in FEATURE_NAMES
                if feature not in input_df.columns
            ]

            if missing:
                st.error(f"Missing required features: {missing}")
            else:
                results = predict_xgboost_df(input_df[FEATURE_NAMES])
                st.success(f"Predicted {len(results)} flows")
                st.dataframe(results, use_container_width=True)

        except Exception as exc:
            st.error(f"Could not process the dataset: {exc}")


# ── MAIN CONTENT ─────────────────────────────
if mode == "📂 Upload PCAP File":
    uploaded = st.file_uploader("Upload a .pcap file", type=["pcap", "pcapng"])

    if uploaded:
        # Save uploaded file
        filename = uploaded.name
        tmp_path = "temp_upload"
        os.makedirs(tmp_path, exist_ok=True)
        out_path = os.path.join(tmp_path, filename)
        with open(out_path, "wb") as f:
            f.write(uploaded.read())

        st.info("⚙️ Extracting flows and classifying...")

        # Use ZIP extractor if a ZIP was uploaded, otherwise use NFStreamer for pcap
        try:
            if filename.lower().endswith(".zip"):
                df = extract_from_pcap_zip(out_path)
            else:
                streamer = NFStreamer(
                    source=out_path,
                    statistical_analysis=True
                )
                df = streamer.to_pandas()
        except Exception as e:
            st.exception(e)
            df = None

        if df is None or df.empty:
            st.error("No flows found in this file.")
        else:
            # Use centralized prediction helper which ensures features are present
            # PCAP files use the NFStream-compatible Random Forest model.
            missing = [
                feature for feature in pcap_feature_names
                if feature not in df.columns
            ]

            if missing:
                st.error(
                    f"PCAP is missing {len(missing)} required Random Forest features."
                )
                st.write("Missing features:", missing)
                st.stop()

            X = (
                df[pcap_feature_names]
                .apply(pd.to_numeric, errors="coerce")
                .replace([np.inf, -np.inf], np.nan)
                .fillna(0)
            )

            df_pred = df.copy()
            df_pred["pred_label"] = pcap_model.predict(X)
            df_pred["pred_confidence"] = (
                pcap_model.predict_proba(X).max(axis=1) * 100
            ).round(1)

            # Normalize column names used in UI
            df = df_pred.copy()
            df['Predicted App'] = df['pred_label']
            # Map numeric labels to human-friendly names when available
            if label_map:
                df['Predicted App'] = df['Predicted App'].astype(str).map(label_map).fillna(df['Predicted App'])
            df['Confidence'] = df['pred_confidence']
            df['⚠️ Alert'] = df['pred_confidence'] / 100.0 < confidence_threshold

            # ── METRICS ROW ──
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Total Flows", len(df))
            col2.metric("Unique Apps", df['Predicted App'].nunique())
            col3.metric("⚠️ Low Confidence", df['⚠️ Alert'].sum())
            col4.metric("Avg Confidence", f"{df['Confidence'].mean():.1f}%")

            st.divider()

            
            # ── CHARTS ROW ──
            c1, c2 = st.columns(2)

            with c1:
                st.subheader("📊 App Distribution")
                app_counts = df['Predicted App'].value_counts()
                fig = px.pie(
                    values=app_counts.values,
                    names=app_counts.index,
                    color_discrete_sequence=px.colors.qualitative.Set3
                )
                st.plotly_chart(fig, use_container_width=True)

            with c2:
                st.subheader("📈 Confidence per App")
                fig2 = px.box(
                    df, x='Predicted App', y='Confidence',
                    color='Predicted App'
                )
                st.plotly_chart(fig2, use_container_width=True)

            # ── ALERTS TABLE ──
            alerts = df[df['⚠️ Alert'] == True]
            if not alerts.empty:
                st.subheader(f"🚨 {len(alerts)} Suspicious / Low-Confidence Flows")
                st.dataframe(
                    alerts[['src_ip','dst_ip','src_port','dst_port',
                             'Predicted App','Confidence']],
                    use_container_width=True
                )

            # ── FULL TABLE ──
            st.subheader("📋 All Classified Flows")
            st.dataframe(
                df[['src_ip','dst_ip','protocol','bidirectional_bytes',
                    'Predicted App','Confidence']],
                use_container_width=True
            )

else:
    st.warning("⚠️ Live capture requires admin/root privileges.")
    st.info("Run: `sudo streamlit run dashboard.py`")
    st.code("sudo streamlit run dashboard.py", language="bash")
    st.divider()
st.subheader("Model Evaluation — Scenario B")

from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, classification_report
from src.scenario_b import load_scenario_b, FEATURE_NAMES

@st.cache_data
def get_evaluation_results():
    dataset = load_scenario_b()
    _, test = train_test_split(
        dataset,
        test_size=0.2,
        random_state=42,
        stratify=dataset["label"]
    )

    predictions = predict_xgboost_df(test[FEATURE_NAMES])
    actual = test["label"].astype(str)
    predicted = predictions["pred_label"].astype(str)
    classes = list(le.classes_)

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

    return np.matrix, report_df, classes, accuracy

matrix, report_df, classes, accuracy = get_evaluation_results()
st.metric("Overall Accuracy", f"{accuracy:.2%}")

st.write("Confusion Matrix — rows: actual, columns: predicted")
st.dataframe(
    pd.DataFrame(matrix, index=classes, columns=classes),
    use_container_width=True
)

st.write("Per-class Precision, Recall and F1-score")
metrics_df = report_df.loc[
    classes, ["precision", "recall", "f1-score", "support"]
].copy()

metrics_df.index.name = "Traffic Class"
st.dataframe(
    metrics_df.round(3),
    use_container_width=True
)

st.write("Macro and Weighted Averages")
st.dataframe(
    report_df.loc[["macro avg", "weighted avg"]].round(3),
    use_container_width=True
)

# ================= DOMAIN / IP BLOCKLIST =================
st.divider()
st.header("🛡️ Domain & IP Blocking")
st.caption(
    "Manage blocklist entries. Adding an entry here does not "
    "yet enforce a network block."
)

with st.form("add_block_target", clear_on_submit=True):
    target = st.text_input(
        "Domain or IP address",
        placeholder="example.com or 192.0.2.10"
    )
    submitted = st.form_submit_button("Add to blocklist")

    if submitted:
        try:
            success, message = add_target(target)
            if success:
                st.success(message)
            else:
                st.warning(message)
        except ValueError as exc:
            st.error(str(exc))

domains, ips = list_blocked()

col1, col2 = st.columns(2)

with col1:
    st.subheader(f"Blocked Domains ({len(domains)})")
    if domains:
        for domain in domains:
            left, right = st.columns([3, 1])
            left.write(domain)
            if right.button("Remove", key=f"remove_domain_{domain}"):
                success, message = remove_target(domain)
                st.success(message)
                st.rerun()
    else:
        st.info("No domains added.")

with col2:
    st.subheader(f"Blocked IPs ({len(ips)})")
    if ips:
        for ip in ips:
            left, right = st.columns([3, 1])
            left.write(ip)
            if right.button("Remove", key=f"remove_ip_{ip}"):
                success, message = remove_target(ip)
                st.success(message)
                st.rerun()
    else:
        st.info("No IP addresses added.")

with st.expander("Blocklist activity log"):
    events = list_events()
    if events:
        st.dataframe(
            pd.DataFrame(events[::-1]),
            use_container_width=True
        )
    else:
        st.info("No activity yet.")

st.divider()
st.header("🔥 Windows Firewall Enforcement")
st.warning(
    "Blocking an IP changes Windows Firewall rules. "
    "Only block an IP you are authorized to restrict."
)

domains, ips = list_blocked()

if not ips:
    st.info("Add an IP address to the blocklist first.")
else:
    selected_ip = st.selectbox(
        "Select an IP address",
        options=ips,
        key="firewall_selected_ip"
    )

    col_block, col_unblock, col_status = st.columns(3)

    with col_block:
        if st.button("Block IP", type="primary"):
            try:
                message = block_ip(selected_ip)
                st.success(message)
            except Exception as exc:
                st.error(
                    f"Could not block IP. Run Streamlit from an "
                    f"Administrator terminal if permission is denied. "
                    f"Details: {exc}"
                )

    with col_unblock:
        if st.button("Unblock IP"):
            try:
                message = unblock_ip(selected_ip)
                st.success(message)
            except Exception as exc:
                st.error(f"Could not remove firewall rule: {exc}")

    with col_status:
        if st.button("Check Firewall Status"):
            try:
                exists = firewall_rule_exists(selected_ip)
                if exists:
                    st.success("Firewall rule exists")
                else:
                    st.info("No matching firewall rule")
            except Exception as exc:
                st.error(str(exc))

st.divider()
st.header("🌐 Windows Domain Blocking")
st.warning(
    "This feature edits the Windows hosts file and requires "
    "Administrator privileges. It affects this laptop only. "
    "It does not block every subdomain or bypass method."
)

domains, _ = list_blocked()

if not domains:
    st.info("Add a domain to the blocklist first.")
else:
    selected_domain = st.selectbox(
        "Select a domain",
        options=domains,
        key="domain_block_selected"
    )
if selected_domain:
    if is_domain_blocked(selected_domain):
        st.success(f"Windows enforcement active for {selected_domain}")
    else:
        st.warning(f"{selected_domain} is in the app, but not enforced by Windows")
    col_block, col_unblock = st.columns(2)

    with col_block:
        if st.button("Block Domain", type="primary"):
            try:
                st.success(block_domain(selected_domain))
                st.cache_data.clear()
            except Exception as exc:
                st.error(
                    f"Could not update hosts file: {exc}. "
                    "Run Streamlit as Administrator if permission is denied."
                )

    with col_unblock:
        if st.button("Unblock Domain"):
            try:
                st.success(unblock_domain(selected_domain))
                st.cache_data.clear()
            except Exception as exc:
                st.error(f"Could not update hosts file: {exc}")
