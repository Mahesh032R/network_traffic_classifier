# dashboard.py — Full Streamlit Dashboard
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
from predict import predict_df
from datetime import datetime
import json

# ── PAGE CONFIG ──────────────────────────────
st.set_page_config(
    page_title="🔍 Traffic Classifier",
    layout="wide",
    page_icon="🌐"
)

# ── LOAD MODEL ───────────────────────────────
@st.cache_resource
def load_model():
    model = joblib.load("models/rf_model.pkl")
    le    = joblib.load("models/label_encoder.pkl")
    feats = joblib.load("models/feature_names.pkl")
    return model, le, feats

model, le, feature_names = load_model()

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
    mode = st.radio("Mode", ["📂 Upload PCAP File", "🔴 Live Capture"])
    confidence_threshold = st.slider(
        "Alert if confidence below:", 0.5, 1.0, 0.7
    )
    st.divider()
    st.info("🧠 Model: Random Forest\n\n📊 Features: 80+\n\n🔐 No decryption needed")

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
            try:
                df_pred = predict_df(df)
            except Exception:
                # Fallback: predict inline using loaded model
                available = [f for f in feature_names if f in df.columns]
                X = df[available].replace([np.inf, -np.inf], np.nan).fillna(0)
                preds = model.predict(X)
                probs = model.predict_proba(X).max(axis=1)
                df_pred = df.copy()
                df_pred['pred_label'] = le.inverse_transform(preds)
                df_pred['pred_confidence'] = (probs * 100).round(1)

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