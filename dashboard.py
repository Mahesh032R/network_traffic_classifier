# dashboard.py — Full Streamlit Dashboard
from sklearn.metrics import confusion_matrix, classification_report
from sklearn.model_selection import train_test_split
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
import os
import tempfile
from pathlib import Path
from src.extract import extract_from_pcap_zip, NFStreamer
from src.predict import load_model as load_rf_model
from src.predict_xgboost import predict_xgboost_df, load_xgboost_model
from src.model_utils import MODEL_DIR, prepare_features
import json
from src.scenario_b import load_scenario_b, FEATURE_NAMES
from src.capture import CaptureSession, list_capture_interfaces
from src.export_utils import flow_csv_bytes

# ── PAGE CONFIG ──────────────────────────────
st.set_page_config(
    page_title="🔍 Traffic Classifier",
    layout="wide",
    page_icon="🌐"
)

# ── LOAD MODEL ───────────────────────────────
@st.cache_resource
def load_model():
    model, feature_names, le = load_xgboost_model()
    return model, le, feature_names

try:
    model, le, feature_names = load_model()
except (OSError, RuntimeError, ValueError) as exc:
    model, le, feature_names = None, None, []
    st.error(f"Scenario B model unavailable: {exc}")

@st.cache_resource
def load_pcap_model():
    pcap_model, _, pcap_features = load_rf_model()
    return pcap_model, pcap_features

try:
    pcap_model, pcap_feature_names = load_pcap_model()
except (OSError, RuntimeError, ValueError) as exc:
    pcap_model, pcap_feature_names = None, []
    st.error(f"Random Forest model unavailable: {exc}")

# Load optional label->app-name mapping
label_map = {}
try:
    with (MODEL_DIR / "label_map.json").open("r", encoding="utf-8") as mf:
        label_map = json.load(mf)
    if not isinstance(label_map, dict):
        raise ValueError("Label map must be a JSON object.")
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
    "Live detected service: nDPI/hostname evidence.\n\n"
    "PCAP/live predicted class: historical Random Forest estimate.\n\n"
    "Scenario B CSV/ARFF: separate XGBoost traffic-category estimate."
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
                for column in input_df.select_dtypes(include=["object"]).columns:
                    input_df[column] = input_df[column].map(
                        lambda value: value.decode("utf-8")
                        if isinstance(value, bytes) else value
                    )

            if "label" in input_df.columns:
                input_df = input_df.drop(columns=["label"])

            missing = [
                feature for feature in FEATURE_NAMES
                if feature not in input_df.columns
            ]

            if missing:
                st.error(f"Missing required features: {missing}")
            else:
                results = predict_xgboost_df(input_df[FEATURE_NAMES])
                st.caption("Scenario B predicts broad historical traffic categories. This is a model estimate, not a verified live service.")
                st.success(f"Predicted {len(results)} flows")
                st.dataframe(results, width="stretch")

        except Exception as exc:
            st.error(f"Could not process the dataset: {exc}")



# ── LIVE CAPTURE STATE ──────────────────────────────────────────
# One controller per browser session; background code never calls Streamlit.
previous_runtime = st.session_state.get("live_capture_runtime")
if isinstance(previous_runtime, dict):
    previous_runtime["stop_event"].set()
    legacy_thread = previous_runtime["state"].get("thread")
    if legacy_thread is not None and legacy_thread.is_alive():
        st.session_state["legacy_capture_thread"] = legacy_thread
if not isinstance(previous_runtime, CaptureSession):
    st.session_state["live_capture_runtime"] = CaptureSession()
live_capture = st.session_state["live_capture_runtime"]
legacy_thread = st.session_state.get("legacy_capture_thread")
legacy_running = legacy_thread is not None and legacy_thread.is_alive()
if legacy_running:
    st.warning("A capture from the previous app version is stopping. Restart Streamlit before starting a new capture if it does not exit.")

# Switching to file analysis also releases the network adapter.
if mode != "🔴 Live Capture" and live_capture.snapshot()["running"]:
    if not live_capture.stop():
        st.error("Capture is still stopping. Wait before starting another session.")


@st.cache_data(ttl=30, max_entries=1)
def detect_capture_interfaces():
    return list_capture_interfaces()


# ── MAIN CONTENT ─────────────────────────────
if mode == "📂 Upload PCAP File":
    uploaded = st.file_uploader("Upload a PCAP or ZIP file", type=["pcap", "pcapng", "zip"])

    if uploaded:
        st.caption("PCAP Random Forest results are estimates of five historical training classes. They do not verify a contacted website or executable.")
        if pcap_model is None:
            st.error("Load the Random Forest model files before classifying PCAP flows.")
            st.stop()
        if NFStreamer is None:
            st.error("NFStream is unavailable. Check nfstream and the Windows Npcap installation.")
            st.stop()
        filename = uploaded.name

        st.info("⚙️ Extracting flows and classifying...")

        # Use ZIP extractor if a ZIP was uploaded, otherwise use NFStreamer for pcap
        try:
            # Close the upload before NFStream opens it (required on Windows).
            with tempfile.TemporaryDirectory(prefix="traffic_upload_") as tmp_path:
                out_path = Path(tmp_path) / ("upload" + Path(filename).suffix.lower())
                out_path.write_bytes(uploaded.getvalue())
                if filename.lower().endswith(".zip"):
                    df = extract_from_pcap_zip(out_path)
                else:
                    streamer = NFStreamer(source=str(out_path), statistical_analysis=True)
                    df = streamer.to_pandas()
        except Exception as e:
            st.error(f"Could not read the capture. Provide a valid PCAP/PCAPNG or ZIP: {e}")
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

            try:
                X = prepare_features(df, pcap_feature_names)
            except ValueError as exc:
                st.error(f"Invalid Random Forest features in PCAP: {exc}")
                st.stop()

            df_pred = df.copy()
            df_pred["pred_label"] = pcap_model.predict(X)
            df_pred["pred_confidence"] = (
                pcap_model.predict_proba(X).max(axis=1) * 100
            ).round(1)

            # Normalize column names used in UI
            df = df_pred.copy()
            df['Predicted App'] = df['pred_label'].astype(str)
            # Map numeric labels to human-friendly names when available
            if label_map:
                df['Predicted App'] = df['Predicted App'].map(label_map).fillna(df['Predicted App']).astype(str)
            df['Confidence'] = df['pred_confidence']
            df['⚠️ Alert'] = df['pred_confidence'] / 100.0 < confidence_threshold

            # ── METRICS ROW ──
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Total Flows", len(df))
            col2.metric("RF predicted classes", df['Predicted App'].nunique())
            col3.metric("⚠️ Low Confidence", df['⚠️ Alert'].sum())
            col4.metric("Avg Confidence", f"{df['Confidence'].mean():.1f}%")

            st.divider()

            
            # ── CHARTS ROW ──
            c1, c2 = st.columns(2)

            with c1:
                st.subheader("Random Forest training-class distribution")
                app_counts = df['Predicted App'].value_counts()
                fig = px.pie(
                    values=app_counts.values,
                    names=app_counts.index,
                    color_discrete_sequence=px.colors.qualitative.Set3
                )
                st.plotly_chart(fig, width="stretch")

            with c2:
                st.subheader("Random Forest confidence by training class")
                fig2 = px.box(
                    df, x='Predicted App', y='Confidence',
                    color='Predicted App'
                )
                st.plotly_chart(fig2, width="stretch")

            # ── ALERTS TABLE ──
            alerts = df[df['⚠️ Alert'] == True]
            if not alerts.empty:
                st.subheader(f"{len(alerts)} Low-confidence Random Forest estimates")
                st.dataframe(
                    alerts[['src_ip','dst_ip','src_port','dst_port',
                             'Predicted App','Confidence']],
                    width="stretch"
                )

            # ── FULL TABLE ──
            st.subheader("Random Forest estimates for all flows")
            st.dataframe(
                df[['src_ip','dst_ip','protocol','bidirectional_bytes',
                    'Predicted App','Confidence']],
                width="stretch"
            )

elif mode == "🔴 Live Capture":
    st.subheader("🔴 Live network traffic monitor")
    st.info("Detected service uses observed hostname or nDPI evidence. Unknown and Ambiguous mean the evidence is insufficient or conflicting. Random Forest output is a separate historical class estimate; neither identifies a Windows executable.")
    st.caption(
        "Choose an active Npcap adapter. Completed flow statistics usually appear "
        "after 5–10 seconds of traffic. Capturing stops when you leave this mode."
    )
    st.info(
        "If access is denied, relaunch Streamlit from an Administrator PowerShell. "
        "A disconnected dashboard stops its capture after 30 seconds."
    )

    @st.fragment(run_every="2s")
    def live_capture_view():
        live_capture.touch()
        snapshot = live_capture.snapshot()
        try:
            interfaces = detect_capture_interfaces()
        except Exception as exc:
            interfaces = []
            st.error(str(exc))
        descriptions = {item["name"]: item["description"] for item in interfaces}
        source = st.selectbox(
            "Npcap interface", options=list(descriptions),
            format_func=lambda name: f"{descriptions.get(name, name)} — {name}",
            key="live_interface", disabled=snapshot["running"],
            placeholder="No Npcap interfaces detected" if not interfaces else "Select an adapter",
        )
        if st.button("Refresh interfaces", key="refresh_live_interfaces", disabled=snapshot["running"]):
            detect_capture_interfaces.clear()
            st.rerun()

        start_col, stop_col = st.columns(2)
        with start_col:
            if st.button("▶ Start Live Capture", type="primary", key="start_live_capture",
                         disabled=snapshot["running"] or not source or legacy_running):
                try:
                    if source not in descriptions:
                        raise ValueError("Select a currently detected Npcap interface.")
                    if not live_capture.start(source):
                        st.warning("A capture session is already running or stopping.")
                except Exception as exc:
                    st.error(f"Could not start capture: {exc}")
        with stop_col:
            if st.button("■ Stop Live Capture", key="stop_live_capture", disabled=not snapshot["running"]):
                if not live_capture.stop():
                    st.error("Capture is still stopping. A new session cannot start until cleanup finishes.")

        snapshot = live_capture.snapshot()
        st.write(f"Capture status: **{snapshot['status']}**")
        if snapshot["interface"]:
            st.caption(f"Source: {snapshot['interface']}")
        if snapshot["error"]:
            st.error(snapshot["error"])
        if snapshot["warning"]:
            st.warning(snapshot["warning"])

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Captured flows", snapshot["total_flows"])
        m2.metric("Identified services", len(snapshot["service_counts"]))
        m3.metric("Unknown service flows", snapshot["unknown_flows"])
        m4.metric("Ambiguous service flows", snapshot["ambiguous_flows"])
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Packets in completed flows", f"{snapshot['packets']:,}")
        m2.metric("Bytes in completed flows", f"{snapshot['bytes']:,}")
        m3.metric("RF classified flows", snapshot["predicted_flows"])
        m4.metric("TCP / UDP flows", f"{snapshot['protocols']['TCP']['Flows']} / {snapshot['protocols']['UDP']['Flows']}")

        st.caption(
            "Detected services use observed hostnames or nDPI protocol evidence; resource "
            "hostnames and weaker nDPI results are marked heuristic. DNS lookups alone "
            "do not establish a visit. HTTPS, HTTP/3, QUIC, encrypted DNS, ECH, and "
            "shared CDNs can hide or obscure identity. Some services and executables "
            "cannot be identified without additional evidence. Random Forest estimates "
            "remain separate and cover only its historical training classes. A service "
            "hostname does not establish which executable or process opened the flow."
        )
        df_live = pd.DataFrame(snapshot["flows"])
        if df_live.empty:
            if snapshot["running"]:
                st.info("Waiting for completed flows. Generate traffic on the selected adapter.")
            else:
                st.info("Click Start Live Capture to begin monitoring.")
        else:
            low_confidence = pd.to_numeric(df_live["Confidence"], errors="coerce") < confidence_threshold * 100
            df_live.loc[low_confidence, "Prediction Status"] = "Low confidence estimate; identity unverified"
            with st.container(border=True):
                st.subheader("Why flows are Unknown")
                st.caption(
                    "Cumulative reasons for this capture session. 'Encrypted flow without hostname' "
                    "means nDPI saw TLS or QUIC but exposed no hostname; it does not prove ECH. "
                    "A DNS lookup alone does not prove a later connection."
                )
                reason_rows = sorted(snapshot["unknown_reasons"].items(),
                                     key=lambda item: item[1], reverse=True)
                st.dataframe(pd.DataFrame(reason_rows, columns=["Reason", "Flows"]),
                             hide_index=True, alt="Cumulative reasons service identity is unknown")
            stats = pd.DataFrame.from_dict(snapshot["protocols"], orient="index").rename_axis("Protocol").reset_index()
            service_counts = dict(snapshot["service_counts"])
            if snapshot["unknown_flows"]:
                service_counts["Unknown"] = snapshot["unknown_flows"]
            if snapshot["ambiguous_flows"]:
                service_counts["Ambiguous"] = snapshot["ambiguous_flows"]
            service_frame = pd.DataFrame(
                sorted(service_counts.items(), key=lambda item: item[1], reverse=True),
                columns=["Detected service", "Flows"],
            )
            usage_frame = pd.DataFrame(
                sorted(snapshot["service_bytes"].items(), key=lambda item: item[1], reverse=True),
                columns=["Detected service", "Bytes"],
            )
            st.subheader("Most contacted services")
            st.caption("Service totals include all completed flows in this capture session. Unknown includes DNS lookups without a verified connection.")
            chart1, chart2 = st.columns(2)
            with chart1:
                st.caption("A. Detected websites and services")
                st.plotly_chart(
                    px.bar(service_frame, x="Detected service", y="Flows"), width="stretch",
                    key="live_service_chart", alt="Detected services, unknown, and ambiguous completed flows",
                )
            with chart2:
                st.caption("Traffic usage by detected service")
                st.plotly_chart(
                    px.bar(usage_frame, x="Detected service", y="Bytes"), width="stretch",
                    key="live_service_usage_chart", alt="Completed flow bytes by detected service",
                )
            st.subheader("Traffic protocols and Random Forest training classes")
            chart1, chart2 = st.columns(2)
            with chart1:
                st.caption("TCP / UDP distribution")
                st.plotly_chart(
                    px.pie(stats, names="Protocol", values="Flows"), width="stretch",
                    key="live_protocol_chart", alt="TCP, UDP, and other completed flows in this capture session",
                )
            with chart2:
                st.caption("B. Random Forest predicted training classes (recent flows)")
                predicted = df_live[df_live["Confidence"].notna()]
                if not predicted.empty:
                    counts = predicted["Predicted App"].value_counts().rename_axis("Estimated class").reset_index(name="Flows")
                    st.plotly_chart(
                        px.bar(counts, x="Estimated class", y="Flows"), width="stretch",
                        key="live_rf_chart", alt="Random Forest predicted training classes for recent compatible flows",
                    )
            st.dataframe(stats, hide_index=True, alt="Cumulative protocol, packet, and byte totals")
            st.subheader("Recent flow details")
            display_columns = [
                "first_seen", "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
                "bidirectional_packets", "bidirectional_bytes", "Detected Hostname",
                "Detected Service", "Evidence Source", "Identification Status",
                "Identification Note", "Unknown Reason", "DNS Query Service", "application_name",
                "application_category_name", "application_is_guessed", "application_confidence",
                "requested_server_name",
                "Predicted App", "Confidence", "Prediction Status",
            ]
            st.dataframe(df_live.iloc[::-1].reindex(columns=display_columns), width="stretch", hide_index=True,
                         alt="Recent endpoints, service evidence, nDPI metadata, and separate Random Forest estimates")
            st.warning("Recent flows and CSV exports can contain private IP addresses, hostnames, and user agents. Share only data you are authorized to disclose.")
            export_confirmed = st.checkbox("I understand this CSV contains sensitive network metadata",
                                           key="confirm_live_csv_export")
            st.download_button(
                "Download recent flows as CSV", flow_csv_bytes(df_live.iloc[::-1]),
                file_name="live_service_flows.csv", mime="text/csv", key="download_live_service_flows",
                on_click="ignore", disabled=not export_confirmed,
            )
            st.caption("CSV includes additional nDPI fingerprints, user agent, and content type when observed; none proves a process identity.")
            st.caption(f"Showing {len(df_live)} of {snapshot['total_flows']} completed flows; up to 500 recent rows are retained. Times are UTC.")
        if snapshot["diagnostics"]:
            with st.expander("Capture diagnostics"):
                st.code("\n".join(snapshot["diagnostics"]), language="text")

    live_capture_view()
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
            width="stretch"
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
        with st.form("enforce_ip_form"):
            confirm_ip_block = st.checkbox(
                f"Confirm outbound Windows Firewall block for {selected_ip}",
                key=f"confirm_ip_block_{selected_ip}",
            )
            if st.form_submit_button("Block IP", type="primary", key="block_ip_submit"):
                if not confirm_ip_block:
                    st.error("Confirm the selected IP address before changing Windows Firewall.")
                else:
                    try:
                        st.success(block_ip(selected_ip, confirmed=True))
                    except Exception as exc:
                        st.error(
                            "Could not block IP. Run Streamlit from an Administrator "
                            f"terminal if permission is denied. Details: {exc}"
                        )

    with col_unblock:
        with st.form("remove_ip_rule_form"):
            confirm_ip_unblock = st.checkbox(
                f"Confirm removal of the managed firewall rule for {selected_ip}",
                key=f"confirm_ip_unblock_{selected_ip}",
            )
            if st.form_submit_button("Unblock IP", key="unblock_ip_submit"):
                if not confirm_ip_unblock:
                    st.error("Confirm the selected IP address before removing its rule.")
                else:
                    try:
                        st.success(unblock_ip(selected_ip))
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
selected_domain = None

if not domains:
    st.info("Add a domain to the blocklist first.")
else:
    selected_domain = st.selectbox(
        "Select a domain",
        options=domains,
        key="domain_block_selected"
    )
if selected_domain:
    try:
        if is_domain_blocked(selected_domain):
            st.success(f"Windows enforcement active for {selected_domain}")
        else:
            st.warning(f"{selected_domain} is in the app, but not enforced by Windows")
    except OSError as exc:
        st.error(f"Could not read the Windows hosts file: {exc}")
    col_block, col_unblock = st.columns(2)

    with col_block:
        with st.form("enforce_domain_form"):
            confirm_domain_block = st.checkbox(
                f"Confirm hosts-file block for {selected_domain}",
                key=f"confirm_domain_block_{selected_domain}",
            )
            if st.form_submit_button("Block Domain", type="primary", key="block_domain_submit"):
                if not confirm_domain_block:
                    st.error("Confirm the selected domain before changing the Windows hosts file.")
                else:
                    try:
                        st.success(block_domain(selected_domain, confirmed=True))
                        st.cache_data.clear()
                    except Exception as exc:
                        st.error(
                            f"Could not update hosts file: {exc}. "
                            "Run Streamlit as Administrator if permission is denied."
                        )

    with col_unblock:
        with st.form("remove_domain_rule_form"):
            confirm_domain_unblock = st.checkbox(
                f"Confirm removal of the managed hosts entry for {selected_domain}",
                key=f"confirm_domain_unblock_{selected_domain}",
            )
            if st.form_submit_button("Unblock Domain", key="unblock_domain_submit"):
                if not confirm_domain_unblock:
                    st.error("Confirm the selected domain before removing its hosts entry.")
                else:
                    try:
                        st.success(unblock_domain(selected_domain))
                        st.cache_data.clear()
                    except Exception as exc:
                        st.error(f"Could not update hosts file: {exc}")
