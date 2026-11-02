"""Network intelligence dashboard: observed services first, model estimates separate."""
import json
import tempfile
from pathlib import Path

import pandas as pd
import streamlit as st

from src import extract
from src.analysis import analyze_capture_frame, analyze_dataset
from src.capture import CaptureSession, list_capture_interfaces
from src.export_utils import flow_csv_bytes
from src.file_routing import detect_format, read_dataset
from src.model_utils import MODEL_DIR
from src.predict import load_model as load_rf_model
from src.predict_xgboost import load_xgboost_model
from src.settings_ui import render_settings
from src.blocking_ui import render_monitor_blocking


st.set_page_config(page_title="Network intelligence", page_icon=":material/network_check:",
                   layout="wide")


@st.cache_resource
def cached_rf_model():
    return load_rf_model()


@st.cache_resource
def cached_xgb_model():
    return load_xgboost_model()


@st.cache_data(ttl=30, max_entries=1)
def detect_capture_interfaces():
    return list_capture_interfaces()


@st.cache_data(max_entries=1)
def label_map():
    try:
        value = json.loads((MODEL_DIR / "label_map.json").read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def show_export(frame, key):
    st.caption("Exports may contain private IP addresses, hostnames, and process paths. Share only authorized data.")
    accepted = st.checkbox("I understand this CSV contains sensitive network metadata",
                           key=f"confirm_{key}_csv_export")
    st.download_button("Download flow report (CSV)", flow_csv_bytes(frame),
                       file_name=f"{key}_flows.csv", mime="text/csv", disabled=not accepted,
                       key=f"download_{key}_flows", on_click="ignore", icon=":material/download:")


def show_evidence_summary(frame):
    if "Detected Service" not in frame:
        return
    known = frame[~frame["Detected Service"].isin(["Unknown", "Ambiguous"])]
    st.caption("Services use observed hostname or nDPI evidence. A service is not proof of a particular executable or browser tab.")
    if known.empty:
        st.info("No service could be identified from the available hostname or protocol evidence.")
        return
    summary = (known.groupby("Detected Service", dropna=False)
               .agg(Connections=("Detected Service", "size"),
                    Bytes=("bidirectional_bytes", "sum"))
               .sort_values("Bytes", ascending=False).reset_index())
    st.bar_chart(summary.set_index("Detected Service")["Bytes"],
                 alt="Transferred bytes by detected service")
    st.dataframe(summary, width="stretch", hide_index=True,
                 alt="Detected services, connection counts, and transferred bytes")


previous_runtime = st.session_state.get("live_capture_runtime")
if isinstance(previous_runtime, dict):
    previous_runtime["stop_event"].set()
    previous_thread = previous_runtime["state"].get("thread")
    if previous_thread is not None and previous_thread.is_alive():
        st.session_state["legacy_capture_thread"] = previous_thread
if not isinstance(previous_runtime, CaptureSession):
    st.session_state["live_capture_runtime"] = CaptureSession()
live_capture = st.session_state["live_capture_runtime"]

with st.sidebar:
    st.markdown("### Network intelligence")
    section = st.radio("Section", ["Monitor", "Analyze file", "Settings"], key="section")
    st.caption("Observed evidence and historical model estimates are shown separately.")

st.html("""<style>
.ntc-hero {
  background: linear-gradient(105deg, #1536A6 0%, #1536A6 82%, #06B6D4 100%);
  border-radius: 12px;
  padding: 22px 28px;
  margin-bottom: 20px;
}
.ntc-hero h1 { color: #FFFFFF; font-size: clamp(1.5rem, 3vw, 2rem); line-height: 1.2; margin: 0 0 5px; }
.ntc-hero p { color: #FFFFFF; font-size: 0.96rem; line-height: 1.5; margin: 0; max-width: 58ch; }
.st-key-start_live_capture button:not(:disabled),
.st-key-open_block_dialog button:not(:disabled),
.st-key-apply_blocking_rules button:not(:disabled) {
  background: linear-gradient(105deg, #1536A6 0%, #1536A6 68%, #06B6D4 100%);
  border: 1px solid #1536A6;
  color: #FFFFFF;
  border-radius: 8px;
}
.st-key-start_live_capture button:focus-visible,
.st-key-open_block_dialog button:focus-visible,
.st-key-apply_blocking_rules button:focus-visible {
  outline: 3px solid #1536A6;
  outline-offset: 3px;
}
</style>""")
_headings = {
    "Monitor": ("Monitor", "Live service evidence, process observations, and recent connections."),
    "Analyze file": ("Analyze file", "Validated captures and flow datasets, with separate model estimates."),
    "Settings": ("Settings", "Adapter preferences, model evaluation, and device-local protection."),
}
_heading, _description = _headings[section]
st.html(f'<section class="ntc-hero"><h1>{_heading}</h1><p>{_description}</p></section>')
if section != "Monitor" and live_capture.snapshot()["running"]:
    if not live_capture.stop():
        st.error("Capture is still stopping. Wait for cleanup before starting another session.")


if section == "Monitor":
    st.caption("Live network activity from completed NFStream flows. Connect to an active Npcap adapter to begin.")

    @st.fragment(run_every="2s")
    def live_capture_view():
        live_capture.touch()
        snapshot = live_capture.snapshot()
        try:
            interfaces = detect_capture_interfaces()
        except Exception as exc:
            interfaces = []
            st.error(f"Network interfaces unavailable: {exc}")
        descriptions = {item["name"]: item["description"] for item in interfaces}
        choices = list(descriptions)
        preferred = st.session_state.get("preferred_interface")
        if "live_interface" not in st.session_state and preferred in choices:
            st.session_state["live_interface"] = preferred
        with st.container(border=True):
            left, right = st.columns([5, 1], vertical_alignment="bottom")
            with left:
                source = st.selectbox("Network interface", choices,
                                      format_func=lambda name: descriptions.get(name, name),
                                      key="live_interface", disabled=snapshot["running"],
                                      placeholder="No Npcap adapters found" if not choices else "Select an adapter")
            with right:
                if st.button("Refresh", key="refresh_live_interfaces", disabled=snapshot["running"],
                             icon=":material/refresh:"):
                    detect_capture_interfaces.clear()
                    st.rerun()
            start_col, stop_col = st.columns(2)
            with start_col:
                legacy = st.session_state.get("legacy_capture_thread")
                legacy_running = legacy is not None and legacy.is_alive()
                if st.button("Start monitoring", type="primary", key="start_live_capture",
                             disabled=snapshot["running"] or not source or legacy_running,
                             icon=":material/play_arrow:"):
                    try:
                        if source not in descriptions:
                            raise ValueError("Select a currently detected Npcap adapter.")
                        if not live_capture.start(source):
                            st.warning("The previous capture is still running or stopping.")
                    except Exception as exc:
                        st.error(f"Could not start monitoring: {exc}")
            with stop_col:
                if st.button("Stop monitoring", key="stop_live_capture",
                             disabled=not snapshot["running"], icon=":material/stop:"):
                    if not live_capture.stop():
                        st.error("Capture is still stopping. Wait for cleanup before restarting.")
        snapshot = live_capture.snapshot()
        if snapshot["error"]:
            st.error(snapshot["error"])
        if snapshot["warning"]:
            st.warning(snapshot["warning"])
        st.caption(f"Capture status: {snapshot['status']} · Completed flows appear after the capture window closes. Stop also runs when you leave Monitor.")
        with st.container(horizontal=True):
            st.metric("Captured flows", snapshot["total_flows"], border=True)
            st.metric("Detected services", len(snapshot["service_counts"]), border=True)
            st.metric("Unknown flows", snapshot["unknown_flows"], border=True)
            st.metric("Transferred data", f"{snapshot['bytes'] / 1_000_000:.2f} MB", border=True)

        recent = pd.DataFrame(snapshot["flows"])
        if recent.empty:
            st.info("Waiting for completed flows. Open a site or generate traffic on the selected adapter."
                    if snapshot["running"] else "Select an adapter and start monitoring to see network activity.")
        else:
            st.subheader("Website & application usage")
            count_rows = sorted(snapshot["service_counts"].items(), key=lambda pair: pair[1], reverse=True)
            usage_rows = sorted(snapshot["service_bytes"].items(), key=lambda pair: pair[1], reverse=True)
            chart_left, chart_right = st.columns(2)
            with chart_left:
                st.caption("Connections by detected service")
                if count_rows:
                    st.bar_chart(pd.DataFrame(count_rows, columns=["Service", "Connections"]).set_index("Service"),
                                 alt="Connections by evidence-based detected service")
                else:
                    st.info("No identified services yet.")
            with chart_right:
                st.caption("Transferred bytes by service, including unresolved traffic")
                st.bar_chart(pd.DataFrame(usage_rows, columns=["Service", "Bytes"]).set_index("Service"),
                             alt="Transferred bytes by detected or unknown service")
            st.caption("Recent traffic trend · completed flows retained in this browser session")
            times = pd.to_datetime(recent["first_seen"], errors="coerce", utc=True).dt.floor("min")
            trend = recent.assign(Minute=times).dropna(subset=["Minute"]).groupby("Minute").size()
            if not trend.empty:
                st.line_chart(trend, alt="Recent completed flows by minute")

            activity = recent.copy()
            for column, default in (("Process Name", "Unknown Process"),
                                    ("Detected Hostname", "Unobserved"),
                                    ("Upload Bytes", None), ("Download Bytes", None)):
                if column not in activity:
                    activity[column] = default
            activity["Process Name"] = activity["Process Name"].fillna("Unknown Process")
            activity["Detected Hostname"] = activity["Detected Hostname"].fillna("Unobserved")
            activity["Upload Bytes"] = pd.to_numeric(activity["Upload Bytes"], errors="coerce")
            activity["Download Bytes"] = pd.to_numeric(activity["Download Bytes"], errors="coerce")
            overview = (activity.groupby(["Detected Service", "Process Name", "Detected Hostname",
                                          "Evidence Source", "Identification Status"],
                                         dropna=False)
                        .agg(Connections=("Detected Service", "size"),
                             Bytes=("bidirectional_bytes", "sum"),
                             Upload_Bytes=("Upload Bytes", lambda values: values.sum(min_count=1)),
                             Download_Bytes=("Download Bytes", lambda values: values.sum(min_count=1)),
                             Last_seen=("first_seen", "max"))
                        .sort_values("Bytes", ascending=False).reset_index().head(20))
            st.dataframe(overview, width="stretch", hide_index=True,
                         alt="Recent service and process activity with connection counts and directional usage")
            st.caption("Upload and download are shown only when an exact local socket match establishes flow direction. Other rows retain total bytes.")

    live_capture_view()
    render_monitor_blocking(live_capture.snapshot()["flows"])

    @st.fragment(run_every="2s")
    def recent_connections_view():
        snapshot = live_capture.snapshot()
        recent = pd.DataFrame(snapshot["flows"])
        if not recent.empty:
            st.subheader("Recent connections")
            query = st.text_input("Search service, process, hostname, or address", key="live_search",
                                  placeholder="Search recent connections")
            statuses = sorted(recent["Identification Status"].fillna("Unknown").unique())
            selected = st.multiselect("Identification status", statuses, key="live_status_filter")
            filtered = recent
            if selected:
                filtered = filtered[filtered["Identification Status"].isin(selected)]
            if query.strip():
                searchable = [column for column in ("Detected Service", "Process Name", "Detected Hostname",
                              "src_ip", "dst_ip") if column in filtered]
                mask = filtered[searchable].fillna("").astype(str).apply(
                    lambda column: column.str.contains(query.strip(), case=False, regex=False)).any(axis=1)
                filtered = filtered[mask]
            primary = ["first_seen", "Detected Service", "Process Name", "Detected Hostname",
                       "bidirectional_bytes", "Upload Bytes", "Download Bytes",
                       "Identification Status", "Evidence Source", "Unknown Reason"]
            st.dataframe(filtered.iloc[::-1].reindex(columns=primary), width="stretch", hide_index=True,
                         alt="Recent services, process observations, hostnames, bytes, and evidence")
            st.caption(f"Showing {len(filtered)} of {len(recent)} recent rows; {snapshot['total_flows']} completed flows total. Times are UTC.")
            with st.expander("Technical flow details and model estimates"):
                st.caption("The Random Forest estimates only five historical training classes. They do not verify a service or process identity.")
                detail = ["first_seen", "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
                          "bidirectional_duration_ms", "bidirectional_packets", "bidirectional_bytes",
                          "src2dst_bytes", "dst2src_bytes", "Process PID", "Process Executable",
                          "Process Evidence", "application_name", "application_category_name",
                          "application_is_guessed", "application_confidence", "requested_server_name",
                          "client_fingerprint", "server_fingerprint", "user_agent", "content_type",
                          "Detected Service", "DNS Query Service", "Identification Note",
                          "Predicted App", "Confidence",
                          "Prediction Status"]
                st.dataframe(filtered.iloc[::-1].reindex(columns=detail), width="stretch", hide_index=True,
                             alt="Technical endpoints, nDPI metadata, process evidence, and historical RF estimates")
                protocols = pd.DataFrame.from_dict(snapshot["protocols"], orient="index").rename_axis("Protocol").reset_index()
                st.dataframe(protocols, hide_index=True, alt="TCP, UDP, and other protocol totals")
                if snapshot["unknown_reasons"]:
                    st.dataframe(pd.DataFrame(sorted(snapshot["unknown_reasons"].items(),
                                                     key=lambda pair: pair[1], reverse=True),
                                              columns=["Unknown reason", "Flows"]), hide_index=True,
                                 alt="Reasons service identity could not be established")
            show_export(recent.iloc[::-1], "live")
        if snapshot["diagnostics"]:
            with st.expander("Capture diagnostics"):
                st.code("\n".join(snapshot["diagnostics"]), language="text")

    recent_connections_view()

elif section == "Analyze file":
    st.caption("One upload for PCAP, PCAPNG, ZIP, CSV, or ARFF. File content and feature schema choose the compatible pipeline.")
    uploaded = st.file_uploader("Upload a capture or flow dataset",
                                type=["pcap", "pcapng", "zip", "csv", "arff"], key="analysis_upload")
    if uploaded is None:
        st.info("Choose a file to inspect. Captures use NFStream; datasets require a saved model's exact feature schema.")
    else:
        with st.spinner("Validating and analyzing the uploaded file…"):
            try:
                payload = uploaded.getvalue()
                file_format = detect_format(uploaded.name, payload)
                try:
                    rf_bundle = cached_rf_model()
                except (OSError, RuntimeError, ValueError) as exc:
                    rf_bundle = None
                    st.warning(f"Random Forest model unavailable: {exc}")
                if file_format in {"pcap", "pcapng", "zip"}:
                    if extract.NFStreamer is None:
                        raise RuntimeError("NFStream is unavailable. Check the Python environment and Npcap.")
                    with tempfile.TemporaryDirectory(prefix="traffic_upload_") as folder:
                        source = Path(folder) / ("upload." + file_format)
                        source.write_bytes(payload)
                        if file_format == "zip":
                            frame = extract.extract_from_pcap_zip(source)
                        else:
                            frame = extract.NFStreamer(source=str(source), statistical_analysis=True,
                                                       n_dissections=32).to_pandas()
                    result = analyze_capture_frame(frame, rf_bundle, label_map())
                    pipeline = "NFStream capture · evidence-based services · separate Random Forest estimates"
                else:
                    frame = read_dataset(payload, file_format)
                    schema, result = analyze_dataset(frame, rf_bundle, label_map())
                    pipeline = ("Random Forest historical classes" if schema == "random_forest"
                                else "Scenario B XGBoost traffic categories")
            except Exception as exc:
                st.error(f"Could not analyze this file: {exc}")
            else:
                st.success(f"Analyzed {len(result)} flows with {pipeline}.")
                st.metric("Total flows", len(result), border=True)
                if "Detected Service" in result:
                    show_evidence_summary(result)
                    columns = ["Detected Service", "Process Name", "Detected Hostname",
                               "Identification Status", "Evidence Source", "Unknown Reason", "DNS Query Service",
                               "src_ip", "dst_ip", "bidirectional_bytes"]
                    st.dataframe(result.reindex(columns=columns), width="stretch", hide_index=True,
                                 alt="Uploaded capture service evidence and flow endpoints")
                else:
                    st.caption("These are historical model category estimates, not observed website or executable identities.")
                    st.dataframe(result, width="stretch", hide_index=True,
                                 alt="Model estimates for uploaded dataset")
                with st.expander("Advanced model estimates and all flow fields"):
                    st.caption("Random Forest and XGBoost serve different training tasks. Confidence is model output, not verified identity.")
                    st.dataframe(result, width="stretch", hide_index=True,
                                 alt="All uploaded flow fields and separate model estimates")
                show_export(result, "analysis")

else:
    try:
        xgb_model, xgb_features, encoder = cached_xgb_model()
    except (OSError, RuntimeError, ValueError) as exc:
        xgb_model, xgb_features, encoder = None, [], None
        st.warning(f"Scenario B model unavailable: {exc}")
    render_settings(xgb_model, encoder, xgb_features, detect_capture_interfaces,
                    live_capture.snapshot()["flows"])
