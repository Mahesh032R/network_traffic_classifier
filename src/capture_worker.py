"""Isolated NFStream entry point. Windows meter children never import Streamlit."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import threading

from .model_utils import MODEL_DIR
from .predict import load_model, predict_with_model
from .service_identification import identify_service


def process_flow(flow, model_bundle=None, label_map=None):
    """Keep observed endpoints/stats; classify only a complete RF feature vector."""
    fields = ("src_ip", "dst_ip", "src_port", "dst_port", "protocol",
              "bidirectional_packets", "bidirectional_bytes", "application_name",
              "application_category_name", "application_is_guessed",
              "application_confidence", "requested_server_name",
              "client_fingerprint", "server_fingerprint", "user_agent", "content_type")
    row = {name: getattr(flow, name, None) for name in fields}
    row["first_seen"] = datetime.now(timezone.utc).isoformat()
    row.update(identify_service(**{name: row[name] for name in (
        "application_name", "application_category_name", "application_is_guessed",
        "application_confidence", "requested_server_name", "src_port", "dst_port")}))
    row.update({"Predicted App": "Not classified", "Confidence": None,
                "Prediction Status": "Random Forest model unavailable"})
    if model_bundle is None:
        return row
    _, _, features = model_bundle
    missing = [feature for feature in features if not hasattr(flow, feature)]
    if missing:
        row["Prediction Status"] = "Incompatible flow; missing features: " + ", ".join(missing)
        return row
    values = {feature: getattr(flow, feature) for feature in features}
    absent = [feature for feature, value in values.items() if value is None]
    if absent:
        row["Prediction Status"] = "Incompatible flow; unavailable features: " + ", ".join(absent)
        return row
    try:
        import pandas as pd
        result = predict_with_model(pd.DataFrame([values], columns=features), model_bundle)
        label = str(result["pred_label"].iloc[0])
        row["Predicted App"] = str((label_map or {}).get(label, label))
        row["Confidence"] = float(result["pred_confidence"].iloc[0])
        row["Prediction Status"] = "Model estimate; application identity unverified"
    except Exception as exc:
        row["Prediction Status"] = f"Prediction unavailable: {exc}"
    return row


def emit(message):
    print(json.dumps(message, allow_nan=False), flush=True)


def run_capture(source, stop_event, emit_message=emit, streamer_factory=None, start_control=None):
    emit_message({"type": "diagnostic", "message": "Loading NFStream and the Random Forest artifacts."})
    if streamer_factory is None:
        from nfstream import NFStreamer
        streamer_factory = NFStreamer
    try:
        bundle = load_model()
    except Exception as exc:
        bundle = None
        emit_message({"type": "warning", "message": f"Random Forest unavailable: {exc}"})
    try:
        label_map = json.loads((MODEL_DIR / "label_map.json").read_text(encoding="utf-8"))
        if not isinstance(label_map, dict):
            label_map = {}
    except (OSError, ValueError):
        label_map = {}
    streamer = streamer_factory(source=source, statistical_analysis=True,
                                idle_timeout=5, active_timeout=10, n_meters=1,
                                n_dissections=32)
    # Initialize scientific libraries before starting background threads on
    # Windows. The supervisor can still cancel a stalled startup externally.
    if start_control is not None:
        start_control()
    emit_message({"type": "ready"})
    iterator = iter(streamer)
    for flow in iterator:
        if stop_event.is_set():
            try:
                iterator.throw(KeyboardInterrupt)
            except (StopIteration, KeyboardInterrupt):
                pass
            break
        emit_message({"type": "flow", "row": process_flow(flow, bundle, label_map)})


def _listen_for_stop(stop_event, control_file, parent_pid):
    import psutil
    # Keep stdin closed: sharing a blocking stdin pipe with Windows spawn can
    # stall meter startup. The unique control file belongs to this session only.
    while not control_file.exists() and psutil.pid_exists(parent_pid):
        if _finished.wait(0.1):
            return
    stop_event.set()
    if not _finished.wait(1):
        children = psutil.Process().children(recursive=True)
        for child in children:
            try:
                child.kill()
            except psutil.NoSuchProcess:
                pass
        psutil.wait_procs(children, timeout=1)
        os._exit(0)


_finished = threading.Event()


def main():
    from multiprocessing import freeze_support
    freeze_support()
    parser = argparse.ArgumentParser(description="NFStream capture worker")
    parser.add_argument("--source", required=True)
    parser.add_argument("--control-file", type=Path, required=True)
    parser.add_argument("--parent-pid", type=int, required=True)
    arguments = parser.parse_args()
    stop_event = threading.Event()
    try:
        run_capture(arguments.source, stop_event, start_control=lambda: threading.Thread(
            target=_listen_for_stop,
            args=(stop_event, arguments.control_file, arguments.parent_pid), daemon=True
        ).start())
        return 0
    except Exception as exc:
        emit({"type": "error", "message": (
            f"NFStream capture failed: {exc}. Check the selected Npcap adapter, "
            "Npcap driver/service, and Administrator permissions."
        )})
        return 1
    finally:
        _finished.set()


if __name__ == "__main__":
    sys.exit(main())
