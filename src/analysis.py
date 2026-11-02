"""Shared, model-safe transforms for uploaded flow files."""
import pandas as pd

from .file_routing import route_schema
from .predict import predict_with_model
from .predict_xgboost import predict_xgboost_df
from .process_attribution import UNKNOWN as UNKNOWN_PROCESS
from .service_identification import identify_service


SERVICE_FIELDS = ("application_name", "application_category_name", "application_is_guessed",
                  "application_confidence", "requested_server_name", "src_port", "dst_port")


def analyze_capture_frame(frame, rf_bundle, label_map=None):
    if not isinstance(frame, pd.DataFrame) or frame.empty:
        raise ValueError("No completed flows were found in the capture.")
    frame = frame.copy()
    evidence = [identify_service(**{field: row.get(field) for field in SERVICE_FIELDS})
                for row in frame.to_dict("records")]
    for key in evidence[0]:
        frame[key] = [item[key] for item in evidence]
    for key, value in UNKNOWN_PROCESS.items():
        frame[key] = value
    frame["Process Evidence"] = "Offline capture has no reliable local socket owner"
    if rf_bundle is not None:
        predicted = predict_with_model(frame, rf_bundle)
        labels = predicted["pred_label"].astype(str)
        frame["Predicted App"] = labels.map(label_map or {}).fillna(labels).astype(str)
        frame["Confidence"] = predicted["pred_confidence"]
        frame["Prediction Status"] = "Model estimate; application identity unverified"
    else:
        frame["Predicted App"] = "Not classified"
        frame["Confidence"] = None
        frame["Prediction Status"] = "Random Forest model unavailable"
    return frame


def analyze_dataset(frame, rf_bundle, label_map=None):
    schema = route_schema(frame, rf_bundle[2] if rf_bundle else [])
    if schema == "random_forest":
        if rf_bundle is None:
            raise RuntimeError("Random Forest model unavailable.")
        return schema, analyze_capture_frame(frame.drop(columns=["label"], errors="ignore"),
                                             rf_bundle, label_map)
    return schema, predict_xgboost_df(frame.drop(columns=["label"], errors="ignore"))
