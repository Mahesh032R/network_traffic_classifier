"""Validate uploaded format and model schema before dispatching analysis."""
import csv
import io
from pathlib import Path

import pandas as pd
from scipy.io import arff

from .scenario_b import FEATURE_NAMES

MAX_UPLOAD_BYTES = 200 * 1024 * 1024
PCAP_MAGIC = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
              b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"}
EXTENSIONS = {".pcap": "pcap", ".pcapng": "pcapng", ".zip": "zip",
              ".csv": "csv", ".arff": "arff"}


def detect_format(filename, data):
    if not isinstance(data, bytes) or not data:
        raise ValueError("The uploaded file is empty.")
    if len(data) > MAX_UPLOAD_BYTES:
        raise ValueError("The upload exceeds the 200 MB safety limit.")
    expected = EXTENSIONS.get(Path(filename).suffix.lower())
    if expected is None:
        raise ValueError("Use a PCAP, PCAPNG, ZIP, CSV, or ARFF file.")
    signature = data[:4]
    if signature in PCAP_MAGIC:
        actual = "pcap"
    elif signature == b"\x0a\x0d\x0d\x0a":
        actual = "pcapng"
    elif signature == b"PK\x03\x04":
        actual = "zip"
    else:
        try:
            preview = data[:65536].decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise ValueError("Unrecognized binary file; expected a capture or UTF-8 dataset.") from exc
        stripped = preview.lstrip("\ufeff \t\r\n").lower()
        actual = "arff" if stripped.startswith("@relation") and "@attribute" in stripped else "csv"
        if "\x00" in preview:
            raise ValueError("Unrecognized binary file; expected a capture or UTF-8 dataset.")
    if actual != expected:
        raise ValueError(f"File content is {actual.upper()}, but the filename says {expected.upper()}.")
    return actual


def read_dataset(data, file_format):
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("Dataset must be UTF-8 text.") from exc
    try:
        if file_format == "csv":
            header = next(csv.reader(io.StringIO(text)), [])
            if len(header) != len(set(header)):
                raise ValueError("CSV header contains duplicate column names.")
            frame = pd.read_csv(io.StringIO(text))
        elif file_format == "arff":
            records, _ = arff.loadarff(io.StringIO(text))
            frame = pd.DataFrame(records)
            for column in frame.select_dtypes(include=["object"]).columns:
                frame[column] = frame[column].map(
                    lambda value: value.decode("utf-8") if isinstance(value, bytes) else value)
        else:
            raise ValueError("Only CSV and ARFF are tabular datasets.")
    except Exception as exc:
        raise ValueError(f"Could not parse {file_format.upper()} dataset: {exc}") from exc
    if frame.empty:
        raise ValueError("The dataset is empty. Provide at least one flow.")
    if not frame.columns.is_unique:
        raise ValueError("The dataset has duplicate column names.")
    return frame


def route_schema(frame, rf_features):
    columns = set(frame.columns)
    rf = bool(rf_features) and set(rf_features).issubset(columns)
    scenario_b = set(FEATURE_NAMES).issubset(columns)
    if rf and scenario_b:
        raise ValueError("Dataset matches both model schemas; choose a dataset with one unambiguous feature set.")
    if rf:
        return "random_forest"
    if scenario_b:
        return "scenario_b"
    rf_missing = len(set(rf_features) - columns)
    scenario_missing = len(set(FEATURE_NAMES) - columns)
    raise ValueError(f"Unsupported dataset schema: missing {rf_missing} Random Forest and "
                     f"{scenario_missing} Scenario B required features.")
