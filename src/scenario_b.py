import zipfile
import os
from pathlib import Path
from io import StringIO

import pandas as pd


DATASET_ZIP = Path.home() / "Downloads" / "Scenario B-ARFF.zip"

ARFF_FILE = (
    "Scenario B-ARFF/"
    "TimeBasedFeatures-Dataset-15s-AllinOne.arff"
)


FEATURE_NAMES = [
    "duration",
    "total_fiat",
    "total_biat",
    "min_fiat",
    "min_biat",
    "max_fiat",
    "max_biat",
    "mean_fiat",
    "mean_biat",
    "flowPktsPerSecond",
    "flowBytesPerSecond",
    "min_flowiat",
    "max_flowiat",
    "mean_flowiat",
    "std_flowiat",
    "min_active",
    "mean_active",
    "max_active",
    "std_active",
    "min_idle",
    "mean_idle",
    "max_idle",
    "std_idle",
]


def load_scenario_b(dataset_zip=None):
    dataset_zip = Path(dataset_zip or os.environ.get("SCENARIO_B_DATASET", DATASET_ZIP))
    if not dataset_zip.is_file():
        raise FileNotFoundError(
            f"Scenario B dataset not found: {dataset_zip}. "
            "Set SCENARIO_B_DATASET to the Scenario B-ARFF.zip path."
        )

    with zipfile.ZipFile(dataset_zip, "r") as archive:
        if ARFF_FILE not in archive.namelist():
            raise ValueError(f"Scenario B archive must contain {ARFF_FILE}.")

        data = archive.read(
            ARFF_FILE
        ).decode(
            "utf-8",
            errors="replace"
        )

    data_start = data.lower().find("@data")

    if data_start == -1:
        raise ValueError(
            "ARFF @DATA section was not found."
        )

    body = data[data_start:]

    first_newline = body.find("\n")

    if first_newline == -1:
        raise ValueError(
            "ARFF data section is empty."
        )

    csv_data = body[first_newline + 1:]

    df = pd.read_csv(
        StringIO(csv_data),
        header=None,
        comment="%",
        skipinitialspace=True,
        na_values=["?"]
    )

    if df.shape[1] != 24:
        raise ValueError(
            f"Expected 24 columns, found {df.shape[1]}"
        )

    df.columns = FEATURE_NAMES + ["label"]
    if df.empty or df["label"].isna().any():
        raise ValueError("Scenario B dataset must contain flows with nonempty labels.")
    df["label"] = df["label"].astype(str).str.strip()

    return df


if __name__ == "__main__":

    df = load_scenario_b()

    print("=" * 60)
    print("SCENARIO B DATASET")
    print("=" * 60)

    print(f"Rows: {len(df)}")
    print(f"Features: {len(FEATURE_NAMES)}")

    print("\nClass distribution:")
    print(df["label"].value_counts())

    print("\nFirst 5 rows:")
    print(df.head().to_string(index=False))
