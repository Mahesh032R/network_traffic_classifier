import zipfile
from io import StringIO

import pandas as pd


DATASET_ZIP = r"C:\Users\mr204\Downloads\Scenario B-ARFF.zip"

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


def load_scenario_b():

    with zipfile.ZipFile(DATASET_ZIP, "r") as archive:

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
        header=None
    )

    if df.shape[1] != 24:
        raise ValueError(
            f"Expected 24 columns, found {df.shape[1]}"
        )

    df.columns = FEATURE_NAMES + ["label"]

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