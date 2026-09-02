import pandas as pd
import os
import zipfile
import tempfile
from pathlib import Path

try:
    from nfstream import NFStreamer
except Exception:
    NFStreamer = None


def extract_from_csv(path):
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    df = pd.read_csv(path)
    return df


def extract_placeholder(n_rows=10, n_features=20):
    import numpy as np
    cols = [f"f{i}" for i in range(n_features)]
    data = np.random.randn(n_rows, n_features)
    df = pd.DataFrame(data, columns=cols)
    return df


def extract_from_pcap_zip(zip_path, pcap_filename=None, statistical_analysis=True):
    """Extract the first pcap/pcapng from a zip and return NFStreamer pandas DataFrame.

    If `pcap_filename` is provided, extract that file; otherwise extract the first
    file ending with .pcap or .pcapng.
    """
    zip_path = Path(zip_path)
    if not zip_path.exists():
        raise FileNotFoundError(zip_path)

    with zipfile.ZipFile(zip_path, "r") as z:
        candidates = [n for n in z.namelist() if n.lower().endswith((".pcap", ".pcapng"))]
        if not candidates:
            raise ValueError("No pcap/pcapng files found inside the zip")
        chosen = pcap_filename or candidates[0]
        tmpdir = tempfile.mkdtemp(prefix="pcap_extract_")
        extracted_path = Path(tmpdir) / Path(chosen).name
        with z.open(chosen) as zf, open(extracted_path, "wb") as outf:
            outf.write(zf.read())

    if NFStreamer is None:
        raise RuntimeError("NFStreamer (nfstream) is not available in this environment")

    streamer = NFStreamer(source=str(extracted_path), statistical_analysis=statistical_analysis)
    df = streamer.to_pandas()
    return df


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python src/extract.py <path-to-zip-or-csv>")
        sys.exit(1)
    path = sys.argv[1]
    if path.lower().endswith(".zip"):
        df = extract_from_pcap_zip(path)
        print("Extracted flows shape:", df.shape)
        print(df.head().to_string())
    elif path.lower().endswith(",csv") or path.lower().endswith(".csv"):
        df = extract_from_csv(path)
        print("CSV rows:", len(df))
        print(df.head().to_string())
    else:
        print("Unsupported file type. Provide a .zip (containing pcap) or .csv")
