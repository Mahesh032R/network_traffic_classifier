import os
import zipfile
import tempfile
from pathlib import Path

import pandas as pd
from nfstream import NFStreamer


DATASET_ZIP = Path(
    r"C:\Users\mr204\Downloads\NonVPN-PCAPs-01.zip"
)

OUTPUT_FILE = Path("data/training_flows.csv")


EXCLUDED_FEATURES = {
    "id",
    "expiration_id",
    "src_ip",
    "src_mac",
    "src_oui",
    "src_port",
    "dst_ip",
    "dst_mac",
    "dst_oui",
    "dst_port",
    "bidirectional_first_seen_ms",
    "bidirectional_last_seen_ms",
    "src2dst_first_seen_ms",
    "src2dst_last_seen_ms",
    "dst2src_first_seen_ms",
    "dst2src_last_seen_ms",
    "application_name",
    "application_category_name",
    "application_is_guessed",
    "application_confidence",
    "requested_server_name",
    "client_fingerprint",
    "server_fingerprint",
    "user_agent",
    "content_type",
}


def get_label(filename):
    name = filename.lower()

    if name.startswith(("aim_chat", "aimchat")):
        return "AIM_Chat"

    if name.startswith("email"):
        return "Email"

    if name.startswith("facebook_audio"):
        return "Facebook_Audio"

    if name.startswith(("facebook_chat", "facebookchat")):
        return "Facebook_Chat"

    if name.startswith("facebook_video"):
        return "Facebook_Video"

    return "Unknown"


def build_dataset():

    if not DATASET_ZIP.exists():
        raise FileNotFoundError(
            f"Dataset not found: {DATASET_ZIP}"
        )

    OUTPUT_FILE.parent.mkdir(exist_ok=True)

    all_frames = []

    with zipfile.ZipFile(DATASET_ZIP, "r") as archive:

        files = [
            name
            for name in archive.namelist()
            if name.lower().endswith((".pcap", ".pcapng"))
        ]

        print("=" * 60)
        print("BUILDING REAL TRAINING DATASET")
        print("=" * 60)
        print(f"PCAP files: {len(files)}")
        print()

        for index, filename in enumerate(files, start=1):

            label = get_label(filename)

            print(
                f"[{index:02d}/{len(files)}] "
                f"{filename} -> {label}"
            )

            suffix = Path(filename).suffix

            with tempfile.NamedTemporaryFile(
                suffix=suffix,
                delete=False
            ) as temp_file:

                temp_path = temp_file.name
                temp_file.write(archive.read(filename))

            try:

                streamer = NFStreamer(
                    source=temp_path,
                    statistical_analysis=True
                )

                df = streamer.to_pandas()

                if df.empty:
                    print("       WARNING: No flows extracted")
                    continue

                feature_columns = [
                    column
                    for column in df.columns
                    if column not in EXCLUDED_FEATURES
                ]

                features = df[feature_columns].copy()

                # Add ground-truth label from the PCAP filename.
                features["label"] = label

                # Keep the source PCAP for traceability.
                features["source_pcap"] = filename

                all_frames.append(features)

                print(
                    f"       Flows added: {len(features)}"
                )

            finally:

                if os.path.exists(temp_path):
                    os.remove(temp_path)

    if not all_frames:
        raise RuntimeError("No training data was generated.")

    dataset = pd.concat(
        all_frames,
        ignore_index=True
    )

    dataset.to_csv(
        OUTPUT_FILE,
        index=False
    )

    print()
    print("=" * 60)
    print("DATASET BUILD COMPLETE")
    print("=" * 60)

    print(f"Total flows: {len(dataset)}")
    print(f"Features: {len(dataset.columns) - 2}")

    print("\nClass distribution:")
    print(dataset["label"].value_counts())

    print(f"\nSaved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    build_dataset()