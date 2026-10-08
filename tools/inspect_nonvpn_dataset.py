import os
import zipfile
import tempfile
from pathlib import Path

from nfstream import NFStreamer


DATASET_ZIP = Path(
    r"C:\Users\mr204\Downloads\NonVPN-PCAPs-01.zip"
)


def get_label(filename: str) -> str:
    """
    Convert the PCAP filename into the ground-truth application label.
    """
    name = filename.lower()

    if name.startswith("aim_chat") or name.startswith("aimchat"):
        return "AIM_Chat"

    if name.startswith("email"):
        return "Email"

    if name.startswith("facebook_audio"):
        return "Facebook_Audio"

    if name.startswith("facebook_video"):
        return "Facebook_Video"

    if name.startswith("facebook_chat") or name.startswith("facebookchat"):
        return "Facebook_Chat"

    return "Unknown"


def inspect_dataset():
    if not DATASET_ZIP.exists():
        raise FileNotFoundError(
            f"Dataset not found: {DATASET_ZIP}"
        )

    with zipfile.ZipFile(DATASET_ZIP, "r") as archive:

        files = [
            name
            for name in archive.namelist()
            if name.lower().endswith((".pcap", ".pcapng"))
        ]

        print("=" * 60)
        print("NONVPN DATASET INSPECTION")
        print("=" * 60)
        print(f"PCAP files found: {len(files)}")
        print()

        total_flows = 0

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

                flow_count = len(df)
                total_flows += flow_count

                print(f"       Flows: {flow_count}")

            finally:
                if os.path.exists(temp_path):
                    os.remove(temp_path)

        print()
        print("=" * 60)
        print(f"TOTAL FLOWS: {total_flows}")
        print("=" * 60)


if __name__ == "__main__":
    inspect_dataset()