from pathlib import Path
import pandas as pd


DATA = [
    ("aim_chat_3a.pcap", "AIM_Chat", 45),
    ("aim_chat_3b.pcap", "AIM_Chat", 325),
    ("AIMchat1.pcapng", "AIM_Chat", 29),
    ("AIMchat2.pcapng", "AIM_Chat", 32),

    ("email1a.pcap", "Email", 3863),
    ("email1b.pcap", "Email", 3882),
    ("email2a.pcap", "Email", 335),
    ("email2b.pcap", "Email", 282),

    ("facebook_audio1a.pcap", "Facebook_Audio", 181),
    ("facebook_audio1b.pcapng", "Facebook_Audio", 56),
    ("facebook_audio2a.pcap", "Facebook_Audio", 284),
    ("facebook_audio2b.pcapng", "Facebook_Audio", 46),
    ("facebook_audio3.pcapng", "Facebook_Audio", 386),
    ("facebook_audio4.pcapng", "Facebook_Audio", 104949),

    ("facebook_chat_4a.pcap", "Facebook_Chat", 71),
    ("facebook_chat_4b.pcap", "Facebook_Chat", 323),
    ("facebookchat1.pcapng", "Facebook_Chat", 36),
    ("facebookchat2.pcapng", "Facebook_Chat", 27),
    ("facebookchat3.pcapng", "Facebook_Chat", 69),

    ("facebook_video1a.pcap", "Facebook_Video", 189),
    ("facebook_video1b.pcapng", "Facebook_Video", 20),
    ("facebook_video2a.pcap", "Facebook_Video", 240),
    ("facebook_video2b.pcapng", "Facebook_Video", 46),
]


def main():
    df = pd.DataFrame(
        DATA,
        columns=["pcap_file", "label", "flow_count"]
    )

    output_dir = Path("data")
    output_dir.mkdir(exist_ok=True)

    output_file = output_dir / "dataset_summary.csv"

    df.to_csv(output_file, index=False)

    print("=" * 60)
    print("DATASET SUMMARY")
    print("=" * 60)

    print("\nFlows by class:")
    print(
        df.groupby("label")["flow_count"]
        .sum()
        .sort_values(ascending=False)
    )

    print("\nTotal flows:", df["flow_count"].sum())
    print("Total PCAP files:", len(df))

    print(f"\nSaved to: {output_file}")


if __name__ == "__main__":
    main()