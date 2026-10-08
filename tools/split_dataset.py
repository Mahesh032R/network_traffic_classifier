import pandas as pd
from sklearn.model_selection import train_test_split


INPUT_FILE = "data/training_flows.csv"
TRAIN_FILE = "data/train_flows.csv"
TEST_FILE = "data/test_flows.csv"


def main():

    df = pd.read_csv(INPUT_FILE)

    print("=" * 60)
    print("STRATIFIED PCAP-BASED TRAIN / TEST SPLIT")
    print("=" * 60)

    # Build a PCAP-level table.
    # Each PCAP belongs to exactly one application class.
    pcap_info = (
        df[["source_pcap", "label"]]
        .drop_duplicates()
        .reset_index(drop=True)
    )

    print(f"Total PCAP files: {len(pcap_info)}")

    print("\nPCAPs per class:")
    print(pcap_info["label"].value_counts())

    # Stratify the PCAPs by their application label.
    train_pcaps, test_pcaps = train_test_split(
        pcap_info["source_pcap"].tolist(),
        test_size=0.30,
        random_state=42,
        stratify=pcap_info["label"].tolist()
    )

    train_df = df[df["source_pcap"].isin(train_pcaps)].copy()
    test_df = df[df["source_pcap"].isin(test_pcaps)].copy()

    train_df.to_csv(TRAIN_FILE, index=False)
    test_df.to_csv(TEST_FILE, index=False)

    print(f"\nTraining PCAPs: {len(train_pcaps)}")
    print(f"Testing PCAPs:  {len(test_pcaps)}")

    print(f"\nTraining flows: {len(train_df)}")
    print(f"Testing flows:  {len(test_df)}")

    print("\nTraining class distribution:")
    print(train_df["label"].value_counts())

    print("\nTesting class distribution:")
    print(test_df["label"].value_counts())

    print("\nTraining PCAPs:")
    for pcap in train_pcaps:
        label = pcap_info.loc[
            pcap_info["source_pcap"] == pcap, "label"
        ].iloc[0]
        print(f"  {pcap} -> {label}")

    print("\nTesting PCAPs:")
    for pcap in test_pcaps:
        label = pcap_info.loc[
            pcap_info["source_pcap"] == pcap, "label"
        ].iloc[0]
        print(f"  {pcap} -> {label}")

    print("\nSaved:")
    print(f"  {TRAIN_FILE}")
    print(f"  {TEST_FILE}")


if __name__ == "__main__":
    main()