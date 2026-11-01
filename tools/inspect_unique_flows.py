
import pandas as pd

TRAIN_FILE = "data/train_flows.csv"

df = pd.read_csv(TRAIN_FILE)

excluded = {"label", "source_pcap"}
features = [c for c in df.columns if c not in excluded]

print("Original rows:", len(df))
print("Unique feature rows overall:", len(df[features].drop_duplicates()))

print("\nUnique rows per class:")
for label, group in df.groupby("label"):
    unique = group[features].drop_duplicates()
    print(
        f"{label}: {len(group)} total rows, "
        f"{len(unique)} unique feature rows"
    )

print("\nSource PCAPs per class:")
print(df.groupby("label")["source_pcap"].nunique())
