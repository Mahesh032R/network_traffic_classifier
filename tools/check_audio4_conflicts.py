
import pandas as pd

df = pd.read_csv("data/train_flows.csv")

features = [
    c for c in df.columns
    if c not in {"label", "source_pcap"}
]

# Find feature vectors that appear with more than one label.
label_counts = df.groupby(features, dropna=False)["label"].nunique()
conflicting_vectors = label_counts[label_counts > 1].index

# Mark every row whose feature vector is conflicting.
row_index = pd.MultiIndex.from_frame(df[features])
df["has_conflicting_labels"] = row_index.isin(conflicting_vectors)

print("Conflicting feature vectors:", len(conflicting_vectors))

print("\nConflicting rows by source PCAP:")
print(
    df[df["has_conflicting_labels"]]
    .groupby("source_pcap")
    .agg(
        rows=("label", "size"),
        labels=("label", lambda x: ", ".join(sorted(x.unique()))),
    )
    .sort_values("rows", ascending=False)
    .to_string()
)

print("\nConflicting rows by source PCAP and label:")
print(
    df[df["has_conflicting_labels"]]
    .groupby(["source_pcap", "label"])
    .size()
    .sort_values(ascending=False)
    .to_string()
)
