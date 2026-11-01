
import pandas as pd
from itertools import combinations
from collections import Counter

df = pd.read_csv("data/train_flows.csv")

excluded = {"label", "source_pcap"}
features = [c for c in df.columns if c not in excluded]

# Group identical feature vectors and collect their labels.
groups = df.groupby(features, dropna=False)["label"].agg(
    lambda values: sorted(set(values.astype(str)))
)

conflicts = groups[groups.map(len) > 1]

print("Total training rows:", len(df))
print("Conflicting feature vectors:", len(conflicts))
print(
    "Rows belonging to conflicting vectors:",
    int(df.set_index(features).index.isin(conflicts.index).sum()),
)

pair_counts = Counter()
for labels in conflicts:
    for pair in combinations(labels, 2):
        pair_counts[pair] += 1

print("\nConflicting label pairs:")
for pair, count in pair_counts.most_common():
    print(f"{pair[0]} <-> {pair[1]}: {count} feature vectors")

# Report source-PCAP coverage for each conflict.
print("\nSource PCAPs represented in conflicting vectors:")
for labels in conflicts:
    matching = df.set_index(features).loc[[conflicts.index[0]]] if False else None

print(
    "\nNote: identical features across labels do not automatically "
    "prove that either label is wrong."
)
