
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GroupKFold
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    f1_score,
)

df = pd.read_csv("data/train_flows.csv")

excluded = {"label", "source_pcap"}
features = [c for c in df.columns if c not in excluded]

df = df.drop_duplicates(
    subset=["source_pcap", "label"] + features
).reset_index(drop=True)

X = (
    df[features]
    .apply(pd.to_numeric, errors="coerce")
    .replace([float("inf"), -float("inf")], float("nan"))
    .fillna(0)
)

y = df["label"].astype(str)
groups = df["source_pcap"]

cv = GroupKFold(n_splits=3)

for fold, (train_idx, val_idx) in enumerate(
    cv.split(X, y, groups), start=1
):
    model = RandomForestClassifier(
        n_estimators=200,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )

    model.fit(X.iloc[train_idx], y.iloc[train_idx])
    predictions = model.predict(X.iloc[val_idx])

    print(f"\nFOLD {fold}")
    print("-" * 40)
    print("Training PCAPs:", groups.iloc[train_idx].nunique())
    print("Validation PCAPs:", groups.iloc[val_idx].nunique())
    print("Validation rows:", len(val_idx))
    print(
        "Accuracy:",
        round(accuracy_score(y.iloc[val_idx], predictions), 4),
    )
    print(
        "Balanced accuracy:",
        round(
            balanced_accuracy_score(y.iloc[val_idx], predictions),
            4,
        ),
    )
    print(
        "Macro F1:",
        round(
            f1_score(
                y.iloc[val_idx],
                predictions,
                average="macro",
                zero_division=0,
            ),
            4,
        ),
    )
    print(
        "Validation classes:",
        sorted(y.iloc[val_idx].unique()),
    )
