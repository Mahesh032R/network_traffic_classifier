import joblib
import json
import os


def main(model_dir="models"):
    le_path = os.path.join(model_dir, "label_encoder.pkl")
    if not os.path.exists(le_path):
        raise FileNotFoundError(le_path)
    le = joblib.load(le_path)
    classes = getattr(le, 'classes_', None)
    if classes is None:
        raise RuntimeError("LabelEncoder has no classes_ attribute")

    mapping = {}
    for i, cls in enumerate(classes):
        mapping[str(cls)] = f"App_{i}"

    out_path = os.path.join(model_dir, "label_map.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(mapping, f, indent=2)

    print("Wrote label map to", out_path)


if __name__ == '__main__':
    main()
