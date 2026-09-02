import sys
import os
# add project root to sys.path so `src` package can be imported
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src import extract, predict


def main(zip_path):
    print("Loading and extracting PCAP from:", zip_path)
    df = extract.extract_from_pcap_zip(zip_path)
    print("Flows extracted:", df.shape)
    out = predict.predict_df(df)
    print("Prediction summary:")
    print(out[['pred_label','pred_confidence']].head().to_string())
    print("Counts:")
    print(out['pred_label'].value_counts())


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python tools/run_extract_predict.py <zip-path>")
        sys.exit(1)
    main(sys.argv[1])
