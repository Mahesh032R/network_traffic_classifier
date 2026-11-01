# Model evaluation audit

Reproduce from the repository root with `.\.venv\Scripts\python.exe -B tools\evaluate_models.py`.
The command reads the existing models and datasets, retrains only Random Forest baselines and one isolated RF candidate, and writes this report plus CSV confusion matrices. It does not change the dashboard model.

## Data and method

Both datasets come from the [UNB ISCXVPN2016 VPN-nonVPN dataset](https://www.unb.ca/cic/datasets/vpn.html). They are different prediction tasks and their accuracies must not be compared as if they share a test set.

| Model | Local source | Rows | Classes | Features | Evaluation |
|---|---|---:|---:|---:|---|
| Saved RF | `NonVPN-PCAPs-01.zip`, 23 real PCAPs; labels assigned by filename | 115,716 | 5 | 61 | 114,764 train / 952 test, PCAP-name split; related a/b sessions overlap |
| Saved XGBoost | `Scenario B-ARFF.zip`, 15-second time features | 18,758 | 7 | 23 | 15,006 train / 3,752 test, stratified random-flow split (`random_state=42`) |

RF classes: AIM_Chat, Email, Facebook_Audio, Facebook_Chat, Facebook_Video.
XGBoost classes: BROWSING, CHAT, FT, MAIL, P2P, STREAMING, VOIP.
The 61 RF features are NFStream flow timing, packet/byte, protocol, and TCP-flag statistics; IPs, ports, hostnames, and nDPI names are excluded. The 23 XGBoost features are time-based Scenario B statistics. The exact ordered feature lists and SHA-256 hashes are in [results.json](results.json).
At inference both paths validate numeric features and replace NaN/infinity with zero. The local training CSVs have no missing or infinite feature values, so this does not alter the evaluated rows. The XGBoost training script used the raw 23 columns; its preprocessing policy should be documented explicitly before deployment to new data.

## Saved Random Forest

Accuracy **56.72%**, balanced accuracy **56.73%**, macro F1 **0.506** on 952 flows. [Confusion matrix](rf_saved_model_test_confusion.csv) and [per-class CSV](rf_saved_model_test_classes.csv).

| Class | Support | Precision | Recall | F1 |
|---|---:|---:|---:|---:|
| AIM_Chat | 45 | 0.268 | 0.244 | 0.256 |
| Email | 282 | 0.937 | 0.950 | 0.944 |
| Facebook_Audio | 340 | 0.530 | 0.129 | 0.208 |
| Facebook_Chat | 96 | 0.563 | 0.740 | 0.640 |
| Facebook_Video | 189 | 0.351 | 0.772 | 0.483 |

Refitting the saved RF configuration on `train_flows.csv` produced identical predictions on all 952 test rows (agreement 100.00%). This strongly supports the local real-PCAP training provenance; `extract_placeholder()` is a separate unused helper.
The saved split has 16 train PCAP filenames and 7 test PCAP filenames, but inferred a/b recording groups cross the split for 856 of 952 test flows. Another 444 test flows have an identical preprocessed feature vector in training. Only 96 test rows come from wholly absent inferred sessions, and those are all Facebook Chat, so the saved model has no independent five-class session test.
The training set has 110,271 repeated feature vectors and 174 feature vectors with conflicting labels. One Facebook Audio PCAP contributes 104,949 of 114,764 training flows. PCAP-level labels may include background traffic. The saved test result is therefore descriptive, not a reliable live-traffic accuracy claim.

## Session-level Random Forest experiment

The split groups each matching a/b PCAP pair as one inferred recording session and holds one session per class out with seed 42. Both models below use the same 61 features, 200-tree RF settings, and 1,618 test flows. The candidate uses only its training sessions, removes duplicate and contradictory vectors, and caps each source PCAP at 500 rows. This reduces its training set to 1,577 rows.

| Model | Accuracy | Balanced accuracy | Macro F1 |
|---|---:|---:|---:|
| Baseline retrained on grouped split | 36.34% | 48.96% | 0.341 |
| Curated candidate | 34.18% | 43.97% | 0.295 |

[Baseline confusion matrix](rf_session_baseline_confusion.csv), [candidate confusion matrix](rf_session_candidate_confusion.csv), [baseline per-class CSV](rf_session_baseline_classes.csv), and [candidate per-class CSV](rf_session_candidate_classes.csv).
Even across sessions, 602 test rows repeat a training feature vector. Novel-vector results and per-PCAP results are in [results.json](results.json). The candidate improves some classes but lowers overall accuracy and macro F1; it is stored under `models/experiments/rf_session_candidate/` and is **not** selected by the dashboard.

## Saved Scenario B XGBoost

The original stratified flow split reproduces **91.20%** accuracy, **88.75%** balanced accuracy, and **0.887** macro F1 on 3,752 test rows. [Confusion matrix](xgb_saved_model_test_confusion.csv) and [per-class CSV](xgb_saved_model_test_classes.csv).

| Class | Support | Precision | Recall | F1 |
|---|---:|---:|---:|---:|
| BROWSING | 1000 | 0.916 | 0.950 | 0.933 |
| CHAT | 417 | 0.860 | 0.794 | 0.825 |
| FT | 590 | 0.872 | 0.820 | 0.845 |
| MAIL | 148 | 0.850 | 0.919 | 0.883 |
| P2P | 386 | 0.834 | 0.938 | 0.883 |
| STREAMING | 191 | 0.895 | 0.806 | 0.848 |
| VOIP | 1020 | 0.996 | 0.985 | 0.991 |

The full ARFF contains 743 repeated feature vectors; 170 test rows match a training vector. The remaining 3582 test rows score 92.52%, but the ARFF has no capture/session IDs. The 91.20% score is reproducible for this artifact and random split, not independently validated on held-out sessions or new traffic. XGBoost was not retrained.

## Submission gaps

- Confirm true session boundaries and per-flow labels in the RF archive; a/b grouping is inferred from filenames.
- Obtain multiple independent labelled captures per RF class, including modern services, with fixed flow-window settings matching live capture. The current live worker uses 5/10-second idle/active timeouts while the RF training extraction used NFStream defaults.
- Obtain capture/session identifiers or a separate external set for Scenario B before claiming independent XGBoost generalization.
- Keep the RF experiment isolated until a candidate improves class-level and aggregate metrics on an independent locked test set. No model was switched or published by this audit.
