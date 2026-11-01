# Final project report: AI-Powered Encrypted Network Traffic Classifier

## Problem and objectives

Encrypted traffic hides payloads while leaving some flow and protocol metadata visible. This project demonstrates collection, conservative service identification, and two separate traffic classification tasks on Windows. It aims to show evidence and uncertainty clearly, rather than claim that a model prediction proves a website or executable identity.

## Architecture and technology

Windows 11 with Npcap supplies packets to NFStream in an isolated Python capture worker. The worker emits bounded flow records to the Streamlit dashboard. nDPI application metadata and observed hostnames feed a rule-based service identifier; unmatched and conflicting evidence remain Unknown or Ambiguous with reasons. A saved scikit-learn Random Forest separately estimates one of five historical application classes from 61 numeric flow features. Uploaded Scenario B CSV/ARFF data uses a saved XGBoost model with 23 time-based features to estimate one of seven traffic categories. The dashboard also supports offline PCAP/PCAPNG extraction, charts, recent-flow CSV export, a local blocklist, and separately confirmed Windows Firewall and hosts-file enforcement.

## Datasets and model evaluation

Both local archives derive from the [UNB ISCXVPN2016 dataset](https://www.unb.ca/cic/datasets/vpn.html), but support different prediction tasks. The Random Forest dataset contains 115,716 flows from 23 filename-labelled non-VPN PCAPs across AIM Chat, Email, Facebook Audio, Facebook Chat, and Facebook Video. The saved model's 16/7 PCAP-name train/test split scores **56.72% accuracy**, **56.73% balanced accuracy**, and **0.506 macro F1** on 952 test flows. Related recording segments cross that split for 856 test rows, and 444 test rows share an identical processed feature vector with training. It is therefore not an independent five-class session result.

A separate, inferred session-group split used 1,618 held-out flows. A freshly trained baseline scored **36.34% accuracy**, while a deduplicated, source-capped RF candidate scored **34.18%**. The candidate performed worse and remains isolated under ignored `models/experiments/`; the dashboard still loads the original saved RF. This comparison does not establish that the original model generalizes to modern services.

Scenario B has 18,758 labelled ARFF rows in seven categories: BROWSING, CHAT, FT, MAIL, P2P, STREAMING, and VOIP. The saved XGBoost model reproduces **91.20% accuracy**, **88.75% balanced accuracy**, and **0.887 macro F1** on 3,752 rows from its original stratified random-flow 80/20 split (`random_state=42`). The archive has no capture/session IDs, and 170 test rows have a feature vector also present in training. The 91.20% result is a reproducible recorded-split score, not an independent live-traffic guarantee. XGBoost was not retrained.

Per-class support, precision, recall, F1, confusion matrices, feature hashes, and reproducibility steps are in the [model audit](model_evaluation/README.md) and its CSV/JSON artifacts.

## Working features and limits

The dashboard selects a Npcap interface, starts and stops one background capture worker, updates completed-flow counts and charts, displays endpoints and nDPI/hostname evidence, and exports at most 500 recent flows. Service evidence, Unknown reasons, RF historical-class estimates, and Scenario B evaluation are presented separately. Domain and IP targets can be added to a local blocklist. Enforcement requires a target-specific confirmation, and managed firewall rules or hosts entries can be removed through Unblock actions.

Service coverage depends on observable nDPI and hostname metadata. HTTPS, QUIC/HTTP/3, encrypted DNS, ECH, shared CDNs, DNS-only observations, and missing server names can leave flows Unknown or Ambiguous. A contacted hostname does not identify the Windows executable, and a model confidence value is not calibrated proof. RF training flow settings differ from short live capture windows. Scenario B lacks a session-held-out evaluation. Neither model establishes production readiness.

## Demonstration and reproducibility

Follow the [Windows setup in README](../README.md#windows-11-setup-and-launch), then run `py -3.13 -m venv .venv`, `.\.venv\Scripts\python.exe -m pip install -r requirements.txt`, and `.\.venv\Scripts\python.exe -m streamlit run dashboard.py` in PowerShell. Select the active Npcap interface, Start Live Capture, generate a browser connection, inspect the hostname/service/evidence and separate RF estimate, export recent flows only to a private location, Stop, and Restart. Upload a suitable PCAP to show the offline RF path; upload Scenario B CSV/ARFF to show the separate XGBoost path and its recorded-split evaluation. Demonstrate a blocklist entry without enforcing it; explain confirmation and Unblock rollback rather than changing real firewall or hosts settings during a public demo.

Run `.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v` and `.\.venv\Scripts\python.exe -B tools\evaluate_models.py` to reproduce tests and model audit. The optional `TRAFFIC_TEST_PCAP` environment variable enables PCAP integration tests; the README gives commands. Physical Npcap capture, adapter permissions, and firewall/hosts enforcement must be checked separately on the demonstration machine.

## Release validation

On Windows 11/Python 3.13.3, **77 automated tests passed**, including two optional PCAPNG integrations. All **42 Python files** parsed; core imports, `pip check`, and Git whitespace checks passed. Headless Streamlit returned HTTP 200 for the health endpoint and root page. The offline capture worker processed **91 flows**, produced **91 RF estimates**, recorded Unknown reasons, and stopped cleanly. A bounded **15-second physical Npcap capture** on the local Wi-Fi adapter processed **19 flows** (18 TCP, one UDP), produced **19 RF estimates**, identified **14 flows** using observed service evidence, recorded five Unknown flows with reasons, and stopped cleanly. This single capture verifies operation on this machine, not identification accuracy. Firewall and hosts-file behavior was tested with mocks and temporary files; no production rule or hosts entry was changed. Browser disconnect cleanup, prolonged capture, and real enforcement still require machine-specific manual checks.

## Privacy and future work

Flow rows can contain personal IP addresses, hostnames, user agents, and timing metadata. Keep live exports, capture files, logs, and the runtime blocklist outside Git and sanitize screenshots. The repository's earlier Git history contains a runtime blocklist and capture; removing them from the current index does **not** erase that history. Review and, if publishing publicly, plan a history rewrite with owner approval.

Future work needs independently labelled capture sessions for every RF class, modern service classes, matching live/train flow windows, a locked external test set for both models, and validated capture-to-process attribution if executable identities are desired.
