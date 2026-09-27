# ScanTrust WAF — AI-Powered Lightweight Web Application Firewall

ScanTrust is an edge-deployable, real-time Web Application Firewall engineered to inspect Layer 7 HTTP traffic and detect obfuscated SQL Injections (case alternation, inline comments, URL/hex encoding) on commodity CPU architectures without GPU overhead.

## Key Performance Metrics
- **Classification Accuracy:** 99.04% on hold-out test set
- **Precision / Recall:** 98.92% | **FPR:** 0.87%
- **Inference Latency:** 6.72ms mean end-to-end processing time (<10ms target)
- **Model Footprint:** ~1 MB compiled pipeline binary
- **SUS Usability Score:** 84.25 / 100 ("Excellent" Grade A)

## Repository Structure
- `app.py`: Streamlit real-time monitoring dashboard and forensic reporting UI
- `classifier.py`: Hybrid AI inference (Random Forest) and regex fallback engine
- `sniffer.py`: Asynchronous promiscuous TCP packet sniffer built with Scapy
- `database.py`: Parameterized SQLite persistence layer for threat audit trails
- `rf_model_all_obfuscations.pkl`: Pre-trained Random Forest model
- `vectorizer_all_obfuscations.pkl`: Pre-fitted character tri-gram CountVectorizer
- `docs/`: Academic research thesis and project documentation

## Quick Setup & Execution
1. Install required dependencies:
   ```bash
   pip install -r requirements.txt