# Kubernetes Anomaly Detection Model

This project uses Isolation Forest to detect network anomalies in Kubernetes NetFlow data from the AssureMOSS dataset. Features: `_source_network_bytes`, `_source_event_duration`, `_source_source_port`. F1-score for malicious class: 0.00. See `train_model.py` for details.

## Dataset
- The full datasets (`elastic_may2021_benign_data.csv` and `elastic_may2021_malicious_data.csv`) are large and not included in this repository due to GitHub's file size limits.
- A small sample of the data (`data_sample.csv`, first 100 rows) is provided for reference.
- The full datasets are part of the AssureMOSS Kubernetes Run-time Monitoring Dataset and can be obtained from the hackathon organizers if needed.

## Files
- `train_model.py`: Code to train and evaluate the model.
- `k8s_anomaly_model.pkl`: Trained Isolation Forest model.
- `scaler.pkl`: Scaler for preprocessing.
- `data_sample.csv`: Sample of the test data (first 100 rows).
- `presentation.pdf`: Presentation slides.
