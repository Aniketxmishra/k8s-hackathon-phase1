
# Kubernetes Anomaly Detection Model

This project employs an Isolation Forest algorithm to detect network anomalies in Kubernetes NetFlow data sourced from the AssureMOSS dataset.

**Features Used**:
- `_source_network_bytes`
- `_source_event_duration`
- `_source_source_port`

**Model Performance**:
- F1-score for malicious class: 0.00 (indicative of class imbalance)

For detailed training and evaluation procedures, refer to `train_model.py`.

## 📁 Dataset

Due to GitHub's file size limitations, the full datasets are not included in this repository. The datasets used are:
- `elastic_may2021_benign_data.csv`
- `elastic_may2021_malicious_data.csv`

A sample of the data (`data_sample.csv`, containing the first 100 rows) is provided for reference. The complete datasets are part of the AssureMOSS Kubernetes Run-time Monitoring Dataset and can be obtained from the hackathon organizers upon request.

## 📄 Files Included

- `train_model.py`: Script to train and evaluate the Isolation Forest model.
- `run_model.py`: Driver script to load the trained model and make predictions.
- `k8s_anomaly_model.pkl`: Trained Isolation Forest model.
- `scaler.pkl`: Scaler used for preprocessing the data.
- `data_sample.csv`: Sample of the test data (first 100 rows).
- `presentation.pdf`: Presentation slides detailing the project.

## 🚀 How to Run the Model

### Prerequisites

Ensure you have Python 3.7 or higher installed. Install the required dependencies using:

```bash
pip install -r requirements.txt
