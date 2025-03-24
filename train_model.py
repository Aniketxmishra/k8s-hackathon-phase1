import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report
import joblib
import os

# Get the directory of the script
script_dir = os.path.dirname(os.path.abspath(__file__))

# Construct file paths
benign_file = os.path.join(script_dir, "elastic_may2021_benign_data.csv")
malicious_file = os.path.join(script_dir, "elastic_may2021_malicious_data.csv")

# Load data
benign_data = pd.read_csv(benign_file)
malicious_data = pd.read_csv(malicious_file)
data = pd.concat([benign_data, malicious_data], ignore_index=True)

# Print columns to confirm
print("Columns in the dataset:", data.columns.tolist())

# Select features
features = ['_source_network_bytes', '_source_event_duration', '_source_source_port']
X = data[features].fillna(0)
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Prepare labels
data['label'] = data['label'].map({'benign': 0, 'malicious': 1})
y_true = data['label']

# Debug: Print sizes based on file and labels
print(f"Number of samples in benign file: {len(benign_data)}")
print(f"Number of samples in malicious file: {len(malicious_data)}")
print(f"Total samples: {len(data)}")
print(f"Number of benign samples (label=0): {len(data[data['label'] == 0])}")
print(f"Number of malicious samples (label=1): {len(data[data['label'] == 1])}")

# Calculate contamination based on labels
contamination = len(data[data['label'] == 1]) / len(data)
print(f"Contamination (malicious proportion based on labels): {contamination:.2%}")
# Cap contamination at 0.5 if it exceeds the allowed range
contamination = min(contamination, 0.5)
model = IsolationForest(contamination=contamination, random_state=42)
model.fit(X_scaled)
predictions = model.predict(X_scaled)
y_pred = np.where(predictions == -1, 1, 0)

# Evaluate
print("Model Performance:")
print(classification_report(y_true, y_pred, target_names=['Benign', 'Malicious']))
anomaly_rate = np.mean(y_pred == 1)
print(f"Detected anomaly rate: {anomaly_rate:.2%}")

# Save model and scaler
joblib.dump(model, os.path.join(script_dir, 'k8s_anomaly_model.pkl'))
joblib.dump(scaler, os.path.join(script_dir, 'scaler.pkl'))

# Demo prediction
test_sample = X_scaled[:5]
test_pred = model.predict(test_sample)
test_pred_labels = np.where(test_pred == -1, 1, 0)
print("Test sample predictions (1 = anomaly, 0 = normal):", test_pred_labels)
print("Ground truth for test samples:", y_true[:5].values)

# Save a small data sample
data_sample = data.head(100)
data_sample.to_csv(os.path.join(script_dir, 'data_sample.csv'), index=False)