#!/usr/bin/env python3
"""
Network Intrusion Detection Model Predictor

This script loads a pre-trained network intrusion detection model and predicts
whether network traffic is benign or malicious based on input features.

The model was trained to detect network intrusions based on network traffic features.
The main features include:
- Bytes sent: The number of bytes sent in the network flow
- Bytes received: The number of bytes received in the network flow

Usage:
    python run_model.py                             # Uses default sample values
    python run_model.py --bytes-sent 500000 --bytes-received 30000000  # Command line input
    python run_model.py --input input_data.csv      # Input from CSV file
"""

import os
import sys
import argparse
import joblib
import pandas as pd
import numpy as np

# Constants
MODEL_FILE = "network_intrusion_model.pkl"
FEATURES_FILE = "selected_features.pkl"


def load_model_and_features():
    """
    Load the pre-trained model and selected features.
    
    Returns:
        tuple: (model, selected_features) if successful
        
    Raises:
        FileNotFoundError: If model or features file is not found
        Exception: For other errors during loading
    """
    try:
        if not os.path.exists(MODEL_FILE):
            raise FileNotFoundError(f"Model file '{MODEL_FILE}' not found.")
        
        if not os.path.exists(FEATURES_FILE):
            raise FileNotFoundError(f"Features file '{FEATURES_FILE}' not found.")
        
        model = joblib.load(MODEL_FILE)
        selected_features = joblib.load(FEATURES_FILE)
        
        return model, selected_features
    except FileNotFoundError as e:
        raise e
    except Exception as e:
        raise Exception(f"Error loading model or features: {str(e)}")


def validate_input_data(data, features):
    """
    Validate the input data to ensure it meets expected format and values.
    
    Args:
        data (pd.DataFrame): Input data to validate
        features (list): List of expected feature names
        
    Returns:
        bool: True if data is valid
        
    Raises:
        ValueError: If data validation fails
    """
    if not isinstance(data, pd.DataFrame):
        raise ValueError("Input must be a pandas DataFrame")
    
    # Check if all required features are present
    missing_features = set(features) - set(data.columns)
    if missing_features:
        raise ValueError(f"Missing required features: {', '.join(missing_features)}")
    
    # Check for negative values (network traffic bytes can't be negative)
    if (data < 0).any().any():
        raise ValueError("Input contains negative values, which is invalid for network traffic data")
        
    # Check for unreasonably large values (basic sanity check)
    if (data > 1e12).any().any():  # More than 1 TB of data
        raise ValueError("Input contains unreasonably large values")
        
    return True


def prepare_input_from_args(args, features):
    """
    Prepare input data from command line arguments or from a file.
    
    Args:
        args: Command line arguments
        features (list): List of expected feature names
        
    Returns:
        pd.DataFrame: Prepared input data
    """
    if args.input:
        try:
            # Load from CSV file
            data = pd.read_csv(args.input)
            # Ensure only selected features are used and in the right order
            data = data[features]
            return data
        except Exception as e:
            raise ValueError(f"Error reading input file: {str(e)}")
    else:
        # Create from command line arguments or use default values
        values = []
        
        # For simplicity, we assume the first two features are bytes sent and received
        if len(features) >= 2:
            values = [args.bytes_sent, args.bytes_received]
            
            # Fill remaining features with zeros
            values.extend([0] * (len(features) - 2))
                
        return pd.DataFrame([values], columns=features)


def predict(model, data):
    """
    Make predictions using the loaded model.
    
    Args:
        model: Trained machine learning model
        data (pd.DataFrame): Input data for prediction
        
    Returns:
        str: "Benign" or "Malicious" prediction result
    """
    try:
        prediction = model.predict(data)
        return "Malicious" if prediction[0] == 1 else "Benign"
    except Exception as e:
        raise Exception(f"Error making prediction: {str(e)}")


def main():
    """Main function that orchestrates the prediction process."""
    # Set up argument parser
    parser = argparse.ArgumentParser(description='Network Intrusion Detection Model Predictor')
    
    # Input method group
    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument('--input', type=str, help='Path to input CSV file')
    
    # Individual feature arguments
    parser.add_argument('--bytes-sent', type=int, default=500000, 
                       help='Number of bytes sent in the network flow')
    parser.add_argument('--bytes-received', type=int, default=30000000, 
                       help='Number of bytes received in the network flow')
    
    args = parser.parse_args()
    
    try:
        # Load model and features
        model, selected_features = load_model_and_features()
        
        # Prepare input data
        input_data = prepare_input_from_args(args, selected_features)
        
        # Validate input data
        validate_input_data(input_data, selected_features)
        
        # Make prediction
        result = predict(model, input_data)
        
        # Display result
        print("Prediction:", result)
        
        return 0
    except FileNotFoundError as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        print("Please ensure the model files are in the current directory.", file=sys.stderr)
        return 1
    except ValueError as e:
        print(f"Input Error: {str(e)}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Unexpected Error: {str(e)}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
