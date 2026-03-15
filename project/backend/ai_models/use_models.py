#!/usr/bin/env python3
"""
استخدام الموديلات - Random Forest, XGBoost, CNN
Raw numbers in -> Prediction out
"""

import joblib
import numpy as np
import sys
from tensorflow.keras.models import load_model


class RandomForestPipeline:
    def __init__(self, model, scaler, feature_names, threshold):
        self.model = model
        self.scaler = scaler
        self.feature_names = feature_names
        self.threshold = threshold
        self.name = "Random Forest"
    
    def predict(self, features):
        features_scaled = self.scaler.transform([features])
        proba = self.model.predict_proba(features_scaled)[0][1]
        prediction = 1 if proba >= self.threshold else 0
        return {
            'prediction': 'Attack' if prediction == 1 else 'Normal',
            'probability': float(proba),
            'threshold': self.threshold,
            'model': self.name
        }

class XGBoostPipeline:
    def __init__(self, model, feature_names, threshold=0.5):
        self.model = model
        self.feature_names = feature_names
        self.threshold = threshold
        self.name = "XGBoost"
    
    def predict(self, features):
        proba = self.model.predict_proba([features])[0][1]
        prediction = 1 if proba >= self.threshold else 0
        return {
            'prediction': 'Attack' if prediction == 1 else 'Normal',
            'probability': float(proba),
            'threshold': self.threshold,
            'model': self.name
        }

class CNNPipeline:
    def __init__(self, model, scaler, feature_names, threshold=0.5):
        self.model = model
        self.scaler = scaler
        self.feature_names = feature_names
        self.threshold = threshold
        self.name = "CNN"
    
    def predict(self, features):
        features_scaled = self.scaler.transform([features])
        features_cnn = features_scaled.reshape(1, 1, -1)
        proba = self.model.predict(features_cnn, verbose=0)[0][0]
        prediction = 1 if proba >= self.threshold else 0
        return {
            'prediction': 'Attack' if prediction == 1 else 'Normal',
            'probability': float(proba),
            'threshold': self.threshold,
            'model': self.name
        }

feature_names = [
    'total_logons', 'avg_logon_hour', 'std_logon_hour', 
    'weekend_logons', 'after_hours_logons', 'unique_pcs_logon',
    'total_device_activities', 'unique_pcs_device', 
    'avg_device_hour', 'after_hours_device',
    'total_file_activities', 'unique_files', 'unique_pcs_file',
    'avg_file_hour', 'after_hours_files'
]


def load_all_models(model_dir=None):
    """Load all models from the given directory. Returns (rf, xgb, cnn) pipelines."""
    import os
    if model_dir is None:
        model_dir = os.path.dirname(os.path.abspath(__file__))

    rf_model = None
    xgb_model = None
    cnn_pipeline_obj = None

    try:
        rf_model = joblib.load(os.path.join(model_dir, 'rf_complete_pipeline.pkl'))
        print("Random Forest loaded")
    except Exception as e:
        print(f"Random Forest: {e}")

    try:
        xgb_model = joblib.load(os.path.join(model_dir, 'xgb_complete_pipeline.pkl'))
        print("XGBoost loaded")
    except Exception as e:
        print(f"XGBoost: {e}")

    try:
        cnn_pipeline_obj = joblib.load(os.path.join(model_dir, 'cnn_complete_pipeline.pkl'))
        cnn_weights = load_model(os.path.join(model_dir, 'cnn_weights.h5'), compile=False)
        cnn_pipeline_obj.model = cnn_weights
        print("CNN loaded")
    except Exception as e:
        print(f"CNN: {e}")

    return rf_model, xgb_model, cnn_pipeline_obj


def print_usage():
    print("\nUsage:")
    print("  python use_models.py rf   450 15.5 3.5 ... (15 numbers)")
    print("  python use_models.py xgb  450 15.5 3.5 ... (15 numbers)")
    print("  python use_models.py cnn  450 15.5 3.5 ... (15 numbers)")
    print("\nExample:")
    print("  python use_models.py rf 450 15.5 3.5 80 150 5 250 4 14.2 120 800 70 4 13.5 150")
    print("\nFeatures order:")
    for i, name in enumerate(feature_names, 1):
        print(f"  {i:2d}. {name}")

if __name__ == "__main__":
    print("Loading models...")
    rf_model, xgb_model, cnn_pipeline = load_all_models()

    if len(sys.argv) < 3:
        print_usage()
        sys.exit(1)
    
    model_name = sys.argv[1].lower()
    
    try:
        features = [float(x) for x in sys.argv[2:]]
        if len(features) != 15:
            print(f" Error: Need 15 features, got {len(features)}")
            print_usage()
            sys.exit(1)
    except ValueError:
        print(" Error: Features must be numbers")
        print_usage()
        sys.exit(1)
    
    if model_name == 'rf':
        if rf_model is None:
            print(" Random Forest not loaded")
            sys.exit(1)
        result = rf_model.predict(features)
    elif model_name == 'xgb':
        if xgb_model is None:
            print(" XGBoost not loaded")
            sys.exit(1)
        result = xgb_model.predict(features)
    elif model_name == 'cnn':
        if cnn_pipeline is None:
            print(" CNN not loaded")
            sys.exit(1)
        result = cnn_pipeline.predict(features)
    else:
        print(f"Unknown model: {model_name}")
        print("Available: rf, xgb, cnn")
        sys.exit(1)
    
    print("\n" + "=" * 60)
    print(f"MODEL: {result['model']}")
    print("=" * 60)
    print(f"Prediction: {result['prediction']}")
    print(f"Attack Probability: {result['probability']:.3f}")
    print(f"Threshold: {result['threshold']}")
    print("-" * 60)
    if result['prediction'] == 'Attack':
        print("  ALERT: Potential attacker detected!")
    else:
        print("User appears normal")