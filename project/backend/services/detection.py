import os
import numpy as np

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
AI_DIR = os.path.join(os.path.dirname(BASE_DIR), "ai_models")


def detect_and_prevent_host(host_features, model_pipeline=None):
    """
    host_features: list of 15 floats
    model_pipeline: loaded CNN pipeline object
    Returns: result dict with detected, action, status
    """
    if model_pipeline is None:
        return {"detected": False, "action": "No Action", "status": "Online"}

    try:
        result = model_pipeline.predict(host_features)

        if isinstance(result, dict):
            pred_label = 1 if result.get('prediction') == 'Attack' else 0
        else:
            pred_label = int(result[0]) if hasattr(result, '__getitem__') else int(result)

        if pred_label == 1:
            action = "Host Isolated"
            status = "Warning"
        else:
            action = "No Action"
            status = "Online"

        return {
            "detected": bool(pred_label),
            "action": action,
            "status": status
        }
    except Exception as e:
        print(f"[DETECTION ERROR] {e}")
        return {"detected": False, "action": "No Action", "status": "Online"}