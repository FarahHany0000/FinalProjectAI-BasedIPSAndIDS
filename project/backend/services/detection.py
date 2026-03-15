import numpy as np
from tensorflow.keras.models import load_model
from use_models import preprocess_features_host

feature_names = np.load("C:/Users/HANY/Desktop/frontend/backend/ai_models/feature_names.npy", allow_pickle=True)
cnn_model = load_model("C:/Users/HANY/Desktop/frontend/backend/ai_models/cnn_weights.h5")
def detect_and_prevent_host(host_features):
    """
    host_features: dict with host metrics
    Returns: result dict with detected, action, status
    """
    features = preprocess_features_host(host_features, feature_names)
    
    # CNN prediction
    pred = cnn_model.predict(features)
    pred_label = int(round(pred[0][0]))  # 0 = Safe, 1 = Threat
    
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