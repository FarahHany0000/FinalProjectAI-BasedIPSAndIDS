import joblib
from use_models import CNNPipeline
import numpy as np

features = np.load("ai_models/feature_names.npy", allow_pickle=True)

print(features)