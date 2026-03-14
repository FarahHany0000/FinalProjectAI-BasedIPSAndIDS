import numpy as np

feature_file = r"C:\Users\HANY\Desktop\frontend\backend\ai_models\feature_names.npy"
feature_names = np.load(feature_file, allow_pickle=True)
print("Features expected by model (in order):")
print(feature_names)
print("Number of features expected:", len(feature_names))
from cnn_pipeline import CNNPipeline  

MODEL_PATH = r"C:\Users\HANY\Desktop\frontend\backend\ai_models\cnn_complete_pipeline.pkl"
model = joblib.load(MODEL_PATH)