import joblib
from use_models import CNNPipeline
MODEL_PATH = r"C:\Users\HANY\Desktop\frontend\backend\ai_models\cnn_complete_pipeline.pkl"

model = joblib.load(MODEL_PATH)

print("\nMODEL TYPE:")
print(type(model))

print("\nMODEL ATTRIBUTES:")
print(dir(model))

# محاولة استخراج feature names
if hasattr(model, "feature_names"):
    print("\nFEATURES:")
    print(model.feature_names)

if hasattr(model, "features"):
    print("\nFEATURES:")
    print(model.features)

if hasattr(model, "feature_names_in_"):
    print("\nFEATURES:")
    print(model.feature_names_in_)