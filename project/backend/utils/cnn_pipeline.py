import os
import numpy as np
import tensorflow as tf

class CNNPipeline:
    def __init__(self, model_dir=None):
        if model_dir is None:
            model_dir = os.path.dirname(os.path.abspath(__file__))

        pkl_path = os.path.join(model_dir, "cnn_complete_pipeline.pkl")
        h5_path = os.path.join(model_dir, "cnn_weights.h5")

        try:
            import joblib
            pipeline = joblib.load(pkl_path)
            self.scaler = getattr(pipeline, 'scaler', None)
            self.threshold = getattr(pipeline, 'threshold', 0.5)
            self.feature_names = getattr(pipeline, 'feature_names', None)
            print("[OK] CNN pipeline scaler loaded from pkl")
        except Exception as e:
            print(f"[WARN] Could not load pkl: {e}")
            self.scaler = None
            self.threshold = 0.5
            self.feature_names = None

        try:
            tf.get_logger().setLevel('ERROR')
            self.model = tf.keras.models.load_model(h5_path, compile=False)
            print("[OK] CNN weights loaded from h5")
        except Exception as e:
            print(f"[ERROR] Could not load h5 weights: {e}")
            self.model = None

    def predict(self, features_list):
        if self.model is None:
            return [0]
        try:
            data = np.array(features_list, dtype=np.float32)

            # Scale features if scaler is available
            if self.scaler is not None:
                data = self.scaler.transform(data.reshape(1, -1)).flatten()

            # CNN expects shape (1, 1, 15)
            X = data.reshape(1, 1, 15)

            prediction = self.model.predict(X, verbose=0)
            val = prediction[0][0] if hasattr(prediction[0], "__getitem__") else prediction[0]
            return [1 if val >= self.threshold else 0]
        except Exception as e:
            print(f"[PREDICTION ERROR] {e}")
            return [0]