import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AI_MODELS_DIR = os.path.join(BASE_DIR, "ai_models")
HOST_CNN_DIR = os.path.join(AI_MODELS_DIR, "host_cnn")
NETWORK_XGB_DIR = os.path.join(AI_MODELS_DIR, "network_xgb")


class ModelLoader:
    """
    Loads and manages AI model pipelines.
    Singleton-like: call load() once at startup, then use get_pipeline().
    """

    _host_pipeline = None

    @classmethod
    def load(cls):
        """Load the CNN pipeline (scaler from pkl + weights from h5)."""
        try:
            import joblib
            import tensorflow as tf
            import __main__

            pkl_path = os.path.join(HOST_CNN_DIR, "cnn_complete_pipeline.pkl")
            h5_path = os.path.join(HOST_CNN_DIR, "cnn_weights.h5")

            if not os.path.exists(pkl_path):
                print(f"[WARN] Model file not found: {pkl_path}")
                return
            if not os.path.exists(h5_path):
                print(f"[WARN] Weights file not found: {h5_path}")
                return

            # The pkl was saved from __main__; inject the class for unpickling
            from utils.pipelines import CNNPipeline as _CNNPipeline
            __main__.CNNPipeline = _CNNPipeline

            pipeline = joblib.load(pkl_path)

            tf.get_logger().setLevel("ERROR")
            cnn_model = tf.keras.models.load_model(h5_path, compile=False)
            pipeline.model = cnn_model

            cls._host_pipeline = pipeline

            has_scaler = hasattr(pipeline, "scaler") and pipeline.scaler is not None
            print(f"[OK] Host CNN model loaded (scaler: {has_scaler})")

        except Exception as e:
            print(f"[ERROR] Failed to load AI model: {e}")
            import traceback
            traceback.print_exc()
            cls._host_pipeline = None

    @classmethod
    def get_pipeline(cls):
        """Return the loaded host model pipeline (or None)."""
        return cls._host_pipeline

    @classmethod
    def is_loaded(cls):
        return cls._host_pipeline is not None
