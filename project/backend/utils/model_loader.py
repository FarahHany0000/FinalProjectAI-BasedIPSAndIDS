import os
import sys

AI_MODELS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ai_models")
sys.path.insert(0, AI_MODELS_DIR)


class ModelLoader:
    """
    Loads and manages AI model pipelines.
    Singleton-like: call load() once at startup, then use get_pipeline().
    """

    _pipeline = None

    @classmethod
    def load(cls):
        """Load the CNN pipeline (scaler from pkl + weights from h5)."""
        try:
            import joblib
            import tensorflow as tf
            import __main__

            pkl_path = os.path.join(AI_MODELS_DIR, "cnn_complete_pipeline.pkl")
            h5_path = os.path.join(AI_MODELS_DIR, "cnn_weights.h5")

            if not os.path.exists(pkl_path):
                print(f"[WARN] Model file not found: {pkl_path}")
                return
            if not os.path.exists(h5_path):
                print(f"[WARN] Weights file not found: {h5_path}")
                return

            # The pkl was saved from __main__; inject the class for unpickling
            from use_models import CNNPipeline as _CNNPipeline
            __main__.CNNPipeline = _CNNPipeline

            pipeline = joblib.load(pkl_path)

            tf.get_logger().setLevel("ERROR")
            cnn_model = tf.keras.models.load_model(h5_path, compile=False)
            pipeline.model = cnn_model

            cls._pipeline = pipeline

            has_scaler = hasattr(pipeline, "scaler") and pipeline.scaler is not None
            print(f"[OK] CNN model loaded (pipeline: {type(pipeline).__name__}, scaler: {has_scaler})")

        except Exception as e:
            print(f"[ERROR] Failed to load AI model: {e}")
            import traceback
            traceback.print_exc()
            cls._pipeline = None

    @classmethod
    def get_pipeline(cls):
        """Return the loaded model pipeline (or None if not loaded)."""
        return cls._pipeline

    @classmethod
    def is_loaded(cls):
        return cls._pipeline is not None
