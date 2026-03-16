import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AI_MODELS_DIR = os.path.join(BASE_DIR, "ai_models")
HOST_MODELS_DIR = os.path.join(AI_MODELS_DIR, "host_cnn")


class ModelLoader:
    """
    Loads all host AI models (XGBoost, Random Forest, CNN) and provides
    majority-vote prediction. XGBoost is the primary model.
    """

    _xgb_pipeline = None
    _rf_pipeline = None
    _cnn_pipeline = None

    @classmethod
    def load(cls):
        """Load all available host model pipelines."""
        import joblib
        import __main__

        from utils.pipelines import XGBoostPipeline, RandomForestPipeline, CNNPipeline
        __main__.XGBoostPipeline = XGBoostPipeline
        __main__.RandomForestPipeline = RandomForestPipeline
        __main__.CNNPipeline = CNNPipeline

        # XGBoost — primary model (best accuracy, lowest false positives)
        xgb_path = os.path.join(HOST_MODELS_DIR, "xgb_complete_pipeline.pkl")
        if os.path.exists(xgb_path):
            try:
                cls._xgb_pipeline = joblib.load(xgb_path)
                print("[OK] XGBoost model loaded")
            except Exception as e:
                print(f"[WARN] XGBoost load failed: {e}")

        # Random Forest — secondary model
        rf_path = os.path.join(HOST_MODELS_DIR, "rf_complete_pipeline.pkl")
        if os.path.exists(rf_path):
            try:
                cls._rf_pipeline = joblib.load(rf_path)
                print("[OK] Random Forest model loaded")
            except Exception as e:
                print(f"[WARN] Random Forest load failed: {e}")

        # CNN — tertiary model (high false positive rate, used for tie-breaking only)
        pkl_path = os.path.join(HOST_MODELS_DIR, "cnn_complete_pipeline.pkl")
        h5_path = os.path.join(HOST_MODELS_DIR, "cnn_weights.h5")
        if os.path.exists(pkl_path) and os.path.exists(h5_path):
            try:
                import tensorflow as tf
                tf.get_logger().setLevel("ERROR")
                cls._cnn_pipeline = joblib.load(pkl_path)
                cls._cnn_pipeline.model = tf.keras.models.load_model(h5_path, compile=False)
                print("[OK] CNN model loaded")
            except Exception as e:
                print(f"[WARN] CNN load failed: {e}")

        loaded = sum(1 for m in [cls._xgb_pipeline, cls._rf_pipeline, cls._cnn_pipeline] if m)
        print(f"[OK] {loaded}/3 host models loaded")

    @classmethod
    def predict(cls, features):
        """
        XGBoost-primary prediction with RF/CNN as secondary evidence.
        XGBoost is the most reliable model for real-time host detection.
        Returns dict with prediction, probability, and per-model details.
        """
        results = {}

        for name, pipeline in [("XGBoost", cls._xgb_pipeline),
                                ("RandomForest", cls._rf_pipeline),
                                ("CNN", cls._cnn_pipeline)]:
            if pipeline is None:
                continue
            try:
                res = pipeline.predict(features)
                results[name] = res
            except Exception as e:
                print(f"[PREDICTION ERROR] {name}: {e}")

        if not results:
            return {"prediction": "Normal", "probability": 0.0, "votes": "0/0", "models": {}}

        # XGBoost is the primary decision maker (best accuracy on CERT data)
        if "XGBoost" in results:
            primary = results["XGBoost"]
        elif "RandomForest" in results:
            primary = results["RandomForest"]
        else:
            primary = results.get("CNN", {"prediction": "Normal", "probability": 0.0})

        votes_attack = sum(1 for r in results.values() if r["prediction"] == "Attack")
        total = len(results)

        return {
            "prediction": primary["prediction"],
            "probability": primary["probability"],
            "votes": f"{votes_attack}/{total}",
            "models": {k: {"prediction": v["prediction"], "probability": round(v["probability"], 4)}
                       for k, v in results.items()},
        }

    @classmethod
    def get_pipeline(cls):
        """Return the primary pipeline (XGBoost) for backward compatibility."""
        return cls._xgb_pipeline or cls._rf_pipeline or cls._cnn_pipeline

    @classmethod
    def is_loaded(cls):
        return any(m is not None for m in [cls._xgb_pipeline, cls._rf_pipeline, cls._cnn_pipeline])
