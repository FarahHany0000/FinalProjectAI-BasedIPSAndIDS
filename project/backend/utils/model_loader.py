import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AI_MODELS_DIR = os.path.join(BASE_DIR, "ai_models")
HOST_MODELS_DIR = os.path.join(AI_MODELS_DIR, "host_cnn")


class ModelLoader:
    """
    Loads XGBoost (primary) and Random Forest (secondary) host models.
    CNN removed — high false positive rate, unsuitable for real-time detection.
    """

    _xgb_pipeline = None
    _rf_pipeline = None

    @classmethod
    def load(cls):
        """Load XGBoost and Random Forest pipelines."""
        import joblib
        import __main__

        from utils.pipelines import XGBoostPipeline, RandomForestPipeline
        __main__.XGBoostPipeline = XGBoostPipeline
        __main__.RandomForestPipeline = RandomForestPipeline

        # XGBoost — primary model (best accuracy, lowest false positives)
        xgb_path = os.path.join(HOST_MODELS_DIR, "xgb_complete_pipeline.pkl")
        if os.path.exists(xgb_path):
            try:
                cls._xgb_pipeline = joblib.load(xgb_path)
                print("[OK] XGBoost model loaded (primary)")
            except Exception as e:
                print(f"[WARN] XGBoost load failed: {e}")

        # Random Forest — secondary model
        rf_path = os.path.join(HOST_MODELS_DIR, "rf_complete_pipeline.pkl")
        if os.path.exists(rf_path):
            try:
                cls._rf_pipeline = joblib.load(rf_path)
                print("[OK] Random Forest model loaded (secondary)")
            except Exception as e:
                print(f"[WARN] Random Forest load failed: {e}")

        loaded = sum(1 for m in [cls._xgb_pipeline, cls._rf_pipeline] if m)
        print(f"[OK] {loaded}/2 host models loaded")

    @classmethod
    def predict(cls, features):
        """
        XGBoost-primary prediction. RF provides secondary confirmation.
        Returns dict with prediction, probability, and per-model details.
        """
        results = {}

        for name, pipeline in [("XGBoost", cls._xgb_pipeline),
                                ("RandomForest", cls._rf_pipeline)]:
            if pipeline is None:
                continue
            try:
                res = pipeline.predict(features)
                results[name] = res
            except Exception as e:
                print(f"[PREDICTION ERROR] {name}: {e}")

        if not results:
            return {"prediction": "Normal", "probability": 0.0, "models": {}}

        # XGBoost is the primary decision maker
        if "XGBoost" in results:
            primary = results["XGBoost"]
        else:
            primary = results["RandomForest"]

        return {
            "prediction": primary["prediction"],
            "probability": primary["probability"],
            "models": {k: {"prediction": v["prediction"], "probability": round(v["probability"], 4)}
                       for k, v in results.items()},
        }

    @classmethod
    def get_pipeline(cls):
        """Return the primary pipeline for backward compatibility."""
        return cls._xgb_pipeline or cls._rf_pipeline

    @classmethod
    def is_loaded(cls):
        return cls._xgb_pipeline is not None or cls._rf_pipeline is not None
