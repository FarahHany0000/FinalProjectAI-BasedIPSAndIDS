import os
import sys

# Get path relative to backend/
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
AI_MODELS_DIR = os.path.join(BACKEND_DIR, "ai_models")
HOST_MODELS_DIR = os.path.join(AI_MODELS_DIR, "host_cnn")
NETWORK_MODELS_DIR = os.path.join(AI_MODELS_DIR, "network_xgb")


class ModelLoader:
    """
    Loads XGBoost (primary) and Random Forest (secondary) host models,
    plus XGBoost network models for attack type detection.
    """

    _xgb_pipeline = None
    _rf_pipeline = None
    _network_engine = None

    @classmethod
    def load(cls):
        """Load XGBoost and Random Forest pipelines for host detection."""
        import joblib
        import __main__

        sys.path.insert(0, BACKEND_DIR)
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
    def load_network_model(cls):
        """
        Load network IDS model (XGBoost for attack detection).
        Returns an inference engine for hierarchical prediction.

        Returns
        -------
        NetworkXGBoostEngine or None if models not found
        """
        try:
            import joblib
            import __main__
            import pathlib
            import sys

            # Add network_module to path
            sys_path = str(pathlib.Path(__file__).resolve().parent.parent.parent / "network_module")
            if sys_path not in sys.path:
                sys.path.insert(0, sys_path)

            # Load the binary + attack XGBoost models
            binary_model_path = os.path.join(NETWORK_MODELS_DIR, "binary_model.json")
            attack_model_path = os.path.join(NETWORK_MODELS_DIR, "attack_model.json")

            if not os.path.exists(binary_model_path) or not os.path.exists(attack_model_path):
                print(f"[WARN] Network models not found at:")
                print(f"       Binary:  {binary_model_path}")
                print(f"       Attack:  {attack_model_path}")
                print(f"       Network sensor will be DISABLED")
                return None

            # Import XGBoost
            try:
                import xgboost as xgb
            except ImportError:
                print("[WARN] XGBoost not installed - network models unavailable")
                return None

            # Create simple inference wrapper
            class NetworkXGBoostEngine:
                """Simple XGBoost inference engine for network IDS."""

                def __init__(self, binary_model_path, attack_model_path):
                    self.binary_model = xgb.Booster(model_file=binary_model_path)
                    self.attack_model = xgb.Booster(model_file=attack_model_path)
                    self.attack_classes = ["ARPSpoof", "FTPBrute", "PortScan", "SSHBrute", "SYNFlood"]

                    # Load scaler — model was trained on StandardScaler-scaled features
                    scaler_path = os.path.join(NETWORK_MODELS_DIR, "scaler.pkl")
                    if os.path.exists(scaler_path):
                        self.scaler = joblib.load(scaler_path)
                    else:
                        print("[WARN] scaler.pkl not found — predictions may be inaccurate")
                        self.scaler = None

                    # Load feature names (sorted order, same as training)
                    feat_path = os.path.join(NETWORK_MODELS_DIR, "feature_names.json")
                    if os.path.exists(feat_path):
                        import json
                        with open(feat_path) as f:
                            self.feature_names = json.load(f)
                    else:
                        # Fallback: sorted feature list
                        sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "network_module"))
                        from data_pipeline.feature_engineer import get_feature_names
                        self.feature_names = get_feature_names()

                def hierarchical_predict(self, X, threshold=0.70, classification_threshold=0.50):
                    """
                    Two-stage detection: Binary (attack/normal) + Multi-class (attack type).
                    X : np.ndarray of shape (1, n_features) — single window
                    threshold : Stage 1 binary threshold (is it an attack?)
                    classification_threshold : Stage 2 minimum confidence (what type?)
                    """
                    import numpy as np
                    import xgboost as xgb

                    # Apply scaler (model was trained on StandardScaler-scaled features)
                    if self.scaler is not None:
                        X_scaled = self.scaler.transform(X).astype(np.float32)
                    else:
                        X_scaled = X.astype(np.float32)

                    dmatrix = xgb.DMatrix(X_scaled)

                    # Stage 1: Binary classification
                    binary_probs = self.binary_model.predict(dmatrix)
                    if binary_probs.ndim == 2:
                        attack_prob = float(binary_probs[0, 1])
                    else:
                        attack_prob = float(binary_probs[0])

                    if attack_prob >= threshold:
                        # Stage 2: Attack type classification
                        attack_probs = self.attack_model.predict(dmatrix)
                        if attack_probs.ndim == 2:
                            attack_idx = int(np.argmax(attack_probs[0]))
                            confidence = float(attack_probs[0, attack_idx])
                        else:
                            if len(attack_probs) == len(self.attack_classes):
                                attack_idx = int(np.argmax(attack_probs))
                                confidence = float(attack_probs[attack_idx])
                            else:
                                attack_idx = int(attack_probs[0])
                                attack_idx = min(attack_idx, len(self.attack_classes) - 1)
                                confidence = attack_prob
                        label = self.attack_classes[attack_idx]

                        # Stage 2 confidence gate
                        if confidence < classification_threshold:
                            label = "Normal"
                            confidence = float(1.0 - attack_prob)
                    else:
                        label = "Normal"
                        confidence = float(1.0 - attack_prob)

                    return [label], [confidence]

            engine = NetworkXGBoostEngine(binary_model_path, attack_model_path)
            print("[OK] Network XGBoost models loaded (binary + attack)")
            cls._network_engine = engine
            return engine

        except Exception as e:
            print(f"[WARN] Failed to load network models: {e}")
            import traceback
            traceback.print_exc()
            return None

    @classmethod
    def predict(cls, features):
        """
        XGBoost-primary prediction for host detection.
        RF provides secondary confirmation.
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
