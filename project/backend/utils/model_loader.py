import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AI_MODELS_DIR = os.path.join(BASE_DIR, "ai_models")
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
                print(f"[WARN] Network models not found:")
                print(f"       Binary: {binary_model_path}")
                print(f"       Attack: {attack_model_path}")
                print(f"       Disabling network sensor")
                return None

            # Import and create engine
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
                    self.feature_names = [
                        'pkt_count', 'pkt_len_mean', 'pkt_len_std', 'pkt_len_min', 'pkt_len_max', 'pkt_len_sum',
                        'ip_len_mean', 'ip_len_std', 'ip_len_min', 'ip_len_max',
                        'tcp_len_mean', 'tcp_len_std',
                        'tcp_win_mean', 'tcp_win_std', 'tcp_win_min', 'tcp_win_max',
                        'syn_count', 'ack_count', 'fin_count', 'rst_count',
                        'syn_ratio', 'ack_ratio', 'fin_ratio', 'rst_ratio',
                        'syn_ack_count', 'rst_to_syn_ratio', 'payload_pkt_ratio', 'avg_payload_size',
                        'ttl_mean', 'ttl_std', 'ttl_min', 'ttl_max',
                        'unique_src_ports', 'unique_dst_ports', 'dst_port_entropy',
                        'dst_port_to_pkt_ratio', 'unique_connections', 'syn_only_ratio',
                        'tcp_dport_mode', 'tcp_dport_min', 'unique_dst_ports_low',
                        'proto_tcp_ratio', 'proto_udp_ratio', 'proto_icmp_ratio', 'proto_arp_ratio', 'proto_entropy',
                        'arp_present', 'arp_pkt_count',
                        'icmp_count', 'icmp_type_mode',
                        'udp_len_mean', 'udp_len_std',
                        'ip_frag_count', 'dscp_mean', 'ip_flags_mean', 'ip_proto_mode',
                    ]
                    self.attack_classes = ["ARPSpoof", "FTPBrute", "PortScan", "SSHBrute", "SYNFlood"]

                def hierarchical_predict(self, X, threshold=0.70):
                    """
                    Two-stage detection: Binary (attack/normal) + Multi-class (attack type).

                    Parameters
                    ----------
                    X : np.ndarray of shape (n_samples, n_features)
                    threshold : float, confidence threshold for attack detection

                    Returns
                    -------
                    (labels, confidences) : (list of str, list of float)
                        labels: "Normal" or attack type
                        confidences: probability for final prediction
                    """
                    import numpy as np
                    import xgboost as xgb

                    # Convert to DMatrix
                    dmatrix = xgb.DMatrix(X)

                    # Stage 1: Binary classification
                    binary_probs = self.binary_model.predict(dmatrix)  # Shape: (n_samples, 2)
                    attack_prob = binary_probs[:, 1]  # P(attack)

                    labels = []
                    confidences = []

                    for i, prob in enumerate(attack_prob):
                        if prob >= threshold:
                            # Stage 2: Attack type classification
                            attack_probs = self.attack_model.predict(dmatrix[i:i+1])  # Shape: (1, 5)
                            attack_idx = np.argmax(attack_probs)
                            label = self.attack_classes[attack_idx]
                            confidence = float(attack_probs[0, attack_idx])
                        else:
                            label = "Normal"
                            confidence = float(1.0 - prob)

                        labels.append(label)
                        confidences.append(confidence)

                    return labels, confidences

            engine = NetworkXGBoostEngine(binary_model_path, attack_model_path)
            print("[OK] Network XGBoost models loaded")
            cls._network_engine = engine
            return engine

        except Exception as e:
            print(f"[WARN] Failed to load network models: {e}")
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
