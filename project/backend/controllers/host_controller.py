import datetime
import numpy as np
from extensions import db
from models.host import Host
from models.alert import Alert
from utils.model_loader import ModelLoader
from utils.constants import EXPECTED_FEATURE_COUNT


class HostController:
    """Business logic for host agent reports and predictions."""

    @staticmethod
    def process_report(agent_id, host_name, ip, features):
        """
        Receive 15 features from the agent, run the CNN model, update DB.
        Returns dict with threat/severity/action.
        """
        if not features or len(features) != EXPECTED_FEATURE_COUNT:
            raise ValueError(
                f"Expected {EXPECTED_FEATURE_COUNT} features, got {len(features) if features else 0}"
            )

        threat, severity, action = "Normal", "Low", "No Action"
        probability = 0.0

        # ── AI Prediction ──
        pipeline = ModelLoader.get_pipeline()
        if pipeline is not None:
            try:
                result = pipeline.predict(features)

                if isinstance(result, dict):
                    pred_label = result.get("prediction", "Normal")
                    probability = result.get("probability", 0.0)
                    if pred_label == "Attack" or pred_label == 1:
                        threat = "Attack"
                        severity = "High" if probability > 0.8 else "Medium"
                        action = "Host Flagged"
                else:
                    pred_val = result[0] if hasattr(result, "__getitem__") else result
                    if isinstance(pred_val, (list, np.ndarray)):
                        pred_val = pred_val[0]
                    if pred_val == 1 or (isinstance(pred_val, float) and pred_val >= 0.5):
                        threat = "Attack"
                        severity = "High"
                        action = "Host Flagged"

            except Exception as e:
                print(f"[PREDICTION ERROR] {e}")
        else:
            print("[WARN] No model loaded — returning Normal.")

        # ── Update Database ──
        now = datetime.datetime.now()

        host = Host.query.filter_by(agent_id=agent_id).first()
        if not host:
            host = Host(agent_id=agent_id, host_name=host_name, ip=ip, last_seen=now, status="Online", action=action)
            db.session.add(host)
        else:
            host.last_seen = now
            host.ip = ip
            host.host_name = host_name
            host.action = action
            host.status = "Online"

        if threat != "Normal":
            alert = Alert(
                host_name=host_name, ip=ip,
                threat_type=threat, severity=severity,
                action=action, time=now,
            )
            db.session.add(alert)

        db.session.commit()

        return {"threats": threat, "severity": severity, "action": action, "prediction": threat, "probability": probability}

    @staticmethod
    def get_all_hosts():
        """Return all registered hosts."""
        hosts = Host.query.all()
        return [h.to_dict() for h in hosts]
