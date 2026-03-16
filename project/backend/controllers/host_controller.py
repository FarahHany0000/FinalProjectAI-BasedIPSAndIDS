import datetime
from extensions import db, socketio
from models.host import Host
from models.alert import Alert
from utils.model_loader import ModelLoader
from utils.constants import EXPECTED_FEATURE_COUNT


class HostController:
    """Business logic for host agent reports and predictions."""

    @staticmethod
    def process_report(agent_id, host_name, ip, features):
        """
        Receive 15 features from the agent, run XGBoost prediction, update DB.
        Returns dict with prediction/probability/action.
        """
        if not features or len(features) != EXPECTED_FEATURE_COUNT:
            raise ValueError(
                f"Expected {EXPECTED_FEATURE_COUNT} features, got {len(features) if features else 0}"
            )

        threat, action = "Normal", "No Action"
        probability = 0.0

        # ── AI Prediction (XGBoost primary) ──
        if ModelLoader.is_loaded():
            try:
                result = ModelLoader.predict(features)
                pred_label = result.get("prediction", "Normal")
                probability = result.get("probability", 0.0)

                if pred_label == "Attack":
                    threat = "Attack"
                    action = "Host Flagged"
                    print(f"[ALERT] {host_name}: Attack (prob={probability:.3f})")

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
                threat_type=threat,
                action=action, time=now,
            )
            db.session.add(alert)

        db.session.commit()

        # Emit real-time WebSocket events
        socketio.emit("host_update", host.to_dict())
        if threat != "Normal":
            socketio.emit("new_alert", alert.to_dict())

        return {"prediction": threat, "probability": probability, "action": action}

    @staticmethod
    def get_all_hosts():
        """Return all registered hosts."""
        hosts = Host.query.all()
        return [h.to_dict() for h in hosts]
