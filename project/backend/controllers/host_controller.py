import datetime
from extensions import db, socketio
from models.host import Host
from models.alert import Alert
from src.infra import ModelLoader
from utils.constants import EXPECTED_FEATURE_COUNT, FEATURE_NAMES
from utils.response_orchestrator import InsiderThreatResponseOrchestrator


class HostController:
    """Business logic for host agent reports and predictions."""

    @staticmethod
    def process_report(agent_id, host_name, ip, features, activity_type="FILE", os_info=None):
        """
        Receive 15 features from the agent, run XGBoost prediction, update DB.
        Returns dict with prediction/probability/action/models.
        """
        if not features or len(features) != EXPECTED_FEATURE_COUNT:
            raise ValueError(
                f"Expected {EXPECTED_FEATURE_COUNT} features, got {len(features) if features else 0}"
            )

        threat, action = "Normal", "No Action"
        probability = 0.0
        models_data = {}
        prevention_result = {
            "test_mode": True,
            "activity_type": activity_type,
            "level": "NONE",
            "action": "No Preventive Action",
            "response_message": "No prevention triggered.",
            "popup": None,
        }

        # ── AI Prediction (XGBoost primary + RandomForest secondary) ──
        if ModelLoader.is_loaded():
            try:
                result = ModelLoader.predict(features)
                pred_label = result.get("prediction", "Normal")
                probability = result.get("probability", 0.0)
                models_data = result.get("models", {})

                if pred_label == "Attack":
                    threat = "Attack"
                    action = "Host Flagged"
                    print(f"[ALERT] {host_name}: Attack (prob={probability:.3f})")

            except Exception as e:
                print(f"[PREDICTION ERROR] {e}")
        else:
            print("[WARN] No model loaded — returning Normal.")

        prevention_result = InsiderThreatResponseOrchestrator.evaluate_and_respond(
            host_name=host_name,
            activity_type=activity_type,
            prediction=threat,
            probability=probability,
            host_ip=ip or "",
            features=features,
        )

        if threat != "Normal":
            action = prevention_result["action"]

        # ── Update Database ──
        now = datetime.datetime.now()

        host = Host.query.filter_by(agent_id=agent_id).first()
        if not host:
            if ip:
                host = (
                    Host.query
                    .filter_by(host_name=host_name, ip=ip)
                    .order_by(Host.last_seen.desc())
                    .first()
                )
            if not host:
                host = (
                    Host.query
                    .filter_by(host_name=host_name)
                    .order_by(Host.last_seen.desc())
                    .first()
                )
            if host:
                host.agent_id = agent_id

        if not host:
            host = Host(agent_id=agent_id, host_name=host_name, ip=ip, os_info=os_info,
                        last_prediction=threat, last_probability=probability,
                        last_seen=now, status="Online", action=action)
            db.session.add(host)
        else:
            host.last_seen = now
            host.ip = ip
            host.host_name = host_name
            host.action = action
            host.status = "Online"
            host.last_prediction = threat
            host.last_probability = probability
            if os_info:
                host.os_info = os_info

        if threat != "Normal":
            detail_parts = []
            detail_parts.append(f"Action: {action}")
            # Add top anomalous features
            anomaly_features = []
            for i, name in enumerate(FEATURE_NAMES):
                if i < len(features):
                    val = features[i]
                    if name == "failed_logins" and val > 0:
                        anomaly_features.append(f"Failed Logins: {val}")
                    elif name == "privilege_escalation_attempts" and val > 0:
                        anomaly_features.append(f"Privilege Escalations: {val}")
                    elif name == "unusual_process_count" and val > 0:
                        anomaly_features.append(f"Unusual Processes: {val}")
                    elif name == "file_access_anomaly_score" and val > 0.5:
                        anomaly_features.append(f"File Anomaly: {val:.2f}")
                    elif name == "cpu_percent" and val > 90:
                        anomaly_features.append(f"High CPU: {val:.1f}%")
                    elif name == "num_connections" and val > 500:
                        anomaly_features.append(f"Connections: {int(val)}")
            if anomaly_features:
                detail_parts.append("Anomalies: " + ", ".join(anomaly_features[:3]))

            alert = Alert(
                host_name=host_name, ip=ip,
                threat_type=threat,
                action=action, time=now,
                confidence=probability,
                severity="Critical" if probability >= 0.9 else ("High" if probability >= 0.7 else "Medium"),
                details=" | ".join(detail_parts),
            )
            db.session.add(alert)

        db.session.commit()

        # Build feature dict for frontend
        feature_dict = {}
        for i, name in enumerate(FEATURE_NAMES):
            if i < len(features):
                feature_dict[name] = features[i]

        # Emit real-time WebSocket events
        socketio.emit("host_update", host.to_dict())
        if threat != "Normal":
            socketio.emit("new_alert", alert.to_dict())
            socketio.emit("prevention_action", {
                "host_name": host_name,
                "ip": ip,
                "prediction": threat,
                "probability": probability,
                "risk_score": round(probability * 100, 1),
                **prevention_result,
            })

        return {
            "prediction": threat,
            "probability": probability,
            "action": action,
            "prevention": prevention_result,
            "models": models_data,
            "features": feature_dict,
        }

    @staticmethod
    def get_all_hosts():
        """Return all registered hosts."""
        hosts = Host.query.order_by(Host.last_seen.desc()).all()
        dedup = {}
        for host in hosts:
            key = f"{(host.host_name or '').strip().lower()}|{host.ip or ''}"
            if key not in dedup:
                dedup[key] = host
        return [h.to_dict() for h in dedup.values()]
