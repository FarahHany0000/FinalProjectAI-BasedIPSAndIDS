import datetime
from models.alert import Alert
from models.host import Host
from extensions import db


class AlertController:
    """Business logic for alerts and dashboard stats."""

    @staticmethod
    def get_alerts_for_host(hostname):
        """Return alerts for a specific host, newest first."""
        alerts = Alert.query.filter_by(host_name=hostname).order_by(Alert.time.desc()).all()
        return [a.to_dict() for a in alerts]

    @staticmethod
    def get_all_alerts(limit=100):
        """Return the most recent alerts across all hosts."""
        alerts = Alert.query.order_by(Alert.time.desc()).limit(limit).all()
        return [a.to_dict() for a in alerts]

    @staticmethod
    def get_dashboard_stats():
        """Aggregate stats for the frontend dashboard."""
        from models.registered_agent import RegisteredAgent

        total_hosts = Host.query.count()
        online_hosts = Host.query.filter_by(status="Online").count()
        offline_hosts = Host.query.filter_by(status="Offline").count()
        total_alerts = Alert.query.count()
        recent_alerts = Alert.query.filter(
            Alert.time >= datetime.datetime.now() - datetime.timedelta(hours=1)
        ).count()

        registered_agents = RegisteredAgent.query.count()
        online_agents = RegisteredAgent.query.filter_by(status="Online").count()

        from utils.model_loader import ModelLoader

        return {
            "total_hosts": total_hosts,
            "online_hosts": online_hosts,
            "offline_hosts": offline_hosts,
            "total_alerts": total_alerts,
            "recent_alerts_1h": recent_alerts,
            "registered_agents": registered_agents,
            "online_agents": online_agents,
            "model_loaded": ModelLoader.is_loaded(),
        }
