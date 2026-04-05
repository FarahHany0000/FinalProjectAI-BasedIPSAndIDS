from extensions import db
from datetime import datetime


class PredictionLog(db.Model):
    """Stores every prediction for risk timeline charts."""
    __tablename__ = "prediction_logs"

    id = db.Column(db.Integer, primary_key=True)
    host_name = db.Column(db.String(100), nullable=False, index=True)
    agent_id = db.Column(db.String(64))
    prediction = db.Column(db.String(20))  # "Normal" or "Attack"
    probability = db.Column(db.Float, default=0.0)
    xgb_prediction = db.Column(db.String(20))
    xgb_probability = db.Column(db.Float, default=0.0)
    rf_prediction = db.Column(db.String(20))
    rf_probability = db.Column(db.Float, default=0.0)
    features = db.Column(db.Text)  # JSON string of 15 features
    prevention_level = db.Column(db.String(20))  # NONE/LOW/MEDIUM/CRITICAL
    prevention_action = db.Column(db.String(200))
    time = db.Column(db.DateTime, default=datetime.now, index=True)

    def to_dict(self):
        return {
            "id": self.id,
            "host_name": self.host_name,
            "prediction": self.prediction,
            "probability": self.probability,
            "xgb_prediction": self.xgb_prediction,
            "xgb_probability": self.xgb_probability,
            "rf_prediction": self.rf_prediction,
            "rf_probability": self.rf_probability,
            "features": self.features,
            "prevention_level": self.prevention_level,
            "prevention_action": self.prevention_action,
            "time": self.time.isoformat() if self.time else None,
        }
