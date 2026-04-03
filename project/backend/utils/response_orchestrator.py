import datetime
import json
import os
from typing import Any, Dict, List, Tuple


def _to_bool(value: Any, default: bool = True) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


class InsiderThreatResponseOrchestrator:
    """
    Coordinates prevention decisions from model output.
    In TEST_MODE, actions are dry-run only (no OS-level blocking).
    """

    _initialized = False
    _test_mode = True
    _thresholds: Tuple[float, float, float] = (0.5, 0.7, 0.9)
    _log_path: str = ""
    _active_constraints: Dict[str, Dict[str, Any]] = {}

    _type_policy = {
        "EMAIL": "Quarantine Action",
        "FILE": "Read-only Enforcement",
        "HTTP": "Connection Reset Action",
    }

    @classmethod
    def initialize_and_reset(cls, config: Dict[str, Any]) -> None:
        """
        Must be called on startup.
        Clears prior in-memory constraints and writes reset marker.
        """
        backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        instance_dir = os.path.join(backend_dir, "instance")
        os.makedirs(instance_dir, exist_ok=True)

        cls._test_mode = _to_bool(
            config.get("TEST_MODE", os.environ.get("TEST_MODE", "true")),
            default=True,
        )
        cls._log_path = config.get(
            "PREVENTION_LOG_PATH",
            os.path.join(instance_dir, "prevention_actions.log"),
        )
        cls._active_constraints = {}
        cls._initialized = True

        cls._write_log(
            {
                "event": "initialize_and_reset",
                "message": "Prevention state reset on startup.",
                "test_mode": cls._test_mode,
            }
        )
        print(f"[PREVENTION] initialize_and_reset() complete | TEST_MODE={cls._test_mode}")

    @classmethod
    def update_thresholds(cls, *, low: float, medium: float, critical: float) -> Dict[str, float]:
        if not (0 <= low < medium < critical <= 1):
            raise ValueError("Thresholds must satisfy 0 <= low < medium < critical <= 1.")

        cls._thresholds = (float(low), float(medium), float(critical))
        cls._write_log(
            {
                "event": "threshold_update",
                "thresholds": cls.get_thresholds(),
            }
        )
        return cls.get_thresholds()

    @classmethod
    def get_thresholds(cls) -> Dict[str, float]:
        low, medium, critical = cls._thresholds
        return {
            "low": low,
            "medium": medium,
            "critical": critical,
        }

    @classmethod
    def evaluate_and_respond(
        cls,
        *,
        host_name: str,
        activity_type: str,
        prediction: str,
        probability: float,
    ) -> Dict[str, Any]:
        """
        Accepts model outcome + activity metadata and returns response action.
        """
        if not cls._initialized:
            raise RuntimeError("Orchestrator not initialized. Call initialize_and_reset() first.")

        pred = (prediction or "Normal").strip().lower()
        normalized_activity = cls._normalize_activity(activity_type)
        dtype_action = cls._type_policy.get(normalized_activity, "Unknown Activity Policy")

        if pred != "attack" or probability < cls._thresholds[0]:
            level = "NONE"
            action = "No Preventive Action"
            response_message = (
                f"No prevention triggered for {host_name}. "
                f"Prediction={prediction}, probability={probability:.3f}."
            )
            result = cls._build_result(
                host_name=host_name,
                activity_type=normalized_activity,
                level=level,
                action=action,
                response_message=response_message,
                popup=False,
            )
            cls._write_log(
                {
                    "event": "observe_only",
                    "host_name": host_name,
                    "activity_type": normalized_activity,
                    "prediction": prediction,
                    "probability": probability,
                    "message": response_message,
                }
            )
            return result

        level, generic_action = cls._decision_level(probability)
        action = f"{generic_action} + {dtype_action}"
        response_message = (
            f"Threat detected ({level}) on host {host_name} for activity {normalized_activity} "
            f"(prob={probability:.3f}). Planned response: {action}."
        )

        if level in {"MEDIUM", "CRITICAL"}:
            cls._active_constraints[host_name] = {
                "activity_type": normalized_activity,
                "action": action,
                "probability": probability,
                "updated_at": datetime.datetime.utcnow().isoformat(),
            }

        cls._write_log(
            {
                "event": "preventive_decision",
                "host_name": host_name,
                "activity_type": normalized_activity,
                "prediction": prediction,
                "probability": probability,
                "level": level,
                "action": action,
                "test_mode": cls._test_mode,
                "response_message": response_message,
            }
        )

        return cls._build_result(
            host_name=host_name,
            activity_type=normalized_activity,
            level=level,
            action=action,
            response_message=response_message,
            popup=True,
        )

    @classmethod
    def get_recent_logs(cls, limit: int = 100) -> List[Dict[str, Any]]:
        if not cls._log_path or not os.path.exists(cls._log_path):
            return []

        with open(cls._log_path, "r", encoding="utf-8") as f:
            lines = f.readlines()[-max(limit, 1):]

        parsed: List[Dict[str, Any]] = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                parsed.append(json.loads(line))
            except json.JSONDecodeError:
                parsed.append({"raw": line})
        return parsed

    @classmethod
    def get_status(cls) -> Dict[str, Any]:
        return {
            "initialized": cls._initialized,
            "test_mode": cls._test_mode,
            "thresholds": cls.get_thresholds(),
            "active_constraints": cls._active_constraints,
            "log_path": cls._log_path,
        }

    @classmethod
    def _normalize_activity(cls, activity_type: str) -> str:
        token = (activity_type or "").strip().upper()
        if token in {"EMAIL", "FILE", "HTTP"}:
            return token
        if "MAIL" in token:
            return "EMAIL"
        if token in {"WEB", "NETWORK", "NET"}:
            return "HTTP"
        if token:
            return "FILE"
        return "FILE"

    @classmethod
    def _decision_level(cls, probability: float) -> Tuple[str, str]:
        _, t_medium, t_critical = cls._thresholds
        if probability > t_critical:
            return "CRITICAL", "Account Lock / Host Network Isolation"
        if probability >= t_medium:
            return "MEDIUM", "MFA Challenge / Temporary Privilege Restriction"
        return "LOW", "Log and Monitor Employee Activity"

    @classmethod
    def _build_result(
        cls,
        *,
        host_name: str,
        activity_type: str,
        level: str,
        action: str,
        response_message: str,
        popup: bool,
    ) -> Dict[str, Any]:
        popup_payload = None
        if popup:
            popup_payload = {
                "title": "Insider Threat Prevention",
                "message": response_message,
                "level": level,
                "host_name": host_name,
            }

        return {
            "test_mode": cls._test_mode,
            "activity_type": activity_type,
            "level": level,
            "action": action,
            "response_message": response_message,
            "popup": popup_payload,
        }

    @classmethod
    def _write_log(cls, payload: Dict[str, Any]) -> None:
        if not cls._log_path:
            return

        record = {"time": datetime.datetime.utcnow().isoformat(), **payload}
        with open(cls._log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
