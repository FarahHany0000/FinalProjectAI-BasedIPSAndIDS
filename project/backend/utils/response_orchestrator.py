import datetime
import json
import os
import subprocess
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
    In LIVE_MODE, executes real OS-level prevention (firewall rules).
    """

    _initialized = False
    _test_mode = True
    _thresholds: Tuple[float, float, float] = (0.5, 0.7, 0.9)
    _log_path: str = ""
    _active_constraints: Dict[str, Dict[str, Any]] = {}
    _blocked_hosts: Dict[str, Dict[str, Any]] = {}

    _type_policy = {
        "EMAIL": "Quarantine Action",
        "FILE": "Read-only Enforcement",
        "HTTP": "Connection Reset Action",
    }

    RULE_PREFIX = "IPS_HOST_BLOCK"

    @classmethod
    def initialize_and_reset(cls, config: Dict[str, Any]) -> None:
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
        cls._blocked_hosts = {}
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
        host_ip: str = "",
    ) -> Dict[str, Any]:
        """
        Accepts model outcome + activity metadata and returns response action.
        In LIVE mode with CRITICAL/MEDIUM: executes real firewall blocking.
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
                firewall_applied=False,
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

        firewall_applied = False

        # LIVE MODE: Execute real OS-level prevention
        if not cls._test_mode and host_ip and level in {"MEDIUM", "CRITICAL"}:
            firewall_applied = cls._apply_host_firewall_block(host_ip, host_name, level)
            if firewall_applied:
                action += " [FIREWALL BLOCK ACTIVE]"

        mode_label = "TEST" if cls._test_mode else "LIVE"
        response_message = (
            f"[{mode_label}] Threat detected ({level}) on host {host_name} "
            f"for activity {normalized_activity} "
            f"(prob={probability:.3f}). Response: {action}."
        )

        if level in {"MEDIUM", "CRITICAL"}:
            cls._active_constraints[host_name] = {
                "activity_type": normalized_activity,
                "action": action,
                "probability": probability,
                "level": level,
                "firewall_applied": firewall_applied,
                "host_ip": host_ip,
                "updated_at": datetime.datetime.utcnow().isoformat(),
            }

        cls._write_log(
            {
                "event": "preventive_decision",
                "host_name": host_name,
                "host_ip": host_ip,
                "activity_type": normalized_activity,
                "prediction": prediction,
                "probability": probability,
                "level": level,
                "action": action,
                "test_mode": cls._test_mode,
                "firewall_applied": firewall_applied,
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
            firewall_applied=firewall_applied,
        )

    # ── Firewall Management ──

    @classmethod
    def _apply_host_firewall_block(cls, ip: str, host_name: str, level: str) -> bool:
        """Block a host's IP via Windows Firewall. Returns True if successful."""
        rule_name = f"{cls.RULE_PREFIX}_{ip.replace('.', '_')}"
        try:
            result = subprocess.run(
                ["netsh", "advfirewall", "firewall", "add", "rule",
                 f"name={rule_name}", "dir=in", "action=block",
                 f"remoteip={ip}", "enable=yes"],
                capture_output=True, text=True, timeout=10
            )
            success = result.returncode == 0
            if success:
                cls._blocked_hosts[ip] = {
                    "host_name": host_name,
                    "rule_name": rule_name,
                    "level": level,
                    "blocked_at": datetime.datetime.utcnow().isoformat(),
                }
                print(f"[HOST PREVENTION] BLOCKED host IP: {ip} ({host_name}) — Level: {level}")

                cls._write_log({
                    "event": "firewall_block_applied",
                    "host_name": host_name,
                    "host_ip": ip,
                    "rule_name": rule_name,
                    "level": level,
                    "proof": f"Verify: netsh advfirewall firewall show rule name={rule_name}",
                })
            else:
                print(f"[HOST PREVENTION] Failed to block {ip}: {result.stderr}")
                cls._write_log({
                    "event": "firewall_block_failed",
                    "host_ip": ip,
                    "error": result.stderr,
                })
            return success
        except Exception as e:
            print(f"[HOST PREVENTION] Exception blocking {ip}: {e}")
            cls._write_log({"event": "firewall_block_error", "host_ip": ip, "error": str(e)})
            return False

    @classmethod
    def remove_host_block(cls, ip: str) -> bool:
        """Remove a firewall block for a specific host IP. Returns True if successful."""
        rule_name = f"{cls.RULE_PREFIX}_{ip.replace('.', '_')}"
        try:
            result = subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule",
                 f"name={rule_name}"],
                capture_output=True, text=True, timeout=10
            )
            success = result.returncode == 0
            if success:
                cls._blocked_hosts.pop(ip, None)
                cls._active_constraints = {
                    k: v for k, v in cls._active_constraints.items()
                    if v.get("host_ip") != ip
                }
                print(f"[HOST PREVENTION] UNBLOCKED host IP: {ip}")
                cls._write_log({"event": "firewall_block_removed", "host_ip": ip, "rule_name": rule_name})
            return success
        except Exception as e:
            print(f"[HOST PREVENTION] Failed to unblock {ip}: {e}")
            return False

    @classmethod
    def remove_all_host_blocks(cls) -> int:
        """Remove all IPS_HOST_BLOCK firewall rules. Returns count removed."""
        removed = 0
        try:
            result = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
                capture_output=True, text=True, timeout=15
            )
            for line in result.stdout.split("\n"):
                if cls.RULE_PREFIX in line:
                    rule_name = line.split(":")[-1].strip()
                    subprocess.run(
                        ["netsh", "advfirewall", "firewall", "delete", "rule",
                         f"name={rule_name}"],
                        capture_output=True, text=True, timeout=10
                    )
                    removed += 1
            cls._blocked_hosts.clear()
            cls._active_constraints.clear()
            print(f"[HOST PREVENTION] Removed {removed} firewall rules")
        except Exception as e:
            print(f"[HOST PREVENTION] Error removing rules: {e}")
        return removed

    @classmethod
    def verify_firewall_rules(cls) -> List[Dict[str, str]]:
        """Verify which IPS_HOST_BLOCK firewall rules actually exist in the OS."""
        rules = []
        try:
            result = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
                capture_output=True, text=True, timeout=15
            )
            current_rule = {}
            for line in result.stdout.split("\n"):
                line = line.strip()
                if line.startswith("Rule Name:") and cls.RULE_PREFIX in line:
                    current_rule = {"name": line.split(":", 1)[1].strip()}
                elif current_rule:
                    if line.startswith("RemoteIP:"):
                        current_rule["ip"] = line.split(":", 1)[1].strip()
                    elif line.startswith("Action:"):
                        current_rule["action"] = line.split(":", 1)[1].strip()
                    elif line.startswith("Enabled:"):
                        current_rule["enabled"] = line.split(":", 1)[1].strip()
                        rules.append(current_rule)
                        current_rule = {}
        except Exception as e:
            print(f"[HOST PREVENTION] Error verifying rules: {e}")
        return rules

    @classmethod
    def get_blocked_hosts(cls) -> Dict[str, Dict[str, Any]]:
        """Return currently blocked hosts (in-memory + verify with OS)."""
        return dict(cls._blocked_hosts)

    # ── Existing methods ──

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
            "blocked_hosts": cls._blocked_hosts,
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
            return "CRITICAL", "Host Network Isolation"
        if probability >= t_medium:
            return "MEDIUM", "Temporary Network Restriction"
        return "LOW", "Log and Monitor Activity"

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
        firewall_applied: bool = False,
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
            "firewall_applied": firewall_applied,
        }

    @classmethod
    def _write_log(cls, payload: Dict[str, Any]) -> None:
        if not cls._log_path:
            return

        record = {"time": datetime.datetime.utcnow().isoformat(), **payload}
        with open(cls._log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
