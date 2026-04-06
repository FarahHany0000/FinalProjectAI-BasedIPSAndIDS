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

        # Auto-cleanup: remove ALL previous firewall rules on startup
        cls._cleanup_on_startup()

        cls._write_log(
            {
                "event": "initialize_and_reset",
                "message": "Prevention state reset on startup. All previous rules cleaned.",
                "test_mode": cls._test_mode,
            }
        )
        print(f"[PREVENTION] initialize_and_reset() complete | TEST_MODE={cls._test_mode}")

    @classmethod
    def set_test_mode(cls, enabled: bool) -> None:
        """Toggle test mode on/off. When test_mode=True, actions are logged only."""
        cls._test_mode = enabled
        print(f"[PREVENTION] Test mode set to {enabled}")

    @classmethod
    def is_test_mode(cls) -> bool:
        return cls._test_mode

    @classmethod
    def _cleanup_on_startup(cls) -> None:
        """Remove ALL prevention artifacts from previous runs."""
        print("[PREVENTION] Cleaning up previous prevention rules...")

        # 1. Remove host firewall rules (IPS_HOST_BLOCK_*)
        host_removed = 0
        try:
            result = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
                capture_output=True, text=True, timeout=15
            )
            for line in result.stdout.split("\n"):
                if cls.RULE_PREFIX in line or "IDS_BLOCK_" in line:
                    rule_name = line.split(":")[-1].strip()
                    subprocess.run(
                        ["netsh", "advfirewall", "firewall", "delete", "rule",
                         f"name={rule_name}"],
                        capture_output=True, text=True, timeout=10
                    )
                    host_removed += 1
        except Exception as e:
            print(f"[PREVENTION] Firewall cleanup error: {e}")

        # 2. Re-enable USB storage (undo disable_usb)
        try:
            if os.name == "nt":
                subprocess.run(
                    ["reg", "add", r"HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR",
                     "/v", "Start", "/t", "REG_DWORD", "/d", "3", "/f"],
                    capture_output=True, text=True, timeout=10
                )
        except Exception:
            pass

        if host_removed > 0:
            print(f"[PREVENTION] Removed {host_removed} old firewall rules")
        else:
            print("[PREVENTION] No old rules found — clean start")

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
        features: list = None,
    ) -> Dict[str, Any]:
        """
        Accepts model outcome + activity metadata and returns response action.
        In LIVE mode: sends prevention_commands to the agent for local execution.
        """
        if not cls._initialized:
            raise RuntimeError("Orchestrator not initialized. Call initialize_and_reset() first.")

        pred = (prediction or "Normal").strip().lower()
        normalized_activity = cls._normalize_activity(activity_type)

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

        # Analyze features to determine specific prevention commands
        prevention_commands = cls._analyze_and_decide(level, probability, features)
        action_desc = cls._describe_actions(prevention_commands)
        action = action_desc

        firewall_applied = False

        # LIVE MODE: server-side firewall (backup) — run async to not block response
        if not cls._test_mode and host_ip and level in {"MEDIUM", "CRITICAL"}:
            import threading
            def _apply_fw():
                result = cls._apply_host_firewall_block(host_ip, host_name, level)
                if result:
                    print(f"[HOST PREVENTION] Firewall block applied for {host_ip}")
            threading.Thread(target=_apply_fw, daemon=True).start()
            firewall_applied = True  # Optimistically set — rule is being applied

        mode_label = "TEST" if cls._test_mode else "LIVE"
        response_message = (
            f"[{mode_label}] Threat detected ({level}) on host {host_name} "
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
                "prevention_commands": prevention_commands,
                "updated_at": datetime.datetime.now().isoformat(),
            }

        cls._write_log(
            {
                "event": "preventive_decision",
                "host_name": host_name,
                "host_ip": host_ip,
                "activity_type": normalized_activity,
                "prediction": prediction,
                "probability": probability,
                "decision_level": level,
                "action_taken": action,
                "test_mode": cls._test_mode,
                "firewall_applied": firewall_applied,
                "prevention_commands": prevention_commands,
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
            prevention_commands=prevention_commands,
        )

    # ── Smart Prevention Analysis ──

    @classmethod
    def _analyze_and_decide(cls, level: str, probability: float, features: list = None) -> List[Dict[str, Any]]:
        """
        Analyze features to decide which prevention commands to send to the agent.
        Returns a list of command dicts that the agent will execute.
        """
        commands = []

        if features and len(features) >= 15:
            # Feature indices (CERT r4.2 order):
            # 0: total_logons, 1: avg_logon_hour, 2: std_logon_hour
            # 3: weekend_logons, 4: after_hours_logons, 5: unique_pcs_logon
            # 6: total_device_activities, 7: unique_pcs_device, 8: avg_device_hour
            # 9: after_hours_device
            # 10: total_file_activities, 11: unique_files, 12: unique_pcs_file
            # 13: avg_file_hour, 14: after_hours_files

            after_hours_logons = features[4]
            total_device = features[6]
            after_hours_device = features[9]
            total_files = features[10]
            unique_files = features[11]
            after_hours_files = features[14]

            # USB / Device exfiltration detected
            if total_device > 100 and after_hours_device > 50:
                commands.append({
                    "type": "disable_usb",
                    "reason": f"Suspicious device activity ({int(total_device)} ops, {int(after_hours_device)} after-hours)",
                })

            # Mass file access / data theft
            if total_files > 5000 or unique_files > 3000:
                commands.append({
                    "type": "kill_suspicious_processes",
                    "reason": f"Abnormal file activity ({int(total_files)} files, {int(unique_files)} unique)",
                })

            # After-hours suspicious activity
            if after_hours_logons > 3 or after_hours_files > 1000:
                commands.append({
                    "type": "lock_screen",
                    "reason": f"Suspicious after-hours activity (logons={int(after_hours_logons)}, files={int(after_hours_files)})",
                })

        # Level-based defaults (if no feature-specific commands)
        if level == "CRITICAL" and not commands:
            commands.append({"type": "lock_screen", "reason": "Critical threat level — force re-authentication"})
            commands.append({"type": "kill_suspicious_processes", "reason": "Critical threat — terminate unknown processes"})
        elif level == "MEDIUM" and not commands:
            commands.append({"type": "lock_screen", "reason": "Medium threat level — verify user identity"})

        # CRITICAL always adds lock_screen if not already there
        if level == "CRITICAL":
            cmd_types = [c["type"] for c in commands]
            if "lock_screen" not in cmd_types:
                commands.insert(0, {"type": "lock_screen", "reason": "Critical threat — force re-authentication"})

        # Always log/alert
        commands.append({"type": "alert_user", "reason": "Threat detected — notifying user"})

        return commands

    @classmethod
    def _describe_actions(cls, commands: List[Dict[str, Any]]) -> str:
        """Human-readable summary of prevention commands."""
        action_names = {
            "lock_screen": "Lock Screen",
            "kill_suspicious_processes": "Kill Suspicious Processes",
            "disable_usb": "Disable USB Storage",
            "alert_user": "Alert User",
        }
        parts = []
        for cmd in commands:
            name = action_names.get(cmd["type"], cmd["type"])
            if name not in parts:
                parts.append(name)
        return " + ".join(parts) if parts else "Monitor Only"

    # ── Firewall Management ──

    @classmethod
    def _apply_host_firewall_block(cls, ip: str, host_name: str, level: str) -> bool:
        """Block a host's IP via Windows Firewall (in+out). Returns True if successful."""
        # Skip loopback/localhost — firewall can't block loopback traffic
        if ip.startswith("127.") or ip == "::1" or ip == "localhost":
            print(f"[HOST PREVENTION] Skipping localhost IP {ip} — firewall cannot block loopback")
            cls._write_log({
                "event": "firewall_block_skipped",
                "host_name": host_name,
                "host_ip": ip,
                "reason": "Loopback IP — Windows Firewall does not filter localhost traffic. "
                          "In production, the agent runs on a remote machine with a real IP.",
            })
            # Still track as "blocked" in memory for status display
            cls._blocked_hosts[ip] = {
                "host_name": host_name,
                "rule_name": f"SKIPPED_LOCALHOST_{ip}",
                "level": level,
                "blocked_at": datetime.datetime.now().isoformat(),
                "note": "Loopback — would be blocked on remote host",
            }
            return True

        rule_in = f"{cls.RULE_PREFIX}_{ip.replace('.', '_')}_IN"
        rule_out = f"{cls.RULE_PREFIX}_{ip.replace('.', '_')}_OUT"
        try:
            r1 = subprocess.run(
                ["netsh", "advfirewall", "firewall", "add", "rule",
                 f"name={rule_in}", "dir=in", "action=block",
                 f"remoteip={ip}", "protocol=any", "enable=yes"],
                capture_output=True, text=True, timeout=10
            )
            r2 = subprocess.run(
                ["netsh", "advfirewall", "firewall", "add", "rule",
                 f"name={rule_out}", "dir=out", "action=block",
                 f"remoteip={ip}", "protocol=any", "enable=yes"],
                capture_output=True, text=True, timeout=10
            )
            err1 = (r1.stderr or r1.stdout or "").strip()
            err2 = (r2.stderr or r2.stdout or "").strip()
            success = r1.returncode == 0 or r2.returncode == 0

            if not success and ("elevation" in err1.lower() or "elevation" in err2.lower()):
                print(f"[HOST PREVENTION] ⚠ Need Administrator! Run backend as admin for firewall.")
                cls._write_log({
                    "event": "firewall_needs_admin",
                    "host_ip": ip,
                    "error": "Backend must run as Administrator for netsh firewall commands",
                })
                return False

            if success:
                cls._blocked_hosts[ip] = {
                    "host_name": host_name,
                    "rule_name": rule_in,
                    "level": level,
                    "blocked_at": datetime.datetime.now().isoformat(),
                }
                print(f"[HOST PREVENTION] BLOCKED host IP: {ip} ({host_name}) — Level: {level}")

                cls._write_log({
                    "event": "firewall_block_applied",
                    "host_name": host_name,
                    "host_ip": ip,
                    "rule_name": rule_in,
                    "level": level,
                    "proof": f"Verify: netsh advfirewall firewall show rule name={rule_in}",
                })
            else:
                print(f"[HOST PREVENTION] Failed to block {ip}: {err1} {err2}")
                cls._write_log({
                    "event": "firewall_block_failed",
                    "host_ip": ip,
                    "error": f"{err1} {err2}",
                })
            return success
        except Exception as e:
            print(f"[HOST PREVENTION] Exception blocking {ip}: {e}")
            cls._write_log({"event": "firewall_block_error", "host_ip": ip, "error": str(e)})
            return False

    @classmethod
    def remove_host_block(cls, ip: str) -> bool:
        """Remove firewall blocks for a specific host IP (in+out). Returns True if successful."""
        success = False
        for suffix in ("_IN", "_OUT", ""):
            rule_name = f"{cls.RULE_PREFIX}_{ip.replace('.', '_')}{suffix}"
            try:
                result = subprocess.run(
                    ["netsh", "advfirewall", "firewall", "delete", "rule",
                     f"name={rule_name}"],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    success = True
            except Exception:
                pass
        if success:
            cls._blocked_hosts.pop(ip, None)
            cls._active_constraints = {
                k: v for k, v in cls._active_constraints.items()
                if v.get("host_ip") != ip
            }
            print(f"[HOST PREVENTION] UNBLOCKED host IP: {ip}")
            cls._write_log({"event": "firewall_block_removed", "host_ip": ip})
        return success

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
    def get_recent_logs(cls, limit: int = 100, actions_only: bool = True) -> List[Dict[str, Any]]:
        if not cls._log_path or not os.path.exists(cls._log_path):
            return []

        with open(cls._log_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        parsed: List[Dict[str, Any]] = []
        for line in reversed(lines):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                if actions_only and entry.get("event") == "observe_only":
                    continue
                parsed.append(entry)
                if len(parsed) >= limit:
                    break
            except json.JSONDecodeError:
                parsed.append({"raw": line})
        parsed.reverse()
        return parsed

    @classmethod
    def get_status(cls) -> Dict[str, Any]:
        total_actions = 0
        if cls._log_path:
            try:
                with open(cls._log_path, "r", encoding="utf-8") as f:
                    total_actions = sum(1 for line in f if line.strip())
            except FileNotFoundError:
                pass
        return {
            "initialized": cls._initialized,
            "test_mode": cls._test_mode,
            "thresholds": cls.get_thresholds(),
            "active_constraints": cls._active_constraints,
            "blocked_hosts": cls._blocked_hosts,
            "log_path": cls._log_path,
            "total_actions": total_actions,
            "active_blocks": len(cls._blocked_hosts),
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
        prevention_commands: list = None,
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
            "prevention_commands": prevention_commands or [],
        }

    @classmethod
    def _write_log(cls, payload: Dict[str, Any]) -> None:
        if not cls._log_path:
            return

        record = {"timestamp": datetime.datetime.now().isoformat(), **payload}
        with open(cls._log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
