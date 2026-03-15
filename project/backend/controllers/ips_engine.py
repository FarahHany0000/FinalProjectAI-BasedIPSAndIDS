class IPSEngine:
    """Intrusion Prevention System — actions to take when threats are detected."""

    @staticmethod
    def get_action(attack_type):
        """Return the prevention action for a given attack type."""
        actions = {
            "DDoS": "Traffic Dropped",
            "Port Scan": "IP Blacklisted",
            "Brute Force": "Account Locked",
            "Malware": "Host Isolated",
        }
        return actions.get(attack_type, "Connection Reset")
