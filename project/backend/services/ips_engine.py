def prevent_attack(attack_type):

    if attack_type == "DDoS":

        return "Traffic Dropped"

    elif attack_type == "Port Scan":

        return "IP Blacklisted"

    elif attack_type == "Brute Force":

        return "Account Locked"

    elif attack_type == "Malware":

        return "Host Isolated"

    else:

        return "Connection Reset"