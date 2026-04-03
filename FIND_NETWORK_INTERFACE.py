#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Find the correct network interface name for Scapy on Windows.
Maps friendly names from ipconfig to Npcap GUID-based names.
"""
import subprocess
import sys
import re
import io

# Fix encoding for Windows console
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

def get_scapy_interfaces():
    """Get all interface names that Scapy can see on Windows."""
    try:
        from scapy.all import get_if_list
        return get_if_list()
    except Exception as e:
        print(f"ERROR: Error getting interfaces: {e}")
        return []

def get_ipconfig_interfaces():
    """Get friendly interface names from ipconfig."""
    try:
        result = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True)
        interfaces = {}
        current_adapter = None

        for line in result.stdout.split('\n'):
            # Match adapter lines (e.g., "Ethernet adapter VMware Virtual Ethernet Adapter for VMnet1:")
            if 'adapter' in line.lower() and ':' in line:
                # Extract friendly name
                match = re.search(r'adapter\s+(.+?):', line, re.IGNORECASE)
                if match:
                    current_adapter = match.group(1).strip()
                    interfaces[current_adapter] = {}

            # Match MAC address (physical address)
            if current_adapter and 'physical address' in line.lower():
                match = re.search(r':\s+([0-9A-Fa-f\-]+)', line)
                if match:
                    interfaces[current_adapter]['mac'] = match.group(1).upper()

            # Match IPv4
            if current_adapter and 'ipv4 address' in line.lower() and 'dhcp' not in line.lower():
                match = re.search(r':\s+(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    interfaces[current_adapter]['ipv4'] = match.group(1)

        return interfaces
    except Exception as e:
        print(f"Error getting ipconfig: {e}")
        return {}

def map_interfaces():
    """Map friendly names to Npcap interface names."""
    scapy_interfaces = get_scapy_interfaces()
    ipconfig_interfaces = get_ipconfig_interfaces()

    print("\n" + "="*70)
    print("  Network Interface Detection for Scapy/Npcap")
    print("="*70 + "\n")

    print("[*] Scapy/Npcap Interfaces (what Scapy sees):")
    for iface in scapy_interfaces:
        print(f"  • {iface}")

    print("\n[*] Friendly Names (from ipconfig):")
    for name, info in ipconfig_interfaces.items():
        ipv4 = info.get('ipv4', 'N/A')
        print(f"  • {name}")
        print(f"    └─ IPv4: {ipv4}")

    print("\n" + "="*70)

    # Look for VMnet1
    vmware_interfaces = {name: info for name, info in ipconfig_interfaces.items()
                        if 'vmware' in name.lower() or 'vmnet' in name.lower()}

    if vmware_interfaces:
        print("\n[+] VMware/VMnet Interfaces Found:\n")
        for idx, (name, info) in enumerate(vmware_interfaces.items(), 1):
            ipv4 = info.get('ipv4', 'N/A')
            mac = info.get('mac', 'N/A')
            print(f"{idx}. {name}")
            print(f"   IPv4: {ipv4}")
            print(f"   MAC: {mac}")

        print("\n" + "="*70)
        print("[*] INSTRUCTIONS:\n")
        print("For Scapy/Npcap on Windows, use the FRIENDLY NAME:\n")
        print("Edit: project/network_module/config/settings.py")
        print("Update DEFAULT_IFACE to the name below\n")

        # Try to extract the correct interface
        for name in vmware_interfaces.keys():
            if 'vmnet1' in name.lower():
                print(f"[+] DETECTED VMnet1: {name}")
                print(f"\nSet this in settings.py:")
                print(f'DEFAULT_IFACE = "{name}"')
                return name

        # Just use any VMware interface found
        first_vmware = list(vmware_interfaces.keys())[0]
        print(f"[+] Using first VMware interface: {first_vmware}")
        print(f'DEFAULT_IFACE = "{first_vmware}"')
        return first_vmware
    else:
        print("\n[-] NO VMware Interface Found!")
        print("\nVerify:")
        print("  1. VMware adapter VMnet1 is enabled")
        print("  2. Npcap is installed: https://npcap.com")
        print("  3. Run: ipconfig /all (manually check for VMnet1)\n")
        return None

def main():
    print("\n[*] Scanning for network interfaces...\n")
    interface = map_interfaces()

    if interface:
        print("\n" + "="*70)
        print("[+] READY TO CONFIGURE!\n")
        print(f"Edit: project/network_module/config/settings.py")
        print(f'Change DEFAULT_IFACE to: "{interface}"')
        print("="*70 + "\n")
        sys.exit(0)
    else:
        print("\n" + "="*70)
        print("[-] CANNOT PROCEED!")
        print("Please enable VMware adapter VMnet1 first")
        print("="*70 + "\n")
        sys.exit(1)

if __name__ == "__main__":
    main()


