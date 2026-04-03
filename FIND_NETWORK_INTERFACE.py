#!/usr/bin/env python
"""
Find the correct network interface name for Scapy on Windows.
The name shown in ipconfig may differ from the Scapy/Npcap interface name.
"""
import subprocess
import sys

def get_scapy_interfaces():
    """Get all interface names that Scapy can see on Windows."""
    try:
        from scapy.all import get_if_list
        return get_if_list()
    except Exception as e:
        print(f"❌ Error getting interfaces: {e}")
        return []

def find_vmware_interface():
    """Find the VMware network interface."""
    interfaces = get_scapy_interfaces()

    print("\n" + "="*60)
    print("  Available Network Interfaces (Scapy/Npcap)")
    print("="*60 + "\n")

    vmware_found = False

    for iface in interfaces:
        print(f"  • {iface}")
        if "VMware" in iface or "vmware" in iface or "VMnet" in iface:
            print(f"    ⭐ THIS LOOKS LIKE VMWARE!")
            vmware_found = True

    print("\n" + "="*60)

    if vmware_found:
        print("  ✅ VMware interface found above!")
        print("\n  Update this in: project/network_module/config/settings.py")
        print("  Change: DEFAULT_IFACE = \"Ethernet 2\"")
        print("  To:     DEFAULT_IFACE = \"<interface name from above>\"")
    else:
        print("  ⚠️  No VMware interface found!")
        print("\n  Make sure:")
        print("    1. VMware Adapter VMnet1 is created")
        print("    2. Npcap is installed (https://npcap.com)")
        print("    3. Run: ipconfig /all (to verify VMnet1 exists)")

    print("\n" + "="*60 + "\n")

    return vmware_found

def main():
    print("\nScanning for network interfaces...\n")
    success = find_vmware_interface()

    if success:
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()
