#!/usr/bin/env python3
"""
Quick installer for the IDS Host Agent.
Run: python install_agent.py
"""
import subprocess
import sys
import os

def main():
    print("=" * 50)
    print("  IDS Host Agent — Quick Setup")
    print("=" * 50)

    # Create venv if not already in one
    in_venv = sys.prefix != sys.base_prefix
    venv_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "venv")
    python_exe = sys.executable

    if not in_venv:
        print("\n[1/4] Creating virtual environment...")
        if not os.path.exists(venv_dir):
            subprocess.check_call([sys.executable, "-m", "venv", venv_dir])
            print("  ✓ venv created")
        else:
            print("  ✓ venv already exists")

        # Use the venv python
        if os.name == "nt":
            python_exe = os.path.join(venv_dir, "Scripts", "python.exe")
        else:
            python_exe = os.path.join(venv_dir, "bin", "python")
    else:
        print("\n[1/4] Already in virtual environment ✓")

    # Install dependencies
    print("\n[2/4] Installing dependencies...")
    subprocess.check_call([python_exe, "-m", "pip", "install", "-r", "requirements.txt", "--quiet"])
    print("  ✓ Dependencies installed")

    # Check config
    print("\n[3/4] Checking configuration...")
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.ini")
    if os.path.exists(config_path):
        print("  ✓ Config file found")
        print("  ℹ Default settings work out of the box — no changes needed!")
    else:
        print("  ✗ config.ini not found! Create one before running the agent.")
        return

    # Ready
    print("\n[4/4] Ready to start!")
    print("\n" + "=" * 50)
    print("  HOW TO RUN:")
    print("=" * 50)

    if os.name == "nt":
        activate = os.path.join(venv_dir, "Scripts", "activate")
        print(f"\n  Option 1 (recommended):")
        print(f"    {activate}")
        print(f"    python host_agent.py --server <SERVER_IP>:5000")
        print(f"\n  Option 2 (direct):")
        print(f"    {python_exe} host_agent.py --server <SERVER_IP>:5000")
    else:
        activate = f"source {os.path.join(venv_dir, 'bin', 'activate')}"
        print(f"\n  Option 1 (recommended):")
        print(f"    {activate}")
        print(f"    python host_agent.py --server <SERVER_IP>:5000")
        print(f"\n  Option 2 (direct):")
        print(f"    {python_exe} host_agent.py --server <SERVER_IP>:5000")

    print(f"\n  Replace <SERVER_IP> with the IDS server IP address.")
    print(f"  Example: python host_agent.py --server 192.168.137.1:5000")
    print()

if __name__ == "__main__":
    main()
