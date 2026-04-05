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
    
    # Install dependencies
    print("\n[1/3] Installing dependencies...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt", "--quiet"])
    print("  ✓ Dependencies installed")
    
    # Check config
    print("\n[2/3] Checking configuration...")
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.ini")
    if os.path.exists(config_path):
        with open(config_path, "r") as f:
            content = f.read()
        if "changeme" in content:
            print("  ⚠ WARNING: Using default agent key 'changeme'.")
            print("    Edit config.ini and set a secure agent_key!")
        if "AUTO" in content:
            print("  ℹ Server discovery set to AUTO (will broadcast to find server)")
        print("  ✓ Config file found")
    else:
        print("  ✗ config.ini not found! Create one before running the agent.")
        return
    
    # Test run
    print("\n[3/3] Ready to start!")
    print("\nTo run the agent:")
    print(f"  {sys.executable} host_agent.py")
    print("\nOr with custom server:")
    print(f"  {sys.executable} host_agent.py --server 192.168.1.100:5000")
    print()

if __name__ == "__main__":
    main()
