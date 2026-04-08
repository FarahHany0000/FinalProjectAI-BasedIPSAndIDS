#!/usr/bin/env python3
"""
==========================================================================
  Host Attack Simulation — CERT r4.2 Insider Threat (Real Behavior)
==========================================================================
  This script is SEPARATE from the IDS system.
  It creates REAL activity on the machine so the Host Agent detects it.

  Flow:
    1. This script runs attack behavior (file ops, USB, network traffic)
    2. The Host Agent (running separately) collects features from the machine
    3. Agent sends features → Backend → AI Model → Detection → Prevention

  Think of it like the ARP spoofing script from Kali — it's the attacker.
  The difference: insider threats come from INSIDE the machine.

  SAFETY:
    ✓ All files created in temp directories inside Desktop/Documents
    ✓ Everything is cleaned up automatically on exit
    ✓ No system changes (no registry, no services)
    ✓ USB simulation uses 'subst' (virtual drive letter, easily removed)
    ✓ Ctrl+C triggers immediate cleanup

  Usage:
    python host_attack_simulation.py
==========================================================================
"""

import os
import sys
import time
import shutil
import signal
import atexit
import string
import ctypes
import socket
import random
import subprocess
import threading
from datetime import datetime

# ─────────────────────────────────────────────────────────
# Safety: Track everything we create for guaranteed cleanup
# ─────────────────────────────────────────────────────────

_sim_dirs = []           # Directories we created
_subst_drives = []       # Virtual drives we mounted
_cleanup_done = False
_stop_event = threading.Event()


def _cleanup():
    """Clean up ALL simulation artifacts. Called on exit, Ctrl+C, or errors."""
    global _cleanup_done
    if _cleanup_done:
        return
    _cleanup_done = True

    print("\n" + "=" * 60)
    print("  🧹 CLEANING UP — Restoring machine to original state...")
    print("=" * 60)

    # Remove virtual drives first (so we can delete their backing dirs)
    for drive in _subst_drives[:]:
        try:
            result = subprocess.run(
                ["subst", drive, "/d"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                print(f"  ✓ Removed virtual drive {drive}")
            else:
                print(f"  ✗ Could not remove {drive}: {result.stderr.strip()}")
        except Exception as e:
            print(f"  ✗ Error removing {drive}: {e}")
    _subst_drives.clear()

    # Delete all simulation directories
    for d in _sim_dirs[:]:
        try:
            if os.path.exists(d):
                shutil.rmtree(d, ignore_errors=True)
                print(f"  ✓ Removed {d}")
        except Exception as e:
            print(f"  ✗ Error removing {d}: {e}")
    _sim_dirs.clear()

    print("  ✅ Machine is clean — no traces left.")
    print("=" * 60)


# Register cleanup for ALL exit scenarios
atexit.register(_cleanup)


def _signal_handler(sig, frame):
    print("\n\n  [Ctrl+C] Stopping simulation...")
    _stop_event.set()
    _cleanup()
    sys.exit(0)


signal.signal(signal.SIGINT, _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)


# ─────────────────────────────────────────────────────────
# Utility Functions
# ─────────────────────────────────────────────────────────

HOME = os.path.expanduser("~")
DESKTOP = os.path.join(HOME, "Desktop")
DOCUMENTS = os.path.join(HOME, "Documents")
DOWNLOADS = os.path.join(HOME, "Downloads")

# Use Desktop for simulation (smaller dir = faster agent scan + visible to user)
SIM_BASE = os.path.join(DESKTOP, "_IDS_ATTACK_SIMULATION")


def _create_sim_dir(name):
    """Create a tracked simulation directory."""
    path = os.path.join(SIM_BASE, name)
    os.makedirs(path, exist_ok=True)
    if SIM_BASE not in _sim_dirs:
        _sim_dirs.append(SIM_BASE)
    return path


def _find_free_drive():
    """Find an unused drive letter for USB simulation."""
    used = set()
    bitmask = ctypes.windll.kernel32.GetLogicalDrives()
    for i in range(26):
        if bitmask & (1 << i):
            used.add(chr(ord('A') + i))
    # Try Z, Y, X... (less likely to conflict)
    for letter in reversed(string.ascii_uppercase):
        if letter not in used:
            return letter
    return None


def _find_real_usb():
    """Find a real removable USB drive."""
    drives = []
    bitmask = ctypes.windll.kernel32.GetLogicalDrives()
    for i in range(26):
        if bitmask & (1 << i):
            letter = chr(ord('A') + i)
            drive = f"{letter}:\\"
            try:
                dtype = ctypes.windll.kernel32.GetDriveTypeW(drive)
                if dtype == 2:  # DRIVE_REMOVABLE
                    drives.append(f"{letter}:")
            except Exception:
                pass
    return drives


def _progress(current, total, label=""):
    """Show progress bar."""
    pct = current / max(total, 1)
    filled = int(pct * 30)
    bar = "█" * filled + "░" * (30 - filled)
    print(f"\r  [{bar}] {current}/{total} {label}", end="", flush=True)


def _wait_for_agent(seconds, message="Waiting for Host Agent to collect features"):
    """Wait with countdown, showing what the agent should be seeing."""
    print(f"\n  ⏳ {message}...")
    print(f"  (The Host Agent collects features every ~10 seconds)")
    for i in range(seconds, 0, -1):
        if _stop_event.is_set():
            return
        print(f"\r  Remaining: {i}s   ", end="", flush=True)
        time.sleep(1)
    print("\r  ✓ Agent should have collected features by now.     ")


# ═══════════════════════════════════════════════════════════
#  ATTACK 1: Data Exfiltration — USB Copy After Hours
# ═══════════════════════════════════════════════════════════

def attack_exfiltration():
    """
    Simulates: Employee copying confidential files to USB drive after hours.
    CERT Category: EXFILTRATION

    What it does:
    1. Creates many files in Documents (agent sees file_activities spike)
    2. Creates a virtual USB drive OR uses real USB
    3. Copies files to USB (agent sees device_activities spike)

    What the agent detects:
    - total_file_activities ↑↑↑ (hundreds of files created/modified)
    - total_device_activities ↑↑↑ (new drive = USB event)
    - after_hours multiplier (if running after 18:00)
    """
    print("\n" + "=" * 60)
    print("  💾 ATTACK: Data Exfiltration — USB Copy")
    print("  CERT Type: EXFILTRATION")
    print("  Mimics: Employee stealing files via USB drive after hours")
    print("=" * 60)

    # Ask about USB mode
    print("\n  USB Simulation Mode:")
    print("    1. Virtual USB (safe — uses 'subst' command)")
    print("    2. Real USB drive (plug in a flash drive first)")

    real_usb_drives = _find_real_usb()
    if real_usb_drives:
        print(f"    ↳ Real USB drives found: {', '.join(real_usb_drives)}")
    else:
        print(f"    ↳ No real USB drives detected")

    choice = input("\n  Choice [1]: ").strip() or "1"
    use_real_usb = choice == "2"

    usb_target = None
    if use_real_usb:
        if not real_usb_drives:
            print("  ✗ No USB drives found! Plug in a flash drive and try again.")
            return
        if len(real_usb_drives) == 1:
            usb_target = real_usb_drives[0] + "\\"
        else:
            print(f"  Choose drive: {', '.join(real_usb_drives)}")
            usb_target = input("  Drive letter (e.g. E): ").strip().upper() + ":\\"
        print(f"  → Using real USB: {usb_target}")
    else:
        drive_letter = _find_free_drive()
        if not drive_letter:
            print("  ✗ No free drive letters available!")
            return

        usb_backing = _create_sim_dir("usb_backing")
        result = subprocess.run(
            ["subst", f"{drive_letter}:", usb_backing],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            print(f"  ✗ Failed to create virtual USB: {result.stderr}")
            return

        _subst_drives.append(f"{drive_letter}:")
        usb_target = f"{drive_letter}:\\"
        print(f"  → Created virtual USB drive: {usb_target}")

    # Phase 1: Create "confidential" files in Documents
    file_count = 500
    src_dir = _create_sim_dir("confidential_docs")
    print(f"\n  Phase 1: Creating {file_count} confidential files...")

    for i in range(file_count):
        if _stop_event.is_set():
            return
        fname = f"confidential_report_{i:04d}.docx"
        with open(os.path.join(src_dir, fname), "w") as f:
            f.write(f"CONFIDENTIAL — Internal Document #{i}\n" * 20)
        if i % 50 == 0:
            _progress(i, file_count, "files created")

    _progress(file_count, file_count, "files created")
    print()

    # Phase 2: Copy files to USB (this triggers device_activities + file_activities)
    copy_count = min(200, file_count)
    usb_sim_dir = os.path.join(usb_target, "_exfiltration_sim")
    try:
        os.makedirs(usb_sim_dir, exist_ok=True)
    except Exception as e:
        print(f"  ✗ Cannot write to USB: {e}")
        return

    print(f"  Phase 2: Copying {copy_count} files to USB ({usb_target})...")

    files = os.listdir(src_dir)[:copy_count]
    for i, fname in enumerate(files):
        if _stop_event.is_set():
            return
        shutil.copy2(os.path.join(src_dir, fname), os.path.join(usb_sim_dir, fname))
        if i % 25 == 0:
            _progress(i, copy_count, "files copied to USB")

    _progress(copy_count, copy_count, "files copied to USB")
    print()

    print(f"\n  ✅ Exfiltration activity complete!")
    print(f"     → {file_count} files created in Documents")
    print(f"     → {copy_count} files copied to USB drive {usb_target}")
    print(f"     → Agent features affected:")
    print(f"       • total_file_activities: ~{file_count}+")
    print(f"       • total_device_activities: +200 (USB detection)")
    after_h = "YES ✓" if (datetime.now().hour < 8 or datetime.now().hour >= 18) else "NO (run after 18:00 for full effect)"
    print(f"       • after_hours: {after_h}")

    _wait_for_agent(30)

    # Cleanup USB files if real USB
    if use_real_usb:
        try:
            shutil.rmtree(usb_sim_dir, ignore_errors=True)
            print(f"  ✓ Cleaned USB files from {usb_target}")
        except Exception:
            print(f"  ⚠ Could not clean USB files — please delete {usb_sim_dir} manually")


# ═══════════════════════════════════════════════════════════
#  ATTACK 2: IT Sabotage — Mass File Deletion
# ═══════════════════════════════════════════════════════════

def attack_sabotage():
    """
    Simulates: Disgruntled employee mass-deleting company files.
    CERT Category: SABOTAGE

    What it does:
    1. Creates many files in Documents (representing "existing" company files)
    2. Rapidly deletes them all (simulates sabotage)
    3. Agent sees massive file activity spike

    What the agent detects:
    - total_file_activities ↑↑↑ (mass file changes)
    - after_hours + weekend multipliers if applicable
    """
    print("\n" + "=" * 60)
    print("  🔥 ATTACK: IT Sabotage — Mass File Deletion")
    print("  CERT Type: SABOTAGE")
    print("  Mimics: Disgruntled employee deleting company files")
    print("=" * 60)

    file_count = 800
    sabotage_dir = _create_sim_dir("company_files")

    # Phase 1: Create "company files" (simulates existing data)
    print(f"\n  Phase 1: Creating {file_count} company files (simulating existing data)...")
    for i in range(file_count):
        if _stop_event.is_set():
            return
        fname = f"company_data_{i:04d}.xlsx"
        with open(os.path.join(sabotage_dir, fname), "w") as f:
            f.write(f"Important Company Data — Record #{i}\n" * 30)
        if i % 100 == 0:
            _progress(i, file_count, "files created")

    _progress(file_count, file_count, "files created")
    print()

    _wait_for_agent(15, "Letting agent see the files first")

    # Phase 2: Mass deletion (the actual sabotage)
    print(f"\n  Phase 2: ⚠ SABOTAGE — Rapidly deleting all {file_count} files...")
    deleted = 0
    for fname in os.listdir(sabotage_dir):
        if _stop_event.is_set():
            break
        try:
            os.remove(os.path.join(sabotage_dir, fname))
            deleted += 1
            if deleted % 100 == 0:
                _progress(deleted, file_count, "files DELETED")
        except Exception:
            pass

    _progress(deleted, file_count, "files DELETED")
    print()

    # Phase 3: Create MORE files rapidly (retaliation - overwriting)
    print(f"  Phase 3: Creating {file_count // 2} more files rapidly (retaliation)...")
    for i in range(file_count // 2):
        if _stop_event.is_set():
            return
        with open(os.path.join(sabotage_dir, f"destroyed_{i:04d}.tmp"), "w") as f:
            f.write("DELETED BY INSIDER " * 50)
        if i % 100 == 0:
            _progress(i, file_count // 2, "overwrite files")

    _progress(file_count // 2, file_count // 2, "overwrite files")
    print()

    total_ops = file_count + deleted + file_count // 2
    print(f"\n  ✅ Sabotage activity complete!")
    print(f"     → {file_count} files created then {deleted} deleted + {file_count // 2} overwritten")
    print(f"     → Total file operations: ~{total_ops}")
    print(f"     → Agent features affected:")
    print(f"       • total_file_activities: ~{file_count // 2}+ (surviving files)")
    after_h = "YES ✓" if (datetime.now().hour < 8 or datetime.now().hour >= 18) else "NO"
    print(f"       • after_hours: {after_h}")

    _wait_for_agent(30)


# ═══════════════════════════════════════════════════════════
#  ATTACK 3: Espionage — IP Theft
# ═══════════════════════════════════════════════════════════

def attack_espionage():
    """
    Simulates: Employee stealing intellectual property across systems.
    CERT Category: ESPIONAGE

    What it does:
    1. Creates many files (R&D documents, source code)
    2. Reads them rapidly (data collection)
    3. Generates network connections (simulates multi-PC access)

    What the agent detects:
    - total_file_activities ↑↑ (file access)
    - total_logons ↑↑ (many connections)
    - after_hours multiplier
    """
    print("\n" + "=" * 60)
    print("  🕵 ATTACK: Espionage — IP Theft")
    print("  CERT Type: ESPIONAGE")
    print("  Mimics: Employee stealing R&D data after hours")
    print("=" * 60)

    file_count = 600
    espionage_dir = _create_sim_dir("rd_documents")

    # Phase 1: Create R&D files
    print(f"\n  Phase 1: Creating {file_count} R&D/IP documents...")
    for i in range(file_count):
        if _stop_event.is_set():
            return
        ext = random.choice([".py", ".docx", ".pdf", ".xlsx", ".cpp", ".java"])
        fname = f"project_alpha_{i:04d}{ext}"
        with open(os.path.join(espionage_dir, fname), "w") as f:
            f.write(f"TOP SECRET — Project Alpha Research #{i}\n" * 25)
        if i % 100 == 0:
            _progress(i, file_count, "IP files created")

    _progress(file_count, file_count, "IP files created")
    print()

    # Phase 2: Rapid file reading (data collection)
    print(f"  Phase 2: Rapidly reading all files (collecting data)...")
    read_count = 0
    for fname in os.listdir(espionage_dir):
        if _stop_event.is_set():
            break
        try:
            with open(os.path.join(espionage_dir, fname), "r") as f:
                _ = f.read()
            read_count += 1
        except Exception:
            pass

    print(f"  → Read {read_count} files")

    # Phase 3: Generate network connections (simulates accessing multiple PCs)
    print(f"  Phase 3: Generating network connections (multi-PC access pattern)...")
    conn_count = 0
    sockets = []
    for port in [80, 443, 8080, 8443, 3000, 5000]:
        for _ in range(5):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                s.connect_ex(("127.0.0.1", port))
                sockets.append(s)
                conn_count += 1
            except Exception:
                pass

    print(f"  → Created {conn_count} network connections")

    print(f"\n  ✅ Espionage activity complete!")
    print(f"     → {file_count} files created + {read_count} files read")
    print(f"     → {conn_count} network connections generated")
    print(f"     → Agent features affected:")
    print(f"       • total_file_activities: ~{file_count}+")
    print(f"       • total_logons: +{conn_count}")
    after_h = "YES ✓" if (datetime.now().hour < 8 or datetime.now().hour >= 18) else "NO"
    print(f"       • after_hours: {after_h}")

    _wait_for_agent(30)

    # Close sockets
    for s in sockets:
        try:
            s.close()
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════
#  ATTACK 4: Fraud — Unauthorized Financial Data Access
# ═══════════════════════════════════════════════════════════

def attack_fraud():
    """
    Simulates: Employee accessing financial data they shouldn't.
    CERT Category: FRAUD

    What it does:
    1. Creates many financial-looking files (invoices, accounts, transactions)
    2. Reads them rapidly (unauthorized access)

    What the agent detects:
    - total_file_activities ↑↑↑ (massive file access)
    - unique_files ↑↑↑ (many different files)
    """
    print("\n" + "=" * 60)
    print("  💰 ATTACK: Fraud — Unauthorized Financial Access")
    print("  CERT Type: FRAUD")
    print("  Mimics: Employee accessing restricted financial data")
    print("=" * 60)

    file_count = 1000
    fraud_dir = _create_sim_dir("financial_records")

    # Phase 1: Create financial files
    print(f"\n  Phase 1: Creating {file_count} financial records...")
    for i in range(file_count):
        if _stop_event.is_set():
            return
        ftype = random.choice(["invoice", "account", "transaction", "payroll", "budget"])
        fname = f"{ftype}_{i:04d}.csv"
        with open(os.path.join(fraud_dir, fname), "w") as f:
            f.write("date,account,amount,category\n")
            for j in range(50):
                f.write(f"2024-{random.randint(1,12):02d}-{random.randint(1,28):02d},"
                        f"ACC-{random.randint(1000,9999)},"
                        f"{random.uniform(100, 50000):.2f},"
                        f"{random.choice(['salary', 'expense', 'transfer', 'payment'])}\n")
        if i % 100 == 0:
            _progress(i, file_count, "financial files")

    _progress(file_count, file_count, "financial files")
    print()

    # Phase 2: Rapid access (unauthorized reading)
    print(f"  Phase 2: Rapidly accessing all financial records...")
    accessed = 0
    for fname in os.listdir(fraud_dir):
        if _stop_event.is_set():
            break
        try:
            with open(os.path.join(fraud_dir, fname), "r") as f:
                data = f.read()
            # "Process" the data (touch the file to update mtime)
            os.utime(os.path.join(fraud_dir, fname))
            accessed += 1
        except Exception:
            pass
        if accessed % 100 == 0:
            _progress(accessed, file_count, "files accessed")

    _progress(accessed, file_count, "files accessed")
    print()

    print(f"\n  ✅ Fraud activity complete!")
    print(f"     → {file_count} financial files created and {accessed} accessed")
    print(f"     → Agent features affected:")
    print(f"       • total_file_activities: ~{file_count}+")
    print(f"       • unique_files: ~{file_count}+")
    after_h = "YES ✓" if (datetime.now().hour < 8 or datetime.now().hour >= 18) else "NO"
    print(f"       • after_hours: {after_h}")

    _wait_for_agent(30)


# ═══════════════════════════════════════════════════════════
#  ATTACK 5: System Abuse — Network Flooding
# ═══════════════════════════════════════════════════════════

def attack_abuse():
    """
    Simulates: Employee abusing network resources / downloading tools.
    CERT Category: ABUSE

    What it does:
    1. Generates massive network traffic (many connections + packets)
    2. Creates some files (downloaded tools)

    What the agent detects:
    - total_device_activities ↑↑↑ (network packets spike)
    - total_logons ↑↑ (many connections)
    """
    print("\n" + "=" * 60)
    print("  🌐 ATTACK: System Abuse — Network Flooding")
    print("  CERT Type: ABUSE")
    print("  Mimics: Employee making mass network requests / downloading tools")
    print("=" * 60)

    # Phase 1: Generate lots of network traffic
    print(f"\n  Phase 1: Generating network traffic (mass connections)...")
    conn_count = 0
    sockets = []
    target_ports = [80, 443, 8080, 8443, 3000, 5000, 3306, 5432, 6379, 27017]

    for port in target_ports:
        for _ in range(20):
            if _stop_event.is_set():
                break
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.3)
                s.connect_ex(("127.0.0.1", port))
                sockets.append(s)
                conn_count += 1
            except Exception:
                pass

    print(f"  → Created {conn_count} connections across {len(target_ports)} ports")

    # Phase 2: Generate UDP traffic (packet flood simulation)
    print(f"  Phase 2: Generating UDP traffic (packet flood)...")
    udp_count = 0
    for _ in range(500):
        if _stop_event.is_set():
            break
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(b"X" * 512, ("127.0.0.1", random.randint(10000, 60000)))
            s.close()
            udp_count += 1
        except Exception:
            pass

    print(f"  → Sent {udp_count} UDP packets")

    # Phase 3: Create "downloaded tools" files
    file_count = 100
    abuse_dir = _create_sim_dir("downloaded_tools")
    print(f"  Phase 3: Creating {file_count} files (simulated tool downloads)...")
    for i in range(file_count):
        if _stop_event.is_set():
            return
        fname = f"tool_{i:03d}.bin"
        with open(os.path.join(abuse_dir, fname), "wb") as f:
            f.write(os.urandom(1024))

    print(f"  → {file_count} files created")

    print(f"\n  ✅ System Abuse activity complete!")
    print(f"     → {conn_count} TCP connections + {udp_count} UDP packets")
    print(f"     → {file_count} files created")
    print(f"     → Agent features affected:")
    print(f"       • total_device_activities: ↑↑↑ (network packets)")
    print(f"       • total_logons: +{conn_count}")
    after_h = "YES ✓" if (datetime.now().hour < 8 or datetime.now().hour >= 18) else "NO"
    print(f"       • after_hours: {after_h}")

    _wait_for_agent(30)

    # Close sockets
    for s in sockets:
        try:
            s.close()
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════
#  ATTACK 6: Combined Attack — Full Insider Threat
# ═══════════════════════════════════════════════════════════

def attack_combined():
    """
    Simulates: Full insider threat scenario combining multiple attack types.
    Creates maximum feature elevation across all dimensions.
    """
    print("\n" + "=" * 60)
    print("  ☠ ATTACK: Combined Full Insider Threat")
    print("  Combines: Espionage + Exfiltration + Sabotage")
    print("  Maximum feature elevation for guaranteed detection")
    print("=" * 60)

    combined_dir = _create_sim_dir("combined_attack")

    # Step 1: Mass file creation (like preparing to steal)
    print(f"\n  Step 1: Creating 2000 files across categories...")
    categories = {
        "financial": 500,
        "rd_secret": 500,
        "company_data": 500,
        "personal_info": 500,
    }
    total_files = 0
    for category, count in categories.items():
        cat_dir = os.path.join(combined_dir, category)
        os.makedirs(cat_dir, exist_ok=True)
        for i in range(count):
            if _stop_event.is_set():
                return
            with open(os.path.join(cat_dir, f"{category}_{i:04d}.dat"), "w") as f:
                f.write(f"SENSITIVE {category.upper()} DATA #{i}\n" * 30)
            total_files += 1

    print(f"  → {total_files} files created")

    # Step 2: Virtual USB + file copy
    drive_letter = _find_free_drive()
    if drive_letter:
        usb_dir = os.path.join(combined_dir, "usb_backing")
        os.makedirs(usb_dir, exist_ok=True)
        result = subprocess.run(["subst", f"{drive_letter}:", usb_dir], capture_output=True, text=True)
        if result.returncode == 0:
            _subst_drives.append(f"{drive_letter}:")
            print(f"  → Virtual USB created: {drive_letter}:\\")
            # Copy files to USB
            copied = 0
            for category in categories:
                cat_dir = os.path.join(combined_dir, category)
                for fname in os.listdir(cat_dir)[:50]:
                    try:
                        shutil.copy2(os.path.join(cat_dir, fname),
                                     os.path.join(f"{drive_letter}:\\", fname))
                        copied += 1
                    except Exception:
                        pass
            print(f"  → {copied} files copied to USB")

    # Step 3: Network connections
    sockets = []
    for port in [80, 443, 8080, 3000, 5000]:
        for _ in range(10):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.3)
                s.connect_ex(("127.0.0.1", port))
                sockets.append(s)
            except Exception:
                pass

    print(f"  → {len(sockets)} network connections")

    # Step 4: UDP flood
    for _ in range(300):
        if _stop_event.is_set():
            break
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(b"X" * 256, ("127.0.0.1", random.randint(10000, 60000)))
            s.close()
        except Exception:
            pass

    print(f"\n  ✅ Combined attack complete!")
    print(f"     → {total_files} files + USB + network flood")
    print(f"     → This should trigger MAXIMUM detection confidence")
    after_h = "YES ✓" if (datetime.now().hour < 8 or datetime.now().hour >= 18) else "NO"
    print(f"     → after_hours: {after_h}")

    _wait_for_agent(30)

    for s in sockets:
        try:
            s.close()
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════
#  BASELINE: Normal Employee Behavior
# ═══════════════════════════════════════════════════════════

def baseline_normal():
    """Normal employee behavior — should NOT trigger detection."""
    print("\n" + "=" * 60)
    print("  👤 BASELINE: Normal Employee Behavior")
    print("  Expected: Agent should report NORMAL (no detection)")
    print("=" * 60)

    normal_dir = _create_sim_dir("work_notes")

    print("\n  Creating 3 normal work files...")
    for i in range(3):
        with open(os.path.join(normal_dir, f"meeting_notes_{i}.txt"), "w") as f:
            f.write(f"Meeting notes for {datetime.now().strftime('%Y-%m-%d')}\n" * 5)

    print(f"  → 3 files created (minimal activity)")
    print(f"  → This should NOT trigger detection")

    _wait_for_agent(20)


# ═══════════════════════════════════════════════════════════
#  MANUAL ATTACK GUIDE
# ═══════════════════════════════════════════════════════════

def show_manual_guide():
    """Show attacks the user can perform manually."""
    print("\n" + "=" * 60)
    print("  📋 MANUAL ATTACK GUIDE")
    print("  Things YOU can do to trigger the IDS (no script needed)")
    print("=" * 60)

    print("""
  ┌─────────────────────────────────────────────────────────┐
  │  1. USB EXFILTRATION (Real USB)                         │
  │     ─────────────────────────────────────────────────── │
  │     • Plug in a real USB flash drive                    │
  │     • Copy many files from Documents to the USB         │
  │     • The agent will detect:                            │
  │       - New drive letter (device_activities ↑↑)         │
  │       - File modifications (file_activities ↑↑)         │
  │     • Best after 18:00 for after_hours detection        │
  ├─────────────────────────────────────────────────────────┤
  │  2. MASS FILE OPERATIONS (Sabotage)                     │
  │     ─────────────────────────────────────────────────── │
  │     • Open File Explorer → Documents                    │
  │     • Create a new folder, paste MANY files into it     │
  │     • Or: select all files → Ctrl+C → Ctrl+V (repeat)  │
  │     • The agent monitors Documents/Desktop/Downloads    │
  │     • 100+ files modified = suspicious activity         │
  ├─────────────────────────────────────────────────────────┤
  │  3. NETWORK FLOODING (Abuse)                            │
  │     ─────────────────────────────────────────────────── │
  │     • Open 50+ browser tabs rapidly                     │
  │     • Or run: ping -t -l 1000 127.0.0.1                │
  │     • Or open many downloads simultaneously             │
  │     • The agent counts network packets and connections  │
  ├─────────────────────────────────────────────────────────┤
  │  4. AFTER-HOURS ACTIVITY                                │
  │     ─────────────────────────────────────────────────── │
  │     • Any of the above done AFTER 18:00                 │
  │     • The after_hours multiplier makes normal activity  │
  │       look MORE suspicious to the model                 │
  │     • Same activity at 14:00 vs 22:00 = different score │
  ├─────────────────────────────────────────────────────────┤
  │  5. WEEKEND ACTIVITY                                    │
  │     ─────────────────────────────────────────────────── │
  │     • Same as above but on Saturday/Sunday              │
  │     • weekend_logons multiplier activates               │
  │     • Corporate employees shouldn't be active on        │
  │       weekends — this is a red flag for the model       │
  └─────────────────────────────────────────────────────────┘

  IMPORTANT:
  • The Host Agent must be RUNNING for any detection to work
  • The Agent collects features every ~10 seconds
  • Run: cd deploy/host_agent && python host_agent.py
""")
    input("  Press Enter to return to menu...")


# ═══════════════════════════════════════════════════════════
#  MAIN MENU
# ═══════════════════════════════════════════════════════════

def main():
    print()
    print("╔" + "═" * 62 + "╗")
    print("║  Host Attack Simulation — CERT r4.2 Insider Threat          ║")
    print("║  Creates REAL activity for the Host Agent to detect         ║")
    print("╠" + "═" * 62 + "╣")
    print("║  ⚠  Make sure the Host Agent is running FIRST:              ║")
    print("║     cd deploy/host_agent && python host_agent.py            ║")
    print("║                                                              ║")
    print("║  🔒 SAFE MODE: All files cleaned up automatically           ║")
    print("╚" + "═" * 62 + "╝")

    hour = datetime.now().hour
    if hour < 8 or hour >= 18:
        print(f"\n  ⏰ Current time: {datetime.now().strftime('%H:%M')} — AFTER HOURS ✓")
        print(f"     After-hours attacks will have maximum detection!")
    else:
        print(f"\n  ⏰ Current time: {datetime.now().strftime('%H:%M')} — Business hours")
        print(f"     Run after 18:00 for after_hours multiplier effect")

    if datetime.now().weekday() >= 5:
        print(f"  📅 It's the WEEKEND — weekend multiplier is active!")

    while True:
        print("\n" + "=" * 60)
        print("  ATTACK MENU")
        print("=" * 60)
        print("  1. 💾 Data Exfiltration   — USB copy after hours")
        print("  2. 🔥 IT Sabotage         — Mass file deletion")
        print("  3. 🕵 Espionage           — IP theft + network access")
        print("  4. 💰 Fraud               — Financial data access")
        print("  5. 🌐 System Abuse        — Network flooding")
        print("  6. ☠ Combined Attack      — All of the above (maximum)")
        print("  7. 👤 Normal Baseline     — Should NOT trigger detection")
        print("  8. 📋 Manual Attack Guide — Things YOU can do manually")
        print("  Q. Exit (auto-cleanup)")
        print("=" * 60)

        choice = input("\n  Choice: ").strip().upper()

        # Reset cleanup flag and stop event for new attack
        global _cleanup_done
        _cleanup_done = False
        _stop_event.clear()

        if choice == "1":
            attack_exfiltration()
        elif choice == "2":
            attack_sabotage()
        elif choice == "3":
            attack_espionage()
        elif choice == "4":
            attack_fraud()
        elif choice == "5":
            attack_abuse()
        elif choice == "6":
            attack_combined()
        elif choice == "7":
            baseline_normal()
        elif choice == "8":
            show_manual_guide()
            continue
        elif choice == "Q":
            break
        else:
            print("  Invalid choice. Try again.")
            continue

        # Cleanup after each attack (keep machine clean between attacks)
        _cleanup()
        print("\n  Ready for next attack or press Q to exit.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
    finally:
        _cleanup()
