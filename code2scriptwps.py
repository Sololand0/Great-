#!/usr/bin/env python3
"""
WPS Quick Scanner — Scan networks, check for WPS, generate default PINs.
No monitor mode needed. Works with just iw and Python.

Usage:
    sudo python3 wps_scanner.py -i wlan0
    sudo python3 wps_scanner.py -i wlan0 -b AA:BB:CC:DD:EE:FF
"""

import subprocess
import re
import sys
import os

def run(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except:
        return ""

def scan_networks(iface):
    """Scan and return list of networks with details."""
    out = run(f"iw dev {iface} scan")
    networks = []
    current = {}
    
    for line in out.split('\n'):
        ls = line.strip()
        if ls.startswith('BSS '):
            if current:
                networks.append(current)
            current = {'bssid': ls.split()[1], 'ssid': '<hidden>', 'channel': '?', 'signal': '?', 'wps': False}
        elif 'SSID:' in ls:
            current['ssid'] = ls.split('SSID:')[-1].strip().strip('"')
        elif 'freq:' in ls:
            f = int(ls.split()[1])
            current['channel'] = str((f-2412)//5+1) if 2412<=f<=2484 else str((f-5180)//5+36)
        elif 'signal:' in ls:
            parts = ls.split()
            for i,p in enumerate(parts):
                if p == 'signal:':
                    current['signal'] = parts[i+1]
        # Check for WPS IE (0x00dd or 0x00904c for WPS)
        elif 'WPS' in ls or 'wps' in ls:
            current['wps'] = True
    
    if current:
        networks.append(current)
    
    # Deduplicate
    seen = set()
    unique = []
    for n in networks:
        if n['bssid'] not in seen:
            seen.add(n['bssid'])
            unique.append(n)
    return unique

def compute_pin(bssid):
    """Generate candidate default WPS PINs from BSSID."""
    clean = bssid.replace(':', '').upper()
    pins = set()
    
    # Method 1: last 7 hex digits -> decimal, then checksum
    try:
        raw = int(clean[-7:], 16) % 10000000
        s = f"{raw:07d}"
        acc = sum(3*int(d) if i%2==0 else int(d) for i,d in enumerate(s))
        ck = (10 - acc%10) % 10
        pins.add(s + str(ck))
    except: pass
    
    # Method 2: last 6 hex -> dec, pad
    try:
        raw = int(clean[-6:], 16) % 10000000
        s = f"{raw:07d}"
        acc = sum(3*int(d) if i%2==0 else int(d) for i,d in enumerate(s))
        ck = (10 - acc%10) % 10
        pins.add(s + str(ck))
    except: pass
    
    return sorted(pins)

def main():
    if os.geteuid() != 0:
        print("[!] Run as root")
        sys.exit(1)
    
    iface = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1] == sys.argv[1] and '-i' in sys.argv else None
    if not iface:
        # Find first wireless interface
        out = run("iw dev 2>/dev/null | grep 'Interface' | awk '{print $2}'")
        ifaces = [l.strip() for l in out.split('\n') if l.strip()]
        if not ifaces:
            print("[!] No wireless interfaces found")
            sys.exit(1)
        iface = ifaces[0]
    
    print(f"\n[*] Scanning on {iface}...\n")
    nets = scan_networks(iface)
    
    if not nets:
        print("[!] No networks found. Make sure Wi-Fi is on.")
        sys.exit(1)
    
    print(f"{'#':<4} {'SSID':<28} {'BSSID':<18} {'CH':<4} {'SIG':<8} {'DEFAULT PINS'}")
    print('-' * 90)
    
    bssid_target = None
    for i, n in enumerate(nets, 1):
        wps_flag = " [WPS?]" if n.get('wps') else ""
        pins = compute_pin(n['bssid'])
        pin_str = ", ".join(pins[:3]) if pins else "-"
        print(f"{i:<4} {n['ssid'][:28]:<28} {n['bssid']:<18} {n['channel']:<4} {n['signal']:<8} {pin_str}{wps_flag}")
    
    print()
    
    # If a BSSID was passed as argument, show detailed info
    if len(sys.argv) > 2 and sys.argv[2]:
        bssid = sys.argv[2].upper()
        pins = compute_pin(bssid)
        print(f"\n[+] Default PINs for {bssid}:")
        for p in pins:
            print(f"    {p}")

if __name__ == "__main__":
    main()
