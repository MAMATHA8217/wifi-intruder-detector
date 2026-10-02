from scapy.all import ARP, Ether, srp
import json
import os
import time
from datetime import datetime

WHITELIST_FILE = "trusted_devices.json"
LOG_FILE = "alerts.log"
SCAN_INTERVAL = 15   # seconds between scans (60 = 1 minute)
TARGET = "10.252.118.0/24"

def scan_network(ip_range):
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    answered, _ = srp(packet, timeout=3, verbose=False)

    devices = []
    for sent, received in answered:
        devices.append({
            "ip": received.psrc,
            "mac": received.hwsrc
        })
    return devices

def save_whitelist(devices):
    with open(WHITELIST_FILE, "w") as f:
        json.dump(devices, f, indent=4)
    print(f"\nSaved {len(devices)} device(s) to {WHITELIST_FILE} as trusted.")

def load_whitelist():
    if not os.path.exists(WHITELIST_FILE):
        return None
    with open(WHITELIST_FILE, "r") as f:
        return json.load(f)

def check_for_intruders(current_devices, trusted_devices):
    trusted_macs = {d["mac"] for d in trusted_devices}
    unknown = [d for d in current_devices if d["mac"] not in trusted_macs]
    return unknown

def log_event(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {message}\n")

def run_single_scan():
    result = scan_network(TARGET)

    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Found {len(result)} device(s):")
    for d in result:
        print(f"IP: {d['ip']:<15}  MAC: {d['mac']}")

    trusted = load_whitelist()

    if trusted is None:
        save_whitelist(result)
        log_event(f"Baseline saved with {len(result)} trusted device(s).")
    else:
        unknown_devices = check_for_intruders(result, trusted)

        if unknown_devices:
            print("\n⚠️  ALERT: Unknown device(s) detected!\n")
            for d in unknown_devices:
                print(f"UNKNOWN -> IP: {d['ip']:<15}  MAC: {d['mac']}")
                log_event(f"ALERT - Unknown device detected: IP={d['ip']} MAC={d['mac']}")
        else:
            print("\n✅ No unknown devices. All devices are trusted.")
            log_event("Scan completed. No unknown devices found.")

if __name__ == "__main__":
    print(f"Starting continuous monitoring (scanning every {SCAN_INTERVAL} seconds)...")
    print("Press Ctrl+C to stop.\n")

    try:
        while True:
            run_single_scan()
            print(f"\nWaiting {SCAN_INTERVAL} seconds until next scan...\n")
            time.sleep(SCAN_INTERVAL)
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.")