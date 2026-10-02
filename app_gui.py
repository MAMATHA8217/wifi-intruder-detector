import tkinter as tk
from tkinter import messagebox, scrolledtext
from scapy.all import ARP, Ether, srp
import json
import os
import threading
import time
import socket
from datetime import datetime

import sys

if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

WHITELIST_FILE = os.path.join(BASE_DIR, "trusted_devices.json")
LOG_FILE = os.path.join(BASE_DIR, "alerts.log")

monitoring = False

def scan_network(ip_range):
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    answered, _ = srp(packet, timeout=3, verbose=False)
    return [{"ip": r.psrc, "mac": r.hwsrc} for s, r in answered]

def save_whitelist(devices):
    with open(WHITELIST_FILE, "w") as f:
        json.dump(devices, f, indent=4)

def load_whitelist():
    if not os.path.exists(WHITELIST_FILE):
        return None
    with open(WHITELIST_FILE, "r") as f:
        return json.load(f)

def log_event(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {message}\n")

def append_output(text):
    output_box.insert(tk.END, text + "\n")
    output_box.see(tk.END)

def do_scan_and_save():
    target = target_entry.get().strip()
    if not target:
        messagebox.showerror("Error", "Please enter a network range, e.g. 192.168.1.0/24")
        return
    append_output(f"Scanning {target} ...")
    result = scan_network(target)
    save_whitelist(result)
    append_output(f"Saved {len(result)} trusted device(s).")
    for d in result:
        append_output(f"  IP: {d['ip']:<15} MAC: {d['mac']}")

def do_single_check():
    target = target_entry.get().strip()
    trusted = load_whitelist()
    if trusted is None:
        messagebox.showwarning("No baseline", "Save your trusted devices first.")
        return
    result = scan_network(target)
    trusted_macs = {d["mac"] for d in trusted}
    unknown = [d for d in result if d["mac"] not in trusted_macs]

    if unknown:
        for d in unknown:
            append_output(f"⚠️ UNKNOWN DEVICE -> IP: {d['ip']} MAC: {d['mac']}")
            log_event(f"ALERT - Unknown device: IP={d['ip']} MAC={d['mac']}")
    else:
        append_output("✅ No unknown devices found.")
        log_event("Scan completed. No unknown devices.")

def monitor_loop():
    global monitoring
    while monitoring:
        do_single_check()
        time.sleep(30)

def start_monitoring():
    global monitoring
    if not monitoring:
        monitoring = True
        threading.Thread(target=monitor_loop, daemon=True).start()
        append_output("Started continuous monitoring...")

def stop_monitoring():
    global monitoring
    monitoring = False
    append_output("Stopped monitoring.")
    
def do_add_trusted():
    target = target_entry.get().strip()
    if not target:
        messagebox.showerror("Error", "Please enter a network range, e.g. 192.168.1.0/24")
        return

    append_output(f"Scanning {target} to add new trusted device(s)...")
    result = scan_network(target)

    existing = load_whitelist() or []
    existing_macs = {d["mac"] for d in existing}

    added_count = 0
    for d in result:
        if d["mac"] not in existing_macs:
            existing.append(d)
            existing_macs.add(d["mac"])
            added_count += 1
            append_output(f"  Added -> IP: {d['ip']:<15} MAC: {d['mac']}")

    save_whitelist(existing)

    if added_count == 0:
        append_output("No new devices found to add, all scanned devices are already trusted.")
    else:
        append_output(f"Added {added_count} new trusted device(s). Total trusted: {len(existing)}")
def get_local_network_range():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        ip_parts = local_ip.split(".")
        network_range = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
        return network_range
    except Exception:
        return None

def auto_fill_range():
    network_range = get_local_network_range()
    if network_range:
        target_entry.delete(0, tk.END)
        target_entry.insert(0, network_range)
        append_output(f"Auto-detected network range: {network_range}")
    else:
        messagebox.showerror("Error", "Could not detect network range. Please enter it manually.")

# --- Build the window ---
root = tk.Tk()
root.title("Wi-Fi Intruder Detector")
root.geometry("500x450")

tk.Label(root, text="Network range (e.g. 192.168.1.0/24):").pack(pady=5)
target_entry = tk.Entry(root, width=40)
target_entry.pack(pady=5)

btn_frame = tk.Frame(root)
btn_frame.pack(pady=5)

tk.Button(btn_frame, text="Save Trusted Devices", command=do_scan_and_save).grid(row=0, column=0, padx=5)
tk.Button(btn_frame, text="Check Now", command=do_single_check).grid(row=0, column=1, padx=5)
tk.Button(btn_frame, text="Start Monitoring", command=start_monitoring).grid(row=1, column=0, padx=5, pady=5)
tk.Button(btn_frame, text="Stop Monitoring", command=stop_monitoring).grid(row=1, column=1, padx=5, pady=5)
tk.Button(btn_frame, text="Add to Trusted", command=do_add_trusted).grid(row=2, column=0, columnspan=2, padx=5, pady=5)
tk.Button(root, text="Auto-Detect Range", command=auto_fill_range).pack(pady=5)

output_box = scrolledtext.ScrolledText(root, width=60, height=18)
output_box.pack(pady=10)

root.mainloop()