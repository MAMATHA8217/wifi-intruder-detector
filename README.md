# Wi-Fi Intruder Detector

A desktop application that scans your local network using ARP requests, 
detects unknown/unauthorized devices, and alerts you via logs.

## Features
- ARP-based network scanning (Scapy + Npcap)
- Trusted device whitelist (save, add, overwrite)
- Real-time unknown device detection
- Automatic continuous monitoring
- Timestamped alert logging
- Auto-detects your current network range
- Simple GUI (Tkinter)

## Requirements
- Windows OS
- [Npcap](https://npcap.com/#download) installed (required for packet capture — 
  check "Install Npcap in WinPcap API-compatible Mode" during setup)
- Administrator privileges to run (needed for raw packet access)

## How to use
1. Download `app_gui.exe` from the Releases section (or run `app_gui.py` with Python installed)
2. Right-click → Run as administrator
3. Click "Auto-Detect Range" to fill in your network automatically
4. Click "Save Trusted Devices" to set your baseline
5. Click "Start Monitoring" for continuous detection, or "Check Now" for a one-time scan

## Tech stack
Python, Scapy, Tkinter, PyInstaller

## Known limitations
- ARP scanning only works on the local network the device is currently connected to
- Some networks (college Wi-Fi, certain mobile hotspots) use AP/client isolation, 
  which blocks device-to-device visibility and prevents detection — this was 
  discovered and confirmed during testing on a college network
- Cloud deployment of the scanning function isn't possible due to ARP being a 
  Layer 2 protocol; only a reporting/dashboard layer could be cloud-hosted
