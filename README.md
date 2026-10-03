# Personal Firewall (Python + iptables)

A simple personal firewall that sniffs network packets, checks them
against rules in `rules.json`, logs every decision, and adds iptables
rules to block unwanted traffic.

## Features
- Packet sniffing with Scapy (TCP, UDP, ICMP)
- Rule-based filtering: blocked IPs, ports and protocols
- Logging to `firewall.log` (ALLOWED / BLOCKED)
- Automatic iptables DROP rules for blocked IPs and ports

## Requirements
- Linux (Ubuntu / WSL2 tested)
- Python 3, Scapy, iptables

## Installation
sudo apt update
sudo apt install python3 python3-scapy iptables -y

## Usage
1. Edit `rules.json`:
   {"blocked_ips": ["192.168.1.50"], "blocked_ports": [23, 445], "blocked_protocols": []}
2. Run: sudo python3 firewall.py
3. Stop with Ctrl+C, then clear rules: sudo iptables -F

## How it works
Each packet is checked in order: source IP, destination port, protocol.
Matching packets are logged as BLOCKED and an iptables rule is added.
Everything else is logged as ALLOWED.

## Limitations
- Packets are inspected after they arrive, so the first packet from a
  newly blocked source may get through before the rule is applied.
- Protocol rules only log, they do not add iptables rules.

## Author
Mohammed Sanaan
