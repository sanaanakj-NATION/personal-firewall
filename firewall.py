import json
import subprocess
import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP

with open("rules.json") as f:
    rules = json.load(f)

already_blocked = set()

def log(msg):
    line = f"[{datetime.datetime.now():%Y-%m-%d %H:%M:%S}] {msg}"
    print(line)
    with open("firewall.log", "a") as f:
        f.write(line + "\n")

def block_ip(ip):
    if ip in already_blocked:
        return
    subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
    already_blocked.add(ip)
    log(f"iptables rule added: DROP all from {ip}")

def block_port(port):
    key = f"port{port}"
    if key in already_blocked:
        return
    subprocess.run(["iptables", "-A", "INPUT", "-p", "tcp",
                    "--dport", str(port), "-j", "DROP"])
    already_blocked.add(key)
    log(f"iptables rule added: DROP tcp port {port}")

def check_packet(pkt):
    if IP not in pkt:
        return

    src = pkt[IP].src
    dst = pkt[IP].dst
    proto = "OTHER"
    dport = None

    if TCP in pkt:
        proto, dport = "TCP", pkt[TCP].dport
    elif UDP in pkt:
        proto, dport = "UDP", pkt[UDP].dport
    elif ICMP in pkt:
        proto = "ICMP"

    if src in rules["blocked_ips"]:
        log(f"BLOCKED IP  | {src} -> {dst} | {proto}")
        block_ip(src)
    elif dport in rules["blocked_ports"]:
        log(f"BLOCKED PORT| {src} -> {dst}:{dport} | {proto}")
        block_port(dport)
    elif proto in rules["blocked_protocols"]:
        log(f"BLOCKED PROTO| {src} -> {dst} | {proto}")
    else:
        log(f"ALLOWED     | {src} -> {dst} | {proto} port={dport}")

print("Firewall chal raha hai... band karne ke liye Ctrl+C")
sniff(prn=check_packet, store=False)
