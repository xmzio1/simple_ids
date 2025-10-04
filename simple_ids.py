#!/usr/bin/env python3

import argparse
import logging
import time
from collections import defaultdict, deque
from scapy.all import sniff, TCP, IP, ICMP

DEFAULT_WINDOW = 10
DEFAULT_SYN_THRESHOLD = 100
DEFAULT_ICMP_THRESHOLD = 200
DEFAULT_PORT_SCAN_PORTS = 20
ALERT_COOLDOWN = 60
LOGFILE = "simple_ids.log"

syn_counters = defaultdict(lambda: deque())
icmp_counters = defaultdict(lambda: deque())
ports_seen = defaultdict(lambda: defaultdict(lambda: deque()))
last_alert_time = defaultdict(lambda: 0)

logger = logging.getLogger("simple_ids")
logger.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s %(levelname)s: %(message)s")
ch = logging.StreamHandler()
ch.setFormatter(formatter)
logger.addHandler(ch)
fh = logging.FileHandler(LOGFILE)
fh.setFormatter(formatter)
logger.addHandler(fh)

def purge_old(deq: deque, window: float, now: float):
    while deq and (now - deq[0]) > window:
        deq.popleft()

def alert(src: str, kind: str, message: str, cooldown: int):
    key = (src, kind)
    now = time.time()
    if now - last_alert_time[key] < cooldown:
        return
    last_alert_time[key] = now
    logger.warning(f"[{kind.upper()}] {src} - {message}")

def handle_packet(pkt, args):
    now = time.time()
    if IP not in pkt:
        return
    src = pkt[IP].src

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        flags = tcp.flags
        if flags & 0x02 and not (flags & 0x10):
            dq = syn_counters[src]
            dq.append(now)
            purge_old(dq, args.window, now)
            syn_count = len(dq)
            if syn_count >= args.syn_threshold:
                alert(src, "syn", f"{syn_count} SYNs in last {args.window}s (threshold={args.syn_threshold})", ALERT_COOLDOWN)

        dst_port = tcp.dport
        pdq = ports_seen[src][dst_port]
        pdq.append(now)
        purge_old(pdq, args.window, now)
        distinct_ports = sum(1 for p, dq in ports_seen[src].items() if dq and (now - dq[-1]) <= args.window)
        if distinct_ports >= args.port_scan_ports:
            alert(src, "portscan", f"{distinct_ports} distinct destination ports touched in last {args.window}s (threshold={args.port_scan_ports})", ALERT_COOLDOWN)

    if pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        if icmp.type == 8:
            dq = icmp_counters[src]
            dq.append(now)
            purge_old(dq, args.window, now)
            icmp_count = len(dq)
            if icmp_count >= args.icmp_threshold:
                alert(src, "icmp", f"{icmp_count} ICMP echo requests in last {args.window}s (threshold={args.icmp_threshold})", ALERT_COOLDOWN)

def main():
    parser = argparse.ArgumentParser(description="Simple network IDS (SYN/ICMP/port-scan detectors) using Scapy")
    parser.add_argument("-i", "--iface", required=True, help="Interface to sniff (e.g., eth0)")
    parser.add_argument("--syn-threshold", type=int, default=DEFAULT_SYN_THRESHOLD, help=f"SYN packets from same IP within window to trigger alert (default {DEFAULT_SYN_THRESHOLD})")
    parser.add_argument("--icmp-threshold", type=int, default=DEFAULT_ICMP_THRESHOLD, help=f"ICMP echo requests from same IP within window to trigger alert (default {DEFAULT_ICMP_THRESHOLD})")
    parser.add_argument("--port-scan-ports", type=int, default=DEFAULT_PORT_SCAN_PORTS, help=f"Distinct destination ports touched within window to trigger port-scan alert (default {DEFAULT_PORT_SCAN_PORTS})")
    parser.add_argument("--window", type=int, default=DEFAULT_WINDOW, help=f"Sliding window in seconds (default {DEFAULT_WINDOW})")
    parser.add_argument("--bpf", type=str, default=None, help="Optional BPF filter to pass to scapy.sniff (e.g., 'tcp or icmp')")
    args = parser.parse_args()

    logger.info("Starting simple IDS")
    logger.info(f"Interface: {args.iface}, window={args.window}s, syn_threshold={args.syn_threshold}, icmp_threshold={args.icmp_threshold}, port_scan_ports={args.port_scan_ports}")
    if args.bpf:
        logger.info(f"Using BPF filter: {args.bpf}")

    try:
        sniff(iface=args.iface, prn=lambda p: handle_packet(p, args), store=False, filter=args.bpf)
    except PermissionError:
        logger.error("Permission denied: you probably need to run as root (sudo)")
    except Exception as e:
        logger.exception(f"Sniffing error: {e}")

if __name__ == "__main__":
    main()
