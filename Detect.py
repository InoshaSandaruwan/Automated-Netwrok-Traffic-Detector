import scapy.all as scapy
from datetime import datetime
from collections import defaultdict

# Define ignored ports and ephemeral ports
IGNORE_PORTS = {53, 80, 443, 67, 68, 123}  # Common service ports to ignore (DNS, HTTP, etc.)
EPHEMERAL_PORT_RANGE = (1024, 65535)  # Ephemeral ports (commonly used by client-side apps)
scan_types = {}
packet_counts = defaultdict(int)

# Function to log alerts to alert.log
def log_alert(scan_type, src_ip, dst_ip, dst_port, protocol):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
    with open("alert.log", "a") as alert_file:
        alert_file.write(f"[{timestamp}] ⚠ {scan_type} Detected from {src_ip} → {dst_ip} Port: {dst_port} Protocol: {protocol}\n")

# Function to handle TCP scans (SYN scan)
def tcp_scan(packet):
    if packet.haslayer(scapy.TCP):
        # SYN scan detection (SYN flag is set, no ACK)
        if packet[scapy.TCP].flags == "S":  # SYN flag set (TCP SYN scan)
            return True
    return False

# Function to handle UDP scans
def udp_scan(packet):
    if packet.haslayer(scapy.UDP):
        # Avoid flagging DNS, DHCP, etc., as scans by ignoring certain ports
        dst_port = packet[scapy.UDP].dport
        if dst_port in IGNORE_PORTS:
            return False  # Ignore DNS, DHCP, etc.
        return True
    return False

# Function to handle ICMP scans (Ping Sweep)
def icmp_scan(packet):
    if packet.haslayer(scapy.ICMP) and packet[scapy.ICMP].type == 8:  # Echo request (ping)
        return True
    return False

# Function to detect Anomalous Traffic
def anomalous_traffic(packet):
    return packet_counts[packet[scapy.IP].src] > 100

# Adding scan types to the dictionary
scan_types["TCP Scan"] = tcp_scan
scan_types["UDP Scan"] = udp_scan
scan_types["ICMP Scan"] = icmp_scan

# Function to process packets
def process_packet(packet):
    if not packet.haslayer(scapy.IP) and not packet.haslayer(scapy.ARP):  # Ignore non-IP & non-ARP packets
        return

    src_ip = packet[scapy.IP].src if packet.haslayer(scapy.IP) else packet[scapy.ARP].psrc
    dst_ip = packet[scapy.IP].dst if packet.haslayer(scapy.IP) else packet[scapy.ARP].pdst
    protocol = "Unknown"
    dst_port = "N/A"

    if packet.haslayer(scapy.TCP):
        protocol = "TCP"
        dst_port = packet[scapy.TCP].dport
    elif packet.haslayer(scapy.UDP):
        protocol = "UDP"
        dst_port = packet[scapy.UDP].dport
    elif packet.haslayer(scapy.ICMP):
        protocol = "ICMP"
    elif packet.haslayer(scapy.ARP):
        protocol = "ARP"

    # Display live packet details (for debugging)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
    print(f"[{timestamp}] {protocol} Packet: {src_ip} → {dst_ip} Port: {dst_port}")

    # Ignore normal traffic (DNS, HTTP, DHCP, ephemeral ports)
    if dst_port != "N/A" and (dst_port in IGNORE_PORTS or EPHEMERAL_PORT_RANGE[0] <= dst_port <= EPHEMERAL_PORT_RANGE[1]):
        return

    # **🚀 FIX: Ignore normal ARP traffic**
    if packet.haslayer(scapy.ARP):
        if packet[scapy.ARP].op == 2:  # Ignore ARP replies (normal responses)
            return
        if dst_ip.endswith(".255"):  # Ignore ARP broadcasts (network-wide discovery)
            return

    # Detect scans & anomalies
    for scan, check in scan_types.items():
        if check(packet):
            log_alert(scan, src_ip, dst_ip, dst_port, protocol)
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] ⚠ {scan} Detected from {src_ip} → {dst_ip} Port: {dst_port} Protocol: {protocol}")
            return

    # Track abnormal traffic per IP
    packet_counts[src_ip] += 1
    if packet_counts[src_ip] > 100:
        log_alert("Anomalous Traffic", src_ip, dst_ip, dst_port, protocol)
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] ⚠ Anomalous Traffic Detected from {src_ip} → {dst_ip} Port: {dst_port} Protocol: {protocol}")

# Function to start sniffing
def start_sniffing():
    print("🔍 Monitoring network traffic in real-time...")
    scapy.sniff(iface="eth0", prn=process_packet, store=0)

if __name__ == "__main__":
    start_sniffing()
