from scapy.all import sniff, TCP, UDP, ICMP, IP, Raw
import time
import signal

def signal_handler(sig, frame):
    print("\nProgram interrupted by user.")
    raise SystemExit(0)

signal.signal(signal.SIGINT, signal_handler)

def process_packet(packet):
    # Check if the packet has a TCP layer
    if packet.haslayer(TCP):
        print("TCP Packet:")
        print("  Source IP:", packet[IP].src)
        print("  Destination IP:", packet[IP].dst)
        print("  Source Port:", packet[TCP].sport)
        print("  Destination Port:", packet[TCP].dport)
        print("  Flags:", packet[TCP].flags)
        if packet.haslayer(Raw):
            print("  Payload:", packet[Raw].load)

    # Check if the packet has a UDP layer
    elif packet.haslayer(UDP):
        print("UDP Packet:")
        print("  Source IP:", packet[IP].src)
        print("  Destination IP:", packet[IP].dst)
        print("  Source Port:", packet[UDP].sport)
        print("  Destination Port:", packet[UDP].dport)
        if packet.haslayer(Raw):
            print("  Payload:", packet[Raw].load)

    # Check if the packet has an ICMP layer
    elif packet.haslayer(ICMP):
        print("ICMP Packet:")
        print("  Source IP:", packet[IP].src)
        print("  Destination IP:", packet[IP].dst)
        print("  Type:", packet[ICMP].type)
        print("  Code:", packet[ICMP].code)

start_time = time.time()
sniff(prn=process_packet, store=False)