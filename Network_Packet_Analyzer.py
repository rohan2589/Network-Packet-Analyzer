from scapy.all import sniff, IP, TCP, UDP, Raw

def packet_callback(packet):
    print("="*60)
    if IP in packet:
        ip_layer = packet[IP]
        print(f"Source IP      : {ip_layer.src}")
        print(f"Destination IP : {ip_layer.dst}")
        print(f"Protocol       : {ip_layer.proto}")
        
        # Check for TCP/UDP layer
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"Source Port    : {tcp_layer.sport}")
            print(f"Destination Port: {tcp_layer.dport}")
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"Source Port    : {udp_layer.sport}")
            print(f"Destination Port: {udp_layer.dport}")
        
        # Raw Payload
        if Raw in packet:
            raw_data = packet[Raw].load
            print(f"Payload        : {raw_data[:50]}...")  # show only first 50 bytes
    else:
        print("Non-IP Packet")

# Start sniffing
print("Starting packet sniffer... Press Ctrl+C to stop.")
sniff(prn=packet_callback, store=False)
