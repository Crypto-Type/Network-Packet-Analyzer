# Network-Packet-Analyzer
Network Monitoring

from scapy.all import sniff, IP, TCP, UDP, Raw

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = ""
        payload = ""

        # Determine Protocol and Extract Payload
        if TCP in packet:
            proto = "TCP"
            if Raw in packet:
                payload = packet[Raw].load[:20]  # Show first 20 bytes for brevity
        elif UDP in packet:
            proto = "UDP"
            if Raw in packet:
                payload = packet[Raw].load[:20]
        else:
            proto = str(packet[IP].proto)
        
        # Display info
        print(f"Source: {ip_src} -> Destination: {ip_dst} | Protocol: {proto} | Payload: {payload}")

def main():
    print("Starting packet sniffer... (Press Ctrl+C to stop)")
    sniff(prn=packet_callback, count=10)  # Capture 10 packets; remove count for infinite

if __name__ == "__main__":
    main()

Method

pip install scapy
Run the program
