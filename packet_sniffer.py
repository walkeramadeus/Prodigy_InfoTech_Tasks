from scapy.all import sniff, Raw
from scapy.layers.inet import IP, TCP, UDP, ICMP

def packet_callback(packet, log_file):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        protocol = ip_layer.proto

        # Determine the protocol type
        if protocol == 6:  # TCP
            protocol_name = "TCP"
        elif protocol == 17:  # UDP
            protocol_name = "UDP"
        elif protocol == 1:  # ICMP
            protocol_name = "ICMP"
        else:
            protocol_name = "Other"

        # Get source and destination IP addresses
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        log_file.write(f"Protocol: {protocol_name}\n")
        log_file.write(f"Source IP: {src_ip}\n")
        log_file.write(f"Destination IP: {dst_ip}\n")

        # Display payload data if present
        if Raw in packet:
            payload = packet[Raw].load
            log_file.write(f"Payload: {payload}\n")
        else:
            log_file.write("No Payload\n")

        log_file.write("-" * 50 + "\n")

def main():
    print("Starting packet sniffer...")
    with open("packet_log.txt", "a") as log_file:
        # Start sniffing packets
        sniff(prn=lambda x: packet_callback(x, log_file), store=0)

if __name__ == "__main__":
    main()
