from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime


def packet_callback(packet):

    print("\n" + "=" * 80)

    print("Timestamp :", datetime.now())

    if packet.haslayer(IP):

        ip_layer = packet[IP]

        source_ip = ip_layer.src
        destination_ip = ip_layer.dst

        print(f"Source IP      : {source_ip}")
        print(f"Destination IP : {destination_ip}")

        protocol = "Other"

        if packet.haslayer(TCP):
            protocol = "TCP"

            tcp_layer = packet[TCP]

            print(f"Source Port    : {tcp_layer.sport}")
            print(f"Destination Port : {tcp_layer.dport}")

        elif packet.haslayer(UDP):
            protocol = "UDP"

            udp_layer = packet[UDP]

            print(f"Source Port    : {udp_layer.sport}")
            print(f"Destination Port : {udp_layer.dport}")

        elif packet.haslayer(ICMP):
            protocol = "ICMP"

        print(f"Protocol       : {protocol}")

        print(f"Packet Length  : {len(packet)} bytes")

        if packet.haslayer(Raw):

            try:
                payload = packet[Raw].load

                print("\nPayload Data:")

                try:
                    print(payload.decode('utf-8', errors='ignore'))

                except:
                    print(payload)

            except Exception as e:
                print("Payload Error:", e)

    else:
        print("Non-IP Packet Captured")


def start_sniffing():

    print("=" * 80)
    print(" BASIC NETWORK SNIFFER ")
    print("=" * 80)

    print("Capturing packets...")
    print("Press CTRL + C to stop.\n")

    sniff(
        prn=packet_callback,
        store=False
    )


if __name__ == "__main__":
    start_sniffing()