import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        http_layer = packet.getlayer(http.HTTPRequest)
        host = http_layer.Host.decode() if http_layer.Host else 'N/A'
        path = http_layer.Path.decode() if http_layer.Path else 'N/A'
        full_url = f"http://{host}{path}"

        print("\n[+] HTTP Request >>")
        print(f"Method: {http_layer.Method.decode() if http_layer.Method else 'N/A'}")
        print(f"Host: {host}")
        print(f"Path: {full_url}")

        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load.decode(errors='ignore')
            print(f"Payload: {load}")


interf = input("Enter your Interface: ")
sniff(interf)