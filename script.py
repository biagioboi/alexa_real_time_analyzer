import pyshark
import time
from datetime import datetime


def filter_packets(p, mac_add):
    val = None
    if p.eth.dst != mac_add and p.eth.src != mac_add:
        return None

    highest_layer = p.highest_layer
    length = 0

    if highest_layer == "SSL":
        if p.ssl.get_field_value('record_content_type') == "21" or p.ssl.get_field_value('record_content_type') == "22":
            print("Handshake")
        elif p.ssl.get_field_value('record_content_type') == "23":
            # Application Data Len = 41 allowed since is a sync packet
            print("Application Data")
        length = p.ssl.record_length
    elif highest_layer == "TCP":
        if p.tcp.flags_ack == 1:
            print("Ack")
        else:
            print("TCP Data")
        length = p.tcp.len
    elif highest_layer == "DATA":
        print("Data packets")
        length = p.data.len
    elif highest_layer == "ARP":
        print("Not relevant")
    else:
        print(highest_layer)
    print(str(length) + "\n")


if __name__ == "__main__":
    # insert here the name of the internet interface you want to sniff and mac address of device to sniff
    capture = pyshark.LiveCapture(interface='Connessione alla rete locale (LAN)* 11')
    mac_address = "08:7c:39:96:8a:8c"

    for packet in capture.sniff_continuously():
        filter_packets(packet, mac_address)
