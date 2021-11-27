import pyshark
import time
from datetime import datetime

spotify_ip = None

def filter_packets(p, mac_add):
    val = None
    global spotify_ip

    if p.eth.src != mac_add:
        return None

    highest_layer = p.highest_layer
    length = 0

    try:
        if highest_layer == "SSL":
            record_length = int(p.ssl.record_content_type)
            if record_length == 21 or record_length == 22:
                print("Handshake")
            elif record_length == 23:
                # Application Data Len = 41 allowed since is a sync packet
                if int(p.ssl.record_length) == 41:
                    print("Syn")
                else:
                    print("Application Data")
            length = p.ssl.record_length
        elif highest_layer == "TCP":
            # if the ack flags it's 1 means that contains a flag, but we need to check if contains also payload
            if int(p.tcp.flags_ack) == 1 and int(p.tcp.len) == 0:
                # we're in ack, ack of what ?
                if p.ip.dst == spotify_ip:
                    print("Spotify Ack")
                else:
                    print("Ack")
            else:
                print("TCP Data")
            length = p.tcp.len
        elif highest_layer == "DATA":
            print("Data packets")
            length = p.data.len
        elif highest_layer == "ARP":
            print("Not relevant")
        elif highest_layer == "HTTP":
            # check if is a song by checking the endpoint if contains "audio"
            request_uri = p.http.request_uri
            if "audio" in request_uri:
                # Store the ip of provider of music
                spotify_ip = p.ip.dst
                print("Request for a song")
    except AttributeError:
        print(p[highest_layer].field_names)
    print(str(length) + "\n")


if __name__ == "__main__":
    # insert here the name of the internet interface you want to sniff and mac address of device to sniff
    capture = pyshark.LiveCapture(interface='Connessione alla rete locale (LAN)* 11')
    mac_address = "08:7c:39:96:8a:8c"

    for packet in capture.sniff_continuously():
        filter_packets(packet, mac_address)
