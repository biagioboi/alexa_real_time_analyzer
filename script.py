import json
import csv
import pyshark
from datetime import date

spotify_ip = None
stream_hour = {}

def filter_packets(p, mac_add, writer, microphone, synchronized):
    global spotify_ip, stream_hour
    # Analyze just the sent packets
    if p.eth.src != mac_add:
        return None
    highest_layer = p.highest_layer
    try:
        kind_of_packet = None
        packet_len = p.captured_length
        delta = 0
        content_type = None
        if highest_layer == "SSL":
            content_type = int(p.ssl.record_content_type)
            # 20 means change spec cipher 21 or 22 means handshake
            if content_type == 20 or content_type == 21 or content_type == 22:
                kind_of_packet = "handshake"
            # 23 means Application Data
            elif content_type == 23:
                # Application Data Len = 41 allowed since is a sync packet, also Len = 28 it's syn
                if int(p.ssl.record_length) == 41 or int(p.ssl.record_length) == 28:
                    kind_of_packet = "syn"
                else:
                    kind_of_packet = "not_justified"
            else:
                print(content_type)
        elif highest_layer == "TCP":
            # if the ack flags it's 1 means that contains a flag, but we need to check if contains also payload
            if int(p.tcp.flags_ack) == 1 and int(p.tcp.len) == 0:
                # we're in ack, ack of what ?
                if p.ip.dst == spotify_ip:
                    kind_of_packet = "ack"
                else:
                    kind_of_packet = "ack"
            else:
                # if len = 11 means that is a syn packet with Google server
                if int(p.tcp.len) == 11:
                    kind_of_packet = "syn"
                elif int(p.tcp.len) == 0:
                    kind_of_packet = "retransmit"
                else:
                    kind_of_packet = "not_relevant"
        elif highest_layer == "DATA":
            if p.tcp.dstport == "4070": # used for synchronization
                kind_of_packet = "syn"
            else:
                kind_of_packet = "not_relevant"
        elif highest_layer == "HTTP":
            # check if is a song by checking the endpoint if contains "audio"
            request_uri = p.http.request_uri
            if "audio" in request_uri:
                # Store the ip of provider of music
                spotify_ip = p.ip.dst
                kind_of_packet = "not_relevant"
            else:
                kind_of_packet = "not_relevant"
        else: # no important packet has been recorded, we can return
            return None
        # store the time (in milliseconds) occurred from the last communication with the same server
        delta = 0
        if highest_layer == "TCP" or highest_layer == "SSL":
            if p.tcp.stream in stream_hour:
                delta = p.sniff_time - stream_hour.get(p.tcp.stream)
                delta = int(delta.total_seconds() * 1000)
                stream_hour.update({p.tcp.stream:p.sniff_time})
            else:
                delta = p.sniff_time
                stream_hour.update({p.tcp.stream:delta})
                delta = 0
        record = {"date": p.sniff_time, "length": packet_len, "dst": p.ip.dst, "dstport": p.tcp.dstport, "highest_layer": highest_layer, "delta": delta, "ack_flag": int(p.tcp.flags_ack), "microphone": microphone, "content_type": content_type, "synchronized": synchronized, "class": kind_of_packet}
        values = []
        for x in record:
            values.append(record[x])
        writer.writerow(values)
        print(json.dumps(record, indent=2, default=str) + "\n")
    except AttributeError:
        print(p[highest_layer].field_names)


if __name__ == "__main__":
    # insert here the name of the internet interface you want to sniff and mac address of device to sniff
    capture = pyshark.LiveCapture(interface='Connessione alla rete locale (LAN)* 11')
    mac_address = "08:7c:39:96:8a:8c"
    today = date.today()
    d1 = today.strftime("%d_%m")
    with open('dataset' + d1 + '.csv', 'a+', encoding='UTF8', newline='') as f:
        writer = csv.writer(f)
        for packet in capture.sniff_continuously():

            filter_packets(packet, mac_address, writer, 1, 1)

