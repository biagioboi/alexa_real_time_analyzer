import pyshark
import time
from datetime import datetime

# quando riceviamo hight_layer = data significa che stiamo inviando / ricevendo dati, se invece TCP è semplicemente un ACK
def filter_packets(p, mac_add):
    val = None
    try:
        # add new ip here
        if p.eth.dst == mac_add:
            print("dst")
            stranger_ip = p.ip.src
            print(p.ip.dst)
        elif p.eth.src == mac_add:
            print("src")
            stranger_ip = p.ip.dst
            print(p.ip.src)
        else:
            # print(p.eth.dst, p.eth.src)
            return None
        print(p.tcp.flags_ack)
        # since tcp is always defined in the communication, let's see if is an ack or not
        is_ack = p.tcp.ack
        print(packet.highest_layer)
        if packet.highest_layer == 'TCP' or packet.highest_layer == 'TLS':
            if p.tcp.stream in stream_hour:
                delta = p.sniff_time - stream_hour.get(p.tcp.stream)
            elif p.tcp.stream not in stream_hour:
                delta = p.sniff_time
                stream_hour.update({p.tcp.stream: delta})
                delta = 0
            body_ = {'date': p.sniff_time,
                     'delta': delta,
                     'src': p.eth.src,
                     'dst': p.eth.dst,
                     'stranger': stranger_ip,
                     'layer': p.highest_layer,
                     'tcpsrcport': packet.tcp.srcport,
                     'tcpdstport': packet.tcp.dstport,
                     'stream': p.tcp.stream,
                     'payload': p.captured_length,
                     'hops': 0,
                     'conv': val}
            # to print body into a csv file
        else:
            delta = 0
            body_ = {'date': p.sniff_time, 'delta': delta, 'src': p.eth.src, 'dst': p.eth.dst, 'stranger': stranger_ip,
                     'layer': p.highest_layer, 'tcpsrcport': None, 'tcpdstport': None, 'stream': None,
                     'payload': p.captured_length, 'hops': 0, 'conv': val}
            # to print body into a csv file
    except:
        pass


if __name__ == "__main__":
    # insert here the name of the internet interface you want to sniff and mac address of device to sniff
    capture = pyshark.LiveCapture(interface='Connessione alla rete locale (LAN)* 11')
    mac_address = "08:7c:39:96:8a:8c"

    for packet in capture.sniff_continuously():
        print(datetime.now().strftime("%H:%M:%S"))
        filter_packets(packet, mac_address)
