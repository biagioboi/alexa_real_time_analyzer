import joblib
import pyshark
import sklearn
import pandas as pd
from pickle import load

stream_hour = {}

def filter_packets(p, mac_add, microphone, model, scaler):
    global stream_hour
    # Analyze just the sent packets
    if p.eth.src != mac_add:
        return None
    highest_layer = p.highest_layer
    try:
        packet_len = p.captured_length
        if highest_layer not in ["SSL", "TCP", "DATA", "HTTP"]:
            return None
        content_type = 0
        if highest_layer == "SSL":
            content_type = int(p.ssl.record_content_type)
        # store the time (in milliseconds) occurred from the last communication with the same server
        delta = 0
        if highest_layer == "TCP" or highest_layer == "SSL":
            if p.tcp.stream in stream_hour:
                delta = p.sniff_time - stream_hour.get(p.tcp.stream)
                delta = int(delta.total_seconds() * 1000)
                stream_hour.update({p.tcp.stream: p.sniff_time})
            else:
                delta = p.sniff_time
                stream_hour.update({p.tcp.stream: delta})
                delta = 0
        if highest_layer == "SSL":
            highest_layer = 0.0
        elif highest_layer == "TCP":
            highest_layer = 1.0
        elif highest_layer == "DATA":
            highest_layer = 2.0
        else:
            highest_layer = 3.0

        record = {"length": packet_len, "dstport": p.tcp.dstport, "highest_layer": highest_layer, "delta": delta, "ack_flag": int(p.tcp.flags_ack),
                  "microphone": microphone, "content_type": content_type}
        df = pd.DataFrame(record, index=[0])
        scaled_value = scaler.transform(df.values)
        result = model.predict(scaled_value)
        print(result[0])
    except AttributeError:
        print(p[highest_layer].field_names)


if __name__ == "__main__":
    # insert here the name of the internet interface you want to sniff and mac address of device to sniff
    capture = pyshark.LiveCapture(interface='Connessione alla rete locale (LAN)* 11')
    mac_address = "08:7c:39:96:8a:8c"
    model = load(open('classifier/model.pkl', 'rb'))
    scaler = load(open('classifier/scaler.pkl', 'rb'))
    for packet in capture.sniff_continuously():
        filter_packets(packet, mac_address, 1, model, scaler)