import webview
import os
import sys
import atexit
import threading
import time
import random
import json

# marker color
colors = [
    '#d63031', '#0984e3', '#00b894', '#6c5ce7', '#e17055', '#d63031',
    '#ff7675', '#74b9ff', '#55efc4', '#a29bfe', '#fab1a0', '#fdcb6e',
    '#e84393', '#2d3436' 
]




def packet_listener(window_ref, new_packet):

    print(f"\n[+] Nuovo pacchetto rilevato: {new_packet['server_name']}")
    add_marker_to_map(window_ref, new_packet)

def add_marker_to_map(window_ref, server_data):

    """
    PACKET STRUCTURE
    "source_ip": f"{source_ip}:{source_port}",
    "destination_ip": f"{dest_ip}:{des_port}",
    "transport_protocol": protocol, #Packet info
    "protocol": application, #Packet info
    "location_source": source_country,
    "source_coordinate": source_coordinate,
    "location_destination": dest_country,
    "destination_coordinate": dest_coordinate,
    "length": length, #Packet info
    "to_me": to_me,
    "from_me": from_me,
    "details": details,
    "long_details": long_details,
    "server_name": server_name
    """

    if (server_data['to_me'] or server_data['from_me']):
        if server_data['to_me']:
            server_loc = server_data['source_coordinate']
            server_ip = server_data['source_ip'].split(':')[0]
            source_loc_packet = server_data['location_destination']
            source_ip_packet = server_data['destination_ip']
        elif server_data['from_me']:
            server_loc = server_data['destination_coordinate']
            server_ip = server_data['destination_ip'].split(':')[0]
            source_loc_packet = server_data['location_source']
            source_ip_packet = server_data['source_ip']
        
        server_info = {
                        "location": server_loc,
                        "name": server_data['server_name'],
                        "ip": server_ip,
                        "details": server_data['details'],
                        "long_details": server_data['long_details'],
                        "color": random.choice(colors)
                        }
        
        packet_info = {
                        "protocol": server_data['protocol'],
                        "transport_protocol": server_data['transport_protocol'],
                        "length": server_data['length'],
                        "source": server_data['location_source'],
                        "destination": server_data['location_destination'],
                        "ip_source": server_data['source_ip'],
                        "ip_destination": server_data['destination_ip']
                        }
                        
        if server_info['location'] != "None":
            
            server_json = json.dumps(server_info)
            packet_json = json.dumps(packet_info)
            
            js_command = f"addMarker({server_json},{packet_json});"
            
            print(f"[*] Esecuzione JS: {js_command}")
            print(f"[FUNZIONE ADD_MARKER] ricevuto: {server_data}")

            # -- FUNCTION IN HTML --
            
            window_ref.evaluate_js(js_command)
    else:
        print("[FUNZIONE ADD_MARKER] ricevuto pacchetto non mio")


