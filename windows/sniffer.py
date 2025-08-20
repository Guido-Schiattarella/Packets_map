import pyshark
import ipinfo
import socket
import netifaces
import ipaddress
import multiprocessing
import sys
import os
import time

########################################
## INSERT HERE YOUR NETWORK INTERFACE ##
########################################

INTERFACE_FOR_PYSHARK = r'your_network_interface' 

#####################################################
## INSET HERE YOUR NETWORK INTERFACE FOR NATIFACES ##
#####################################################

INTERFACE_GUID_FOR_NETIFACES = 'your_network_interface_guid'

###################################
## INSERT HERE YOUR IPINFO TOKEN ##
###################################

IPINFO_TOKEN = 'your_ipinfo_token' 

def get_network_address(interface_guid):
    
    try:
        addrs = netifaces.ifaddresses(interface_guid)
        if netifaces.AF_INET in addrs:
            ip = addrs[netifaces.AF_INET][0]['addr']
            netmask = addrs[netifaces.AF_INET][0]['netmask']
            
            network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
            return str(network)
    except Exception as e:
        print(f"Errore nel trovare l'indirizzo di rete: {e}")
        return None

def is_ip_in_network(network_with_netmask, ip_to_check):
    try:
        network = ipaddress.ip_network(network_with_netmask, strict=False)
        ip = ipaddress.ip_address(ip_to_check)
        return ip in network
    except ValueError:
        return False

def get_coordinates_from_ipinfo(ip_details):
    
    try:
        if 'loc' in ip_details and ip_details['loc']:
            lat, lon = ip_details['loc'].split(',')
            return [float(lat), float(lon)]
        return [0.0, 0.0]  
    except:
        return [0.0, 0.0]

def get_server_name(ip_details):
    
    try:
        org = ip_details.get('org', 'Unknown')
        city = ip_details.get('city', 'Unknown')
        country = ip_details.get('country', 'XX')
        
        
        if org.startswith('AS'):
            parts = org.split(' ', 2)
            if len(parts) > 2:
                org = parts[2]
            elif len(parts) > 1:
                org = parts[1]
        
        return f"{org} ({city}, {country})"
    except:
        return "Unknown Server"

def packet_sniffer_process(packet_queue, stop_event):
   
    handler = ipinfo.getHandler(IPINFO_TOKEN)
    my_ip = socket.gethostbyname(socket.gethostname())
    network_address_with_netmask = get_network_address(INTERFACE_GUID_FOR_NETIFACES)

    if not network_address_with_netmask:
        print("Impossibile determinare la rete locale. Il processo terminerà.")
        return

    print(f"Avvio sniffer... IP locale: {my_ip}, Rete: {network_address_with_netmask}")
    
    
    capture = pyshark.LiveCapture(interface=INTERFACE_FOR_PYSHARK)

    try:
        for packet in capture.sniff_continuously():
            if stop_event.is_set():
                print("Evento di stop ricevuto, terminazione della cattura.")
                break

            if not hasattr(packet, 'ip'):
                continue
            
            source_ip = packet.ip.src
            dest_ip = packet.ip.dst
            
           
            source_port = getattr(packet[packet.transport_layer], 'srcport', '0') if hasattr(packet, 'transport_layer') and packet.transport_layer else '0'
            dest_port = getattr(packet[packet.transport_layer], 'dstport', '0') if hasattr(packet, 'transport_layer') and packet.transport_layer else '0'
            transport_protocol = packet.transport_layer if hasattr(packet, 'transport_layer') else 'Unknown'
            length = packet.length if hasattr(packet, 'length') else 0

            
            if source_ip == "34.117.59.81" or dest_ip == "34.117.59.81":
                continue

            is_local = is_ip_in_network(network_address_with_netmask, source_ip) and \
                       is_ip_in_network(network_address_with_netmask, dest_ip)
            
            
            if is_local:
                continue  

           
            try:
                ip_loc_source = handler.getDetails(source_ip).all
                ip_loc_dest = handler.getDetails(dest_ip).all

                from_me = source_ip == my_ip
                to_me = dest_ip == my_ip
                
                
                details = "N/A"
                long_details = "N/A"
                server_name = "Unknown"
                
                if from_me and "bogon" not in ip_loc_dest:
                    details = f"Server situato in {ip_loc_dest.get('region', 'N/A')}, {ip_loc_dest.get('country_name', 'N/A')}({ip_loc_dest.get('city', 'N/A')})"
                    long_details = (f"Server proprietà di {ip_loc_dest.get('org', 'N/A')} situato in {ip_loc_dest.get('region', 'N/A')}, {ip_loc_dest.get('country_name', 'N/A')}({ip_loc_dest.get('city', 'N/A')}): " +
                                    f"{get_coordinates_from_ipinfo(ip_loc_dest)} con fusorario {ip_loc_dest.get('timezone', 'N/A')} e moneta ufficiale del Paese {ip_loc_dest.get('country_currency', 'N/A')}"
                                    )
                    server_name = get_server_name(ip_loc_dest)
                elif to_me and "bogon" not in ip_loc_source:
                    details = f"Server situato in {ip_loc_source.get('region', 'N/A')}, {ip_loc_source.get('country_name', 'N/A')}({ip_loc_source.get('city', 'N/A')})"
                    long_details = (f"Server proprietà di {ip_loc_source.get('org', 'N/A')} situato in {ip_loc_source.get('region', 'N/A')}, {ip_loc_source.get('country_name', 'N/A')}({ip_loc_source.get('city', 'N/A')}): " +
                                    f"{get_coordinates_from_ipinfo(ip_loc_source)} con fusorario {ip_loc_source.get('timezone', 'N/A')} e moneta ufficiale del Paese {ip_loc_source.get('country_currency', 'N/A')}"
                                    )
                    server_name = get_server_name(ip_loc_source)
                
                
                packet_details = {
                    "source_ip": f"{source_ip}:{source_port}",
                    "destination_ip": f"{dest_ip}:{dest_port}",
                    "transport_protocol": transport_protocol,
                    "protocol": "Internet", 
                    "location_source": ip_loc_source.get('country_name', 'N/A'),
                    "source_coordinate": get_coordinates_from_ipinfo(ip_loc_source),
                    "location_destination": ip_loc_dest.get('country_name', 'N/A'),
                    "destination_coordinate": get_coordinates_from_ipinfo(ip_loc_dest),
                    "length": length,
                    "to_me": to_me,
                    "from_me": from_me,
                    "details": details,
                    "long_details": long_details,
                    "server_name": server_name
                }
                
                packet_queue.put(packet_details)
                
            except Exception as e:
                
                pass 

    except Exception as e:
        print(f"Errore critico durante la cattura: {e}")
    finally:
        capture.close()
        print("Processo sniffer terminato.")

if __name__ == "__main__":
    
    packet_queue = multiprocessing.Queue()
    stop_event = multiprocessing.Event()
    
    sniffer_proc = multiprocessing.Process(target=packet_sniffer_process, args=(packet_queue, stop_event))
    sniffer_proc.start()
    
    try:
        while True:
            try:
                packet = packet_queue.get(timeout=5.0) 
                print(f"--> Pacchetto ricevuto nel processo principale: {packet}")
            except multiprocessing.queues.Empty:
                
                if not sniffer_proc.is_alive():
                    print("Il processo sniffer non è più attivo.")
                    break
                print("In attesa di pacchetti...")
                
    except KeyboardInterrupt:
        print("\nInterruzione richiesta. Invio segnale di stop...")
        stop_event.set()
        sniffer_proc.join(timeout=5) 
        if sniffer_proc.is_alive():
            print("Il processo sniffer non è terminato correttamente, forzo la chiusura.")
            sniffer_proc.terminate()
        print("Script terminato.")
