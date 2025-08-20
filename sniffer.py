import pyshark as pyshark
import requests
import time
import ipinfo
import socket
import netifaces
import ipaddress

########################################
## INSERT HERE YOUR NETWORK INTERFACE ##
########################################
interface = 'your_interface_name_here'


###################################
## INSERT HERE YOUR IPINFO TOKEN ##
###################################
token = 'your_ipinfo_token_here'


#setup ipinfo
handler = ipinfo.getHandler(token)

def get_netmask(interface):
    addrs = netifaces.ifaddresses(interface)
    if netifaces.AF_INET in addrs:
        return addrs[netifaces.AF_INET][0]['netmask']
    return None

def get_network_address(interface):
    addrs = netifaces.ifaddresses(interface)
    if netifaces.AF_INET in addrs:
        ip = addrs[netifaces.AF_INET][0]['addr']
        netmask = addrs[netifaces.AF_INET][0]['netmask']
        #print(f"IP Address: {ip}")
        #print(f"Subnet Mask: {netmask}")
        network = str(ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False))
        #print(f"Network Address: {network.network_address}")
        return network

def local_control(network_address_with_netmask, ip_1):
    network_address = network_address_with_netmask.split('/')[0]
    netmask = network_address_with_netmask.split('/')[1]
    num_equal_bit = 0

    separeted_ip_1 = ip_1.split('.')
    firt_oct_ip = f"{int(separeted_ip_1[0]):08b}"
    sec_oct_ip = f"{int(separeted_ip_1[1]):08b}"
    third_oct_ip = f"{int(separeted_ip_1[2]):08b}"
    fourth_oct_ip = f"{int(separeted_ip_1[3]):08b}"
    ip_1_bin = firt_oct_ip + sec_oct_ip + third_oct_ip + fourth_oct_ip

    separated_network_ip = network_address.split('.')
    firt_oct_ip = f"{int(separated_network_ip[0]):08b}"
    sec_oct_ip = f"{int(separated_network_ip[1]):08b}"
    third_oct_ip = f"{int(separated_network_ip[2]):08b}"
    fourth_oct_ip = f"{int(separated_network_ip[3]):08b}"
    network_ip_bin = firt_oct_ip + sec_oct_ip + third_oct_ip + fourth_oct_ip


    #control ip
    for i in range(int(netmask)):
        if ip_1_bin[i] == network_ip_bin[i]:
            num_equal_bit = num_equal_bit +1

    if num_equal_bit == int(netmask):
        return True
    else:
        return False
    
#my ip
hostname = socket.gethostname()
my_ip = socket.gethostbyname(hostname)
my_ip_details = handler.getDetails().all
separated_my_ip = my_ip.split('.')
network_address_with_netmask = get_network_address(interface)

def sniffer ():
    global my_ip
    global my_ip_details
    global network_address_with_netmask
    global handler

    capture = pyshark.LiveCapture(interface=interface)

    for packet in capture:
        
        if hasattr(packet, 'ip'):

            print(packet)

            from_me = False
            to_me = False
            is_local = False

            #setup ipinfo
            handler = ipinfo.getHandler(token)
            
            #packet transport protocol
            protocol = packet.transport_layer
            application = packet.highest_layer

            #source ip
            source_ip = packet.ip.src
           
            #destination ip
            dest_ip = packet.ip.dst

            # Gestione delle porte per protocolli con layer di trasporto
            if protocol is not None and protocol.upper() in ['TCP', 'UDP']:
                try:
                    source_port = packet[protocol].srcport
                    dest_port = packet[protocol].dstport
                except AttributeError:
                    # Fallback nel caso in cui srcport/dstport non siano disponibili
                    source_port = "N/A"
                    dest_port = "N/A"
            else:
                # Per protocolli come IGMP, ICMP, ecc. che non hanno porte
                source_port = "N/A"
                dest_port = "N/A"

            if local_control(network_address_with_netmask, source_ip) and local_control(network_address_with_netmask, dest_ip):
                is_local = True

            #IPINFO filter
            if not (source_ip=="34.117.59.81" or dest_ip=="34.117.59.81"):

                #packet source and destination location
                ip_loc_source = handler.getDetails(source_ip).all
                ip_loc_dest = handler.getDetails(dest_ip).all

                #length
                length = packet.length

                #country name and coordinate
                if 'country_name' in ip_loc_source:
                    source_country = ip_loc_source['country_name']
                    source_coordinate = [float(ip_loc_source['latitude']),float(ip_loc_source['longitude'])]
                else:
                    source_country = "None"
                    source_coordinate = "None"

                if 'country_name' in ip_loc_dest:
                    dest_country = ip_loc_dest['country_name']
                    dest_coordinate = [float(ip_loc_dest['latitude']),float(ip_loc_dest['longitude'])]
                else:
                    dest_country = "None"
                    dest_coordinate = "None"


                #print(f"My IP is: {my_ip}")
                

                #if source or destination are me
                #comunication with me but not in local network
                if source_ip == my_ip and not is_local and "bogon" not in ip_loc_dest:
                    source_country = my_ip_details['country_name']
                    source_coordinate = [my_ip_details['latitude'], my_ip_details['longitude']]
                    from_me = True

                    #server details
                    details = f"Server situato in {ip_loc_dest['region']}, {dest_country}({ip_loc_dest['city']})"
                    long_details = (f"Server proprietà di {ip_loc_dest['org']} situato in {ip_loc_dest['region']}, {dest_country}({ip_loc_dest['city']}): "+
                                f"{dest_coordinate[0]}, {dest_coordinate[1]} con fusorario {ip_loc_dest['timezone']} e moneta ufficiale del Paese {ip_loc_dest['country_currency']['symbol']}" 
                                )
                    server_name = ip_loc_dest['org']
                elif dest_ip == my_ip and not is_local and "bogon" not in ip_loc_source:
                    dest_country = my_ip_details['country_name']
                    dest_coordinate = [my_ip_details['latitude'],my_ip_details['longitude']]
                    to_me = True

                    #server details
                    details = f"Server situato in {ip_loc_source['region']}, {source_country}({ip_loc_source['city']})"
                    long_details = (f"Server proprietà di {ip_loc_source['org']} situato in {ip_loc_source['region']}, {source_country}({ip_loc_source['city']}): "+
                                f"{source_coordinate[0]}, {source_coordinate[1]} con fusorario {ip_loc_source['timezone']} e moneta ufficiale del Paese {ip_loc_source['country_currency']['symbol']}" 
                                )
                    server_name = ip_loc_source['org']
                else:
                    details = "None"
                    long_details = "None"
                    server_name = "None"

                #local comunication but not with me
                if is_local:
                    details = "Comunicazione locale"
                    long_details = f"Comunicazione locale tra {source_ip}:{source_port} e {dest_ip}:{dest_port}"
                    server_name = "Rete LAN"




                #all packet details
                received_paket_details =   {
                                            
                                            "source_ip": f"{source_ip}:{source_port}",
                                            "destination_ip": f"{dest_ip}:{dest_port}",
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
                                            "server_name": server_name,
                                            "is_local": is_local

                                            }

                return received_paket_details
            else:
                print("comunicazione con ipinfo")
                #return "ipinfo comunication"

if __name__ == "__main__":
    sniffer()
