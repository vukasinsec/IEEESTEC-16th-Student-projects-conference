import paramiko
from netmiko import ConnectHandler
import re
from collections import deque
import keyboard
import os
import getpass

import networkx as nx
import matplotlib.pyplot as plt

def gather_device_info(device_ip, username, password, enable_password):
    # Parametri za SSH konekciju
    ssh_params = {
        'device_type': 'cisco_ios',
        'ip': device_ip,
        'username': username,
        'password': password,
        'secret' : enable_password
    }

    try:
        # Konekcija preko SSH-a
        ssh_session = ConnectHandler(**ssh_params)

        # Izvršavanje komande "show cdp neighbors detail"
        output = ssh_session.send_command('show cdp neighbors detail')

        ssh_session.enable()

        shrun = ssh_session.send_command('show running-config')

        # Zatvaranje SSH sesije
        ssh_session.disconnect()

        return output,shrun


    except Exception as e:
        print(f"Greška pri povezivanju ili izvršavanju komande na uređaju {device_ip}: {str(e)}")

def extract_hostname(config_str):
    # Definiramo uzorak za pretragu hostname-a
    hostname_pattern = r'hostname (\w+)'

    # Tražimo uzorak u konfiguracijskom stringu
    match = re.search(hostname_pattern, config_str)

    if match:
        # Ako pronađemo podudaranje, vraćamo prvi grupirani podatak
        return match.group(1)
    else:
        # Ako ne pronađemo hostname, vraćamo None ili bilo koji drugi odgovarajući rezultat
        return None

def bfs_network_scan(start_device_ip, username, password,privileged_mode):

    output = []
    konf = []
    #
    # cdpNames = []
    # cdpInterfaces = []
    # cdpOutgoingPorts = []
    # cdpAdresses = []

    edges = []
    nodes = []
    ips = {}

    visited = set()  # Skup za praćenje već posetjenih uređaja
    queue = deque()  # Red za BFS pretragu

    # Početni uređaj
    start_device = {"ip": start_device_ip, "username": username, "password": password}
    queue.append(start_device)

    # i = -1
    while queue:
        current_device = queue.popleft()

        x, y = gather_device_info(current_device["ip"], current_device["username"], current_device["password"],privileged_mode)

        hostname_current_device = extract_hostname(y)

        if hostname_current_device not in visited:


            # Skeniraj uređaj i pokupi rezultate
            cdp_output, shrun = gather_device_info(current_device["ip"], current_device["username"], current_device["password"],privileged_mode)

            cdpNames = extract_device_name(cdp_output)
            cdpInterfaces = extract_interface(cdp_output)
            cdpOutgoingPorts = extract_outgoing_port(cdp_output)
            cdpAdresses = extract_ip_address(cdp_output)

            nodes.append(hostname_current_device)
            ips[hostname_current_device] = current_device["ip"]
            for target in cdpNames:
                edges.append((hostname_current_device,target))

            # if len(cdpAdresses) == 0:
            #     cdpAdresses = extract_ip_addresses2(cdp_output)

            # konf.append(f'Za uredjaj na ip adresi {current_device["ip"]} ovo je sh run naredba:')
            konf.append(shrun)

            output.append(f'Uredjaj ciji je hostname "{hostname_current_device}" i ip adresa "{current_device["ip"]}" je: ')
            for i in range(len(cdpAdresses)):
                output.append(f'Povezan preko interfejsa "{cdpInterfaces[i]}" sa uredjajem ciji je hostname "{cdpNames[i]}".')

            # Označi trenutni uređaj kao posetjen
            visited.add(hostname_current_device)

            # Dodaj sve pronađene uređaje u red za dalje skeniranje
            new_devices = parse_cdp_output_and_get_neighbors(cdp_output)

            # connectedDevices = extractInfo(new_devices)

            # info = f'Uredjaj {current_device["ip"]} je konektovan preko {new_devices} '

            # output[current_device["ip"]] = new_devices

            nove_ip_adrese = find_ip_addresses(new_devices)

            for i in range(len(cdpNames)):
                if cdpNames[i] not in visited:
                    uredjaj = {"ip": nove_ip_adrese[i], "username": username, "password": password}
                    queue.append(uredjaj)

    return output,konf,nodes,edges,ips


import re

# Funkcija za izdvajanje IP adrese
def extract_ip_address(text):
    ip_addresses = re.findall(r'Entry address\(es\):\s+IP address: (\d+\.\d+\.\d+\.\d+)', text)
    return ip_addresses
def extract_ip_addresses2(text):
    ip_addresses = []
    entries = re.finditer(r'IP address\s*:\s*(\d+\.\d+\.\d+\.\d+)', text)
    for entry in entries:
        ip_addresses.append(entry.group(1))
    return ip_addresses

# Funkcija za izdvajanje interfejsa
def extract_interface(text):
    interfaces = re.findall(r'Interface: ([\w/]+)', text)
    return interfaces

# Funkcija za izdvajanje outgoing porta
def extract_outgoing_port(text):
    outgoing_ports = re.findall(r'Port ID \(outgoing port\): ([\w/]+)', text)
    return outgoing_ports

# Funkcija za izdvajanje naziva uređaja (Device ID)
def extract_device_name(text):
    device_names = re.findall(r'Device ID: (\w+)', text)
    # device_names.split('.')[0]
    return device_names

def find_ip_addresses(data):
    found_ips = []  # Lista za čuvanje pronađenih IP adresa

    # Iteriramo kroz sve setove unutar liste
    for data_set in data:
        for element in data_set:
            if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', element):
                found_ips.append(element)  # Dodamo pronađenu IP adresu u listu

    return found_ips

def parse_cdp_output_and_get_neighbors(output):
    # Ovde treba napisati logiku za parsiranje rezultata "show cdp neighbors detail"
    # i dobijanje informacija o susednim uređajima (IP adrese, interfejsi, itd.)
    # Rezultate treba vratiti kao listu uređaja za dalje skeniranje
    pattern = r"Device ID: (\w+).*?IP address: ([0-9.]+).*?Interface: ([\w/]+).*?Port ID \(outgoing port\): ([\w/]+)"

    matches = re.finditer(pattern, output, re.DOTALL)

    devices = []  # Lista za čuvanje informacija o uređajima

    for match in matches:
        device_id, ip_address, interface, port_id = match.groups()
        device_info = {
            device_id,
            ip_address,
            interface,
            port_id
        }
        devices.append(device_info)

    return devices

def write_to_file(text,filename):
    with open(filename,"w") as file:
        for t in text:
            file.write(t + "\n")


def get_default_gateway():
    try:
        output = os.popen("route print").read()
        gateway_pattern = r"0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)\s+"
        match = re.search(gateway_pattern, output)
        if match:
            return match.group(1)
    except Exception as e:
        print(f"Greška: {e}")
    return None


def draw_custom_graph(nodes, edges, ip_addresses=None):
    G = nx.DiGraph()
    G.add_edges_from(edges)
    red_edges = []
    # Stvaranje liste oznaka za svaki čvor sa imenom i opcionalno IP adresom
    node_labels = {}
    for node in nodes:
        label = node
        if ip_addresses and node in ip_addresses:
            label += f'\n{ip_addresses[node]}'
        node_labels[node] = label

    # Određivanje boja grana
    edge_colours = ['black' if not red_edges or edge not in red_edges else 'red' for edge in G.edges()]

    # Podešavanje pozicija čvorova
    pos = nx.spring_layout(G)

    # Crta graf
    node_font = {'fontname': 'Arial', 'size': 12}
    nx.draw_networkx_nodes(G, pos, cmap=plt.get_cmap('jet'), node_color='lightblue', node_size=500)
    nx.draw_networkx_labels(G, pos, labels=node_labels, font_color='black', font_size=8, font_weight='bold',
                            font_family=node_font['fontname'])
    nx.draw_networkx_edges(G, pos, arrows=True, edge_color=edge_colours)

    plt.show()


if __name__ == "__main__":

    gateway = get_default_gateway()

    username = input("Unesite username koji je isti na svim uredjajima: ")
    password = input("Unesite password koji je isti na svim uredjajima: ")
    password_privileged_mode = input("Unesite password privileged moda: ")

    print(f"Pritisnite Enter ako zelite da pokrenete skriptu.. [{gateway}]")
    keyboard.wait("Enter")



    output,shrun,nodes,edges,ips = bfs_network_scan(gateway, username, password,password_privileged_mode)

    draw_custom_graph(nodes,edges,ips)

    write_to_file(shrun,"show_run.txt")


    print("\n")

    for i in range(len(output)):
        print(output[i])
        # print("\n")