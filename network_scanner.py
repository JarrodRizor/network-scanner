#!/usr/bin/env python

import scapy.all as scapy

# Scans network for ARP requests
# returns list of data found after scapy scans the network
def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    client_list = []
    for element in answered:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(client_dict)
    return client_list

# Print the output of the results gathered in the ARP scan
# Loop through the results and display the results in a table 
# (for IP address and Mac Address)
def print_result(results_list):
    print("IP\t\t\tMAC Address\n-------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])

scan_result = scan("192.168.1.67/24")
print_result(scan_result)