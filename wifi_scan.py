import logging
import json
import time
import subprocess
import re
import os
from plyer import notification
import smtplib
from email.mime.text import MIMEText

header = """
 __      __.______________.___  ___________________            ___________
/  \\    /  \\   \\_   _____/|   |/   _____/\\______   \\____   ____\\_   _____/
\\   \\/\\/   /   ||    __)  |   |\\_____  \\  |     ___/  _ \\ /  _ \\|    __)  
 \\        /|   ||     \\   |   |/        \\ |    |  (  <_> |  <_> )     \\   
  \\__/\\  / |___|\\___  /   |___/_______  / |____|   \\____/ \\____/\\___  /   
       \\/           \\/                \\/                            \\/   
       
Tool: WIFI Scan
Version: 1.1
author : PSYKO
"""

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

# Function to print the header
def print_header():
    print(header)

# Constants
CONFIG_FILE = 'config.json'
DEFAULT_CONFIG = {
    'scan_interval': 5,
    'trusted_networks': {},
    'blacklist': []
}
INTERFACE = 'wlan0'

# Initialize logging
logging.basicConfig(filename='wifi_monitor.log', level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Load configuration from JSON file
def load_config():
    try:
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
    except FileNotFoundError:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(DEFAULT_CONFIG, f, indent=4)
        config = DEFAULT_CONFIG
    return config

# Save configuration to JSON file
def save_config(config):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)

# Function to scan Wi-Fi networks using iwlist and parse the results
def scan_wifi_networks(interface):
    networks = []

    try:
        output = subprocess.check_output(['sudo', 'iwlist', interface, 'scan'], universal_newlines=True)

        bssid_list = re.findall(r'Address: ([\w:]+)', output)

        for bssid in bssid_list:
            network = {
                'BSSID': bssid
            }

            # Find the SSID corresponding to this BSSID
            ssid_match = re.search(r'Address: ' + bssid + r'.*?ESSID:"(.*?)"', output, re.DOTALL)
            if ssid_match:
                network['ESSID'] = ssid_match.group(1)
            else:
                network['ESSID'] = "Hidden Network"

            # Find the channel
            channel_match = re.search(r'Address: ' + bssid + r'.*?Channel:(\d+)', output, re.DOTALL)
            if channel_match:
                network['Channel'] = channel_match.group(1)

            # Find the quality and signal level
            quality_match = re.search(r'Address: ' + bssid + r'.*?Quality=(\d+)/(\d+).*?Signal level=(-?\d+) dBm', output, re.DOTALL)
            if quality_match:
                network['Quality'] = quality_match.group(1) + '/' + quality_match.group(2)
                network['Signal Level'] = quality_match.group(3)

            # Find the encryption type
            encryption_match = re.search(r'Address: ' + bssid + r'.*?(WPA[2]?|WEP)', output, re.DOTALL)
            if encryption_match:
                encryption_type = encryption_match.group(1)
                if encryption_type == "WPA" or encryption_type == "WPA2":
                    network['Encryption'] = encryption_type
                elif encryption_type == "WEP":
                    network['Encryption'] = encryption_type
                else:
                    network['Encryption'] = "Other"
            else:
                network['Encryption'] = 'None'

            networks.append(network)

        return networks

    except subprocess.CalledProcessError as e:
        logging.error(f"Error while scanning with iwlist: {e.stderr}")
        return networks

# Function to display available Wi-Fi networks
def display_available_networks(networks):
    print("\nAvailable Wi-Fi Networks:")
    print("{:<30}  {:<20}  {:<10}  {:<10}  {:<15}  {:<15}".format(
        "ESSID", "BSSID", "Channel", "Quality", "Signal Level", "Encryption"))
    for network in networks:
        print("{:<30}  {:<20}  {:<10}  {:<10}  {:<15}  {:<15}".format(
            network.get('ESSID', ''),
            network.get('BSSID', ''),
            network.get('Channel', ''),
            network.get('Quality', ''),
            network.get('Signal Level', ''),
            network.get('Encryption', '')))

# Function for continuous network monitoring
def monitor_networks():
    print("Starting Wi-Fi network monitoring...")
    config = load_config()
    scan_interval = config.get('scan_interval', 5)
    previous_networks = []
    while True:
        networks = scan_wifi_networks(INTERFACE)
        display_available_networks(networks)
        log_signal_strength(networks, config['trusted_networks'])
        log_networks_data(networks)
        
        fraudulent_networks = detect_advanced_fraudulent_networks(networks, config['trusted_networks'], previous_networks)
        for fn in fraudulent_networks:
            send_notification(fn['ESSID'], fn['BSSID'], fn['Signal Level'], fn['Encryption'])
            send_fraudulent_network_email(fn['ESSID'], fn['BSSID'], fn['Signal Level'], fn['Encryption'])

        blacklisted_networks = detect_blacklisted_networks(networks, config.get('blacklist', []))
        for bn in blacklisted_networks:
            send_notification(bn['ESSID'], bn['BSSID'], bn['Signal Level'], bn['Encryption'])
            send_fraudulent_network_email(bn['ESSID'], bn['BSSID'], bn['Signal Level'], bn['Encryption'])

        previous_networks = networks
        time.sleep(scan_interval)

# Log signal strength of trusted networks over time
def log_signal_strength(networks, trusted_networks):
    with open('signal_strength.log', 'a') as f:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        for network in networks:
            ssid = network.get('ESSID', '')
            bssid = network.get('BSSID', '')
            signal = network.get('Signal Level', '')
            if ssid in trusted_networks and bssid == trusted_networks[ssid]:
                f.write(f"{timestamp}, {ssid}, {bssid}, {signal} dBm\n")
                logging.info(f"Signal strength logged for SSID: {ssid}, BSSID: {bssid}, Signal: {signal} dBm")

# Function to send email notifications
def send_email_notification(subject, message, to_email):
    from_email = "your_email@example.com"
    password = "your_password"

    msg = MIMEText(message)
    msg['Subject'] = subject
    msg['From'] = from_email
    msg['To'] = to_email

    try:
        server = smtplib.SMTP_SSL('smtp.example.com', 465)
        server.login(from_email, password)
        server.sendmail(from_email, to_email, msg.as_string())
        server.quit()
        logging.info(f"Email notification sent to {to_email}")
    except Exception as e:
        logging.error(f"Failed to send email: {e}")

def send_fraudulent_network_email(ssid, bssid, signal, encryption):
    subject = "Fraudulent Wi-Fi Network Detected"
    message = f"SSID: {ssid}, BSSID: {bssid}, Signal: {signal} dBm, Encryption: {encryption}"
    to_email = "recipient@example.com"
    send_email_notification(subject, message, to_email)

# Log all detected networks and their details
def log_networks_data(networks):
    with open('networks_data.log', 'a') as f:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        for network in networks:
            ssid = network.get('ESSID', '')
            bssid = network.get('BSSID', '')
            channel = network.get('Channel', '')
            quality = network.get('Quality', '')
            signal = network.get('Signal Level', '')
            encryption = network.get('Encryption', '')
            f.write(f"{timestamp}, {ssid}, {bssid}, {channel}, {quality}, {signal} dBm, {encryption}\n")
            logging.info(f"Network data logged for SSID: {ssid}, BSSID: {bssid}")

# Enhanced detection of fraudulent networks
def detect_advanced_fraudulent_networks(networks, trusted_networks, previous_networks):
    fraudulent_networks = []
    for network in networks:
        ssid = network.get('ESSID', '')
        bssid = network.get('BSSID', '')
        encryption = network.get('Encryption', '')
        signal = network.get('Signal Level', '')

        # Check if the network is a trusted network
        if ssid in trusted_networks and bssid == trusted_networks[ssid]:
            continue

        # Check if encryption is None or weak
        if encryption == "None" or encryption == "WEP":
            fraudulent_networks.append(network)
            continue

        # Check if signal strength decreased significantly
        previous_signal = next((n['Signal Level'] for n in previous_networks if n['BSSID'] == bssid), None)
        if previous_signal is not None:
            if int(signal) <= int(previous_signal) - 10:  # Adjust threshold as needed (e.g., 10 dBm difference)
                fraudulent_networks.append(network)

    return fraudulent_networks

# Detect networks in blacklist
def detect_blacklisted_networks(networks, blacklist):
    blacklisted_networks = []
    for network in networks:
        bssid = network.get('BSSID', '')
        if bssid in blacklist:
            blacklisted_networks.append(network)

    return blacklisted_networks

# Add a network to the blacklist
def add_to_blacklist(bssid):
    config = load_config()
    if 'blacklist' not in config:
        config['blacklist'] = []
    config['blacklist'].append(bssid)
    save_config(config)
    logging.info(f"Network added to blacklist: BSSID: {bssid}")

# Remove a network from the blacklist
def remove_from_blacklist(bssid):
    config = load_config()
    if 'blacklist' in config and bssid in config['blacklist']:
        config['blacklist'].remove(bssid)
        save_config(config)
        logging.info(f"Network removed from blacklist: BSSID: {bssid}")

# Manage the blacklist of networks
def manage_blacklist():
    while True:
        print("\nManage Network Blacklist")
        print("1. Add a network to the blacklist")
        print("2. Remove a network from the blacklist")
        print("3. View the blacklist")
        print("4. Back")
        choice = input("Choose an option: ")
        if choice == '1':
            bssid = input("Enter the BSSID of the network to add to the blacklist: ")
            add_to_blacklist(bssid)
        elif choice == '2':
            bssid = input("Enter the BSSID of the network to remove from the blacklist: ")
            remove_from_blacklist(bssid)
        elif choice == '3':
            config = load_config()
            print("Networks in the Blacklist:")
            for bssid in config.get('blacklist', []):
                print(bssid)
        elif choice == '4':
            break
        else:
            print("Invalid choice. Please choose again.")

# Main function
if __name__ == "__main__":
    print_header()
    while True:
        print("\nMain Menu")
        print("1. Start Wi-Fi Network Monitoring")
        print("2. Manage Network Blacklist")
        print("3. Exit")
        choice = input("Choose an option: ")
        if choice == '1':
            monitor_networks()
        elif choice == '2':
            manage_blacklist()
        elif choice == '3':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please choose again.")
