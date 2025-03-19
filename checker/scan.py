import nmap
from tqdm import tqdm  # Progress bar library

def scan_network(network_range):
    """Scan the local network for active devices and detect device types, open ports, and vulnerabilities."""
    nm = nmap.PortScanner()
    print(f"Scanning {network_range}... (This may take a while)")

    # Perform the network scan (with OS detection and additional detailed scans)
    nm.scan(hosts=network_range, arguments='-O -sV --script=vuln')  # OS detection, version detection, and vulnerability scripts
    print("Scan completed.")

    devices = []

    # Show progress while processing the results
    for host in tqdm(nm.all_hosts(), desc="Processing Hosts", bar_format="{l_bar}{bar} [Time: {elapsed}]"):
        # Get OS information (if available)
        os_info = nm[host].get('osmatch', [])
        os_name = os_info[0]['name'] if os_info else "Unknown"

        # Get MAC and vendor (if available)
        mac_address = nm[host]['addresses'].get('mac', 'Unknown')
        vendor = nm[host].get('vendor', 'Unknown')

        # Check for open ports
        open_ports = []
        vulnerabilities_found = False

        if 'tcp' in nm[host]:
            for port in nm[host]['tcp']:
                if nm[host]['tcp'][port]['state'] == 'open':
                    open_ports.append(port)
                    # Check for vulnerabilities using the nmap vuln script
                    if 'script' in nm[host]['tcp'][port]:
                        for script in nm[host]['tcp'][port]['script']:
                            if 'vuln' in script.lower():
                                vulnerabilities_found = True

        # Store device details in the list
        device_info = {
            'IP': host,
            'MAC': mac_address,
            'OS': os_name,
            'Vendor': vendor,
            'Open Ports': open_ports,
            'Vulnerabilities': vulnerabilities_found
        }
        devices.append(device_info)

    return devices

# Define the network range (you can customize this)
network_range = "10.0.0.0/24"  # Adjust based on your local network

# Scan the network
devices = scan_network(network_range)

# Display results
if devices:
    print("\nActive Devices Found:")
    for device in devices:
        vulnerabilities_msg = "Vulnerabilities found" if device['Vulnerabilities'] else "No vulnerabilities found"
        print(f"Device: {device['IP']} | MAC: {device['MAC']} | OS: {device['OS']} | Vendor: {device['Vendor']} | Open Ports: {device['Open Ports']} | {vulnerabilities_msg}")
else:
    print("No active devices found.") 