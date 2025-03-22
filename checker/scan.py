import nmap
import smtplib
import time
from tqdm import tqdm
from email.mime.text import MIMEText

# Email Configuration (Use a valid SMTP server)
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_SENDER = "" # add email here
EMAIL_PASSWORD = ""  # Use an App Password if using Gmail
EMAIL_RECEIVER = "" # add email here

# Function to send email alerts
def send_email_alert(device):
    subject = f"⚠️ Vulnerability Alert: {device['IP']} ⚠️"
    body = f"""
    A vulnerability has been detected on the following device:

    🔹 IP: {device['IP']}
    🔹 MAC: {device['MAC']}
    🔹 OS: {device['OS']}
    🔹 Vendor: {device['Vendor']}
    🔹 Open Ports: {device['Open Ports']}
    
    Immediate action is recommended. Stay secure! 🔒
    """
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = EMAIL_SENDER
    msg["To"] = EMAIL_RECEIVER

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_SENDER, EMAIL_PASSWORD)
        server.sendmail(EMAIL_SENDER, EMAIL_RECEIVER, msg.as_string())
        server.quit()
        print(f"📧 Email Alert Sent for {device['IP']}")
    except Exception as e:
        print(f"❌ Failed to send email: {e}")

# Function to scan network and detect vulnerabilities
def scan_network(network_range):
    nm = nmap.PortScanner()
    print(f"🔍 Scanning {network_range}... (This may take a while)")
    nm.scan(hosts=network_range, arguments='-O -sV --script=vuln')
    print("✅ Scan completed.")

    devices = []

    for host in tqdm(nm.all_hosts(), desc="Processing Hosts", bar_format="{l_bar}{bar} [Time: {elapsed}]"):
        os_info = nm[host].get('osmatch', [])
        os_name = os_info[0]['name'] if os_info else "Unknown"

        mac_address = nm[host]['addresses'].get('mac', 'Unknown')
        vendor = nm[host].get('vendor', 'Unknown')

        open_ports = []
        vulnerabilities_found = False

        if 'tcp' in nm[host]:
            for port in nm[host]['tcp']:
                if nm[host]['tcp'][port]['state'] == 'open':
                    open_ports.append(port)
                    if 'script' in nm[host]['tcp'][port]:
                        for script in nm[host]['tcp'][port]['script']:
                            if 'vuln' in script.lower():
                                vulnerabilities_found = True

        device_info = {
            'IP': host,
            'MAC': mac_address,
            'OS': os_name,
            'Vendor': vendor,
            'Open Ports': open_ports,
            'Vulnerabilities': vulnerabilities_found
        }
        devices.append(device_info)

        # Send an alert if a vulnerability is found
        if vulnerabilities_found:
            send_email_alert(device_info)
            log_vulnerability(device_info)

    return devices

# Function to log vulnerabilities to a file
def log_vulnerability(device):
    with open("vulnerability_log.txt", "a") as log_file:
        log_file.write(f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] ALERT - Vulnerability Found\n")
        log_file.write(f"IP: {device['IP']}, MAC: {device['MAC']}, OS: {device['OS']}, Vendor: {device['Vendor']}, Open Ports: {device['Open Ports']}\n")
    print(f"📜 Logged vulnerability for {device['IP']}")

# Define network range
network_range = "" #keep you ip address here  

# Run periodic scans every 30 minutes
while True:
    devices = scan_network(network_range)
    
    # Display results
    if devices:
        print("\n📡 Active Devices Found:")
        for device in devices:
            vulnerabilities_msg = "⚠️ Vulnerabilities found!" if device['Vulnerabilities'] else "✅ No vulnerabilities found"
            print(f"🔹 Device: {device['IP']} | MAC: {device['MAC']} | OS: {device['OS']} | Vendor: {device['Vendor']} | Open Ports: {device['Open Ports']} | {vulnerabilities_msg}")
    else:
        print("❌ No active devices found.")

    print("⏳ Waiting 30 minutes before the next scan...")
    time.sleep(1800)  # Wait 30 minutes before running again
