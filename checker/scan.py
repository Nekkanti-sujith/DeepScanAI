import nmap
import pandas as pd
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import socket
import os
from sklearn.ensemble import IsolationForest

# Function to get the local IP address dynamically
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip_address = s.getsockname()[0]
        s.close()
        return ip_address
    except Exception as e:
        return f"Error getting local IP: {e}"

# Function to send email
def send_email(subject, body, to_email):
    try:
        from_email = "your_email@gmail.com"
        password = "your_email_password"  # Use app-specific password if using Gmail with 2FA

        msg = MIMEMultipart()
        msg['From'] = from_email
        msg['To'] = to_email
        msg['Subject'] = subject

        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(from_email, password)
        text = msg.as_string()
        server.sendmail(from_email, to_email, text)
        server.quit()

        print("✅ Email sent successfully!")
    except Exception as e:
        print(f"❌ Failed to send email: {e}")

# Function to scan the network
def scan_network(network_range="192.168.1.0/24"):
    scanner = nmap.PortScanner()
    print(f"🔍 Scanning {network_range}...")
    scanner.scan(hosts=network_range, arguments='-O -sS')  # -O for OS detection, -sS for SYN scan

    devices = []
    for host in scanner.all_hosts():
        if scanner[host].state() == "up":
            os_match = scanner[host].get('osmatch', [])
            os = os_match[0]['name'] if os_match else "Unknown OS"
            device_info = {
                "IP": host,
                "MAC": scanner[host]['addresses'].get('mac', 'Unknown'),
                "OS": os,
                "Open_Ports": list(scanner[host].get('tcp', {}).keys()),
                "Vulnerabilities": 0,  # Placeholder, could be enhanced with CVE data
                "Anomaly": "Normal",  # Placeholder for anomaly detection
            }
            devices.append(device_info)
    
    return devices

# Function to process scan results and log anomalies using both rule-based and AI detection
def process_scan_results(devices):
    if not devices:
        print("❌ No devices found. Skipping anomaly detection.")
        return devices

    df = pd.DataFrame(devices)

    # Convert categorical data to numerical
    df['OS'] = df['OS'].astype('category').cat.codes  # Encode OS names to numerical values
    df['Num_Open_Ports'] = df['Open_Ports'].apply(len)  # Count number of open ports

    # Rule-Based Anomaly Detection (Legacy)
    df['Rule_Based_Anomaly'] = df['Num_Open_Ports'].apply(lambda x: '⚠️ Suspicious' if x > 3 else '✅ Normal')

    # AI-Based Anomaly Detection (Isolation Forest)
    features = df[['OS', 'Num_Open_Ports']].values
    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(features)
    
    df['AI_Anomaly'] = model.predict(features)
    df['AI_Anomaly'] = df['AI_Anomaly'].map({1: '✅ Normal', -1: '⚠️ Suspicious'})

    # Save results
    log_file = 'network_scan_results_ai.csv'
    df.to_csv(log_file, index=False)

    print(f"📜 Scan results logged in '{log_file}'")
    print(df[['IP', 'OS', 'Num_Open_Ports', 'Rule_Based_Anomaly', 'AI_Anomaly']])

    return df.to_dict(orient='records')

# Function to execute the scan and process results
def main():
    local_ip = get_local_ip()
    print(f"🌐 Your Local IP: {local_ip}")

    network_range = ".".join(local_ip.split(".")[:3]) + ".0/24"  # Dynamically set network range
    print(f"🔍 Scanning Network Range: {network_range}")

    devices = scan_network(network_range)
    
    if devices:
        processed_results = process_scan_results(devices)

        # Send email with the scan results (optional)
        email_subject = f"Network Scan Report: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        email_body = f"Here are the results of the network scan:\n\n{pd.DataFrame(processed_results).to_string(index=False)}"
        recipient_email = "recipient_email@example.com"
        send_email(email_subject, email_body, recipient_email)
    else:
        print("❌ No devices found during the scan.")

if __name__ == "__main__":
    main()
