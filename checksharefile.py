import socket
from impacket.smbconnection import SMBConnection
import logging
import click
import configparser
import smtplib
import time
import sys
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logging.basicConfig(filename="scan.log", level=logging.INFO, 
                    format="%(asctime)s - %(levelname)s - %(message)s")

config = configparser.ConfigParser()
config.read("config.ini")

USERNAME = config.get("credentials", "username")
PASSWORD = config.get("credentials", "password")
IP_LIST_FILE = config.get("paths", "ip_list_file")
OUTPUT_FILE = config.get("paths", "output_file")
ALERT_EMAIL = config.get("email", "alert_email")
SMTP_SERVER = config.get("email", "smtp_server")
SMTP_PORT = config.get("email", "smtp_port")
SMTP_USER = config.get("email", "smtp_user")
SMTP_PASSWORD = config.get("email", "smtp_password")

def get_hostname(ip):
    """Resolve the hostname of a given IP address."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Hostname not found"

def list_all_smb_shares(ip, username, password):
    try:
        smb = SMBConnection(ip, ip)
        smb.login(username, password)
        shares = smb.listShares()
        public_shares = []
        
        for share in shares:
            share_name = share['shi1_netname'].rstrip('\x00').strip()
            if share['shi1_type'] == 0:  # Type 0 indicates disk directory
                public_shares.append(share_name)
        
        return public_shares if public_shares else ["No public shares found"]
    except Exception as e:
        logging.error(f"Error listing SMB shares for {ip}: {e}")
        return [f"Error: {str(e)}"]

def send_email_alert(subject, message, email):
    """Send an alert email using smtplib."""
    try:
        msg = MIMEMultipart()
        msg["From"] = SMTP_USER
        msg["To"] = email
        msg["Subject"] = subject
        msg.attach(MIMEText(message, "plain"))

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_USER, email, msg.as_string())

        logging.info(f"Alert email sent to {email}.")
    except Exception as e:
        logging.error(f"Failed to send email alert: {e}")

def check_alert(ip, hostname, shares):
    """Check for public shares and send an alert if found."""
    if shares and "No public shares found" not in shares:
        alert_message = f"ALERT: Public SMB shares detected for {ip} ({hostname}): {shares}"
        logging.warning(alert_message)
        print(alert_message)
        send_email_alert("SMB Share Alert", alert_message, ALERT_EMAIL)

@click.command(help="A tool to scan SMB public shares and send email alerts if public shares are detected.")
@click.option("-la", "--list-all", is_flag=True, help="List all SMB public shares from the IP list.")
@click.option("-e", "--email-alert", is_flag=True, help="Send email alerts for detected public shares.")
@click.option("-t", "--interval-time", type=int, default=None, help="Set the interval time in seconds to run the scan automatically.")
def main(list_all, email_alert, interval_time):
    """Main function to list and check SMB shares."""
    def scan_and_alert():
        with open(IP_LIST_FILE, "r") as ip_file:
            ip_addresses = [line.strip() for line in ip_file.readlines()]

        with open(OUTPUT_FILE, "w", encoding="utf-8") as output_file:
            for ip in ip_addresses:
                hostname = get_hostname(ip)
                shares = list_all_smb_shares(ip, USERNAME, PASSWORD)
                output_file.write(f"{ip} - {hostname} - SMB Shares: {shares}\n")

                if email_alert:
                    check_alert(ip, hostname, shares)

        logging.info("SMB share scan completed.")
        print(f"Results have been written to {OUTPUT_FILE}")

    if interval_time:
        # Loop to automatically scan at the given interval
        while True:
            scan_and_alert()
            print(f"Waiting {interval_time} seconds to next scan...")
            time.sleep(interval_time)  # Wait before next scan
    else:
        scan_and_alert()  # Run the scan once if no interval is specified

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScan stopped by user.")
        sys.exit(0)