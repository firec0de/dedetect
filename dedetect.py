import hashlib
import socket
import sys
import threading
import time
from datetime import datetime, timezone, timedelta

import requests
from scapy.layers.dot11 import *
from scapy.sendrecv import sniff

# Author: firec0de
# Install required libraries by running: pip install -r requirements.txt
# Usage without notification: sudo python dedetect.py <interface>
# Usage with telegram notification: sudo python dedetect.py <interface> <chat_id> <token>

host = socket.gethostname()  # hostname of the machine
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    # finds the local interface
    s.connect(("8.8.8.8", 80))
    host_ip = s.getsockname()[0]  # local IP address
finally:
    s.close()

# Capture command-line arguments
if len(sys.argv) < 2:
    print("At least the interface argument is required")
    print("Usage 1: sudo python dedetect.py <interface_name>")
    print("Usage 2: sudo python dedetect.py <interface_name> <chat_id> <token>")
    sys.exit(1)

try:
    interface = str(sys.argv[1])  # Wireless interface name ex wlan0 etc.

    if not interface:
        raise ValueError("Interface cannot be empty.")

    # Check if additional arguments are provided (chat_id and TOKEN)
    if len(sys.argv) == 4:
        chat_id = str('-'+sys.argv[2])  # Telegram channel ID
        TOKEN = str(sys.argv[3])  # Telegram Bot API Token

        if not chat_id:
            raise ValueError("Chat ID cannot be empty.")
        if not TOKEN:
            raise ValueError("TOKEN cannot be empty.")
        enable_notifications = True
    else:
        enable_notifications = False

except ValueError as ve:
    print(f"ValueError: {ve}")
    sys.exit(1)
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)

# Define the wait time before sending the Telegram notification.
wait_time = 2  # in seconds

def time_now():
    return (datetime.now(timezone.utc) + timedelta(hours=2)).strftime('%H:%M:%S on %d/%m/%Y')


def notify(message):  # send a notification to Telegram
    if enable_notifications:
        url = f"https://api.telegram.org/bot{TOKEN}/sendMessage?chat_id={chat_id}&text={message}"  # Telegram API URL
        try:
            response = requests.get(url)
            if response.status_code == 200:
                print("- Notified")
        except Exception as e:
            print(f"- Failed to notify: {e}")
        time.sleep(wait_time)  # wait before sending the next notification
    else:
        print("- Telegram Notifications are disabled.")

def parse(frame):
    if frame.haslayer(Dot11) and frame.type == 0 and frame.subtype == 8:
        try:
            channel = int(ord(frame[Dot11Elt:3].info))
            if frame.haslayer(Dot11EltCountry):
                country = (frame[Dot11EltCountry].country_string).decode('utf-8')
            else:
                country = 0
            erates = frame[Dot11EltRates].info
            if frame.haslayer(Dot11EltCountryConstraintTriplet):
                power = frame[Dot11EltCountryConstraintTriplet].mtp
            else:
                power = 0
            if frame.haslayer(Dot11Beacon):
                cap = frame[Dot11Beacon].cap
            else:
                cap = 0
            if frame.haslayer(Dot11EltHTCapabilities):
                htmax = frame[Dot11EltHTCapabilities].Max_A_MSDU
                ht = frame[Dot11EltHTCapabilities].summary
            else:
                htmax = 0
                ht = 0
            if frame.haslayer(Dot11EltVendorSpecific):
                try:
                    vendor = frame[Dot11EltVendorSpecific:2].oui
                except:
                    vendor = 0
            else:
                vendor = 0

            all = frame.addr3 + str(frame.info) + str(channel) + str(country) + str(vendor) + str(frame.rates) + str(
                erates) + str(power) + str(cap) + str(htmax) + str(vendor)
            details = (
                f"BSSID:{frame.addr3}\nSSID:{(frame.info).decode('utf-8')}\nChannel:{channel}\nCountry:{country}\nSupported Rates:{frame.rates}\nExtended Rates:{erates}\nMax Transmit Power:{power}\nCapabilities:{cap}\nMax_A_MSDU:{htmax}\nVendor:{vendor}\nSHA256:{hashlib.sha256(all.encode('utf-8')).hexdigest()}")

            airbasesig = str(country) + str(frame.rates) + str(erates) + str(power) + str(cap) + str(htmax) + str(
                vendor)
            if hashlib.sha256(airbasesig.encode(
                    'utf-8')).hexdigest() == "4c847490293ea0bf0cf2fe7ddb02703368aaf8e97ffb16455f0365a7497e2de2":
                print(f"****AIRBASE-NG DETECTED AT THIS ACCESS POINT ****\n{details}\n")
                notify(
                    f"**** AIRBASE-NG DETECTED AT THIS ACCESS POINT ****\n{details}\n----------------------------------------------------------------------------------\nOn {time_now()} at {host_ip}")  # send the notification

        except Exception as e:
            notify(f"Error parsing frame: {e}")
            print(f"Error parsing frame: {e}")


def parse_packet(packet):  # parse the packet to get the AP MAC address and send a notification if Detected Deauth
    if packet.haslayer(Dot11):  # check if the packet contains a Dot11 layer
        try:
            ap_mac = packet.addr2  # get the AP MAC address from the packet
            if packet.type == 0 and (
                    packet.subtype == 0x0a or packet.subtype == 0x0c):  # check if the packet is a Deauth/Disassoc
                print(
                    f"**** Deauth/Disassoc DETECTED **** \n{ap_mac} on {time_now()} at {host_ip}.\n----------------------------------------------------------------------------------")  # print the detected Deauth/Disassoc message
                notify(
                    f"**** Deauth/Disassoc DETECTED ****\n{ap_mac} on {time_now()} at {host_ip}.")  # send the notification
        except Exception as e:
            notify(f"Error parsing packet: {e}")
            print(f"Error parsing packet: {e}")


def start_sniffers():
    thread1 = threading.Thread(target=sniff,
                               kwargs={"iface": interface, "prn": parse, "filter": "wlan type mgt subtype beacon"})
    thread2 = threading.Thread(target=sniff, kwargs={"iface": interface, "prn": parse_packet,
                                                     "filter": "wlan type mgt subtype deauth or wlan type mgt subtype disassoc"})

    thread1.start()
    thread2.start()
    thread1.join()
    thread2.join()


# Start the sniffers and monitor the network for Deauth/Disassoc and Fake/Rogue APs
if __name__ == "__main__":
    print("DeDetect a Deauth/Disassoc + Fake/Rogue AP Detection with Telegram Notifications")
    print(f"Inspired by the tool snappy by spiderlabs at: https://github.com/SpiderLabs/snap.py\nAuthor: firec0de\n\n")
    notify(f"Started Monitoring Connected Network on {time_now()} at {host_ip} user {host}.")
    print(
        f"Started Monitoring Connected Network on {time_now()} at {host_ip} user {host}.\n----------------------------------------------------------------------------------")
    start_sniffers()
