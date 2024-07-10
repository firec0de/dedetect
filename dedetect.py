from scapy.layers.dot11 import Dot11
from scapy.sendrecv import sniff
import requests
from time import time,strftime, gmtime
# Define the wait time before sending the Telegram notification for Detected Packets.
wait_time =3   # seconds
time_now = strftime("%H:%M:%S on %d/%m/%Y", gmtime())

def notify(message):
    TOKEN = "******" # telegram API 
    chat_id = "****" # telegram channel id 
    url = f"https://api.telegram.org/bot{TOKEN}/sendMessage?chat_id={chat_id}&text={message}"
    if requests.get(url).status_code == 200:
        print("-Notified")  # this sends the message
    else:
        print("- Failed to notify")  # this sends an error message
        print(requests.get(url).text)

def parse_packet(packet):
    if packet.haslayer(Dot11):
        ap_mac = packet.addr2
        if packet.type == 0 and (packet.subtype == 0x0a or packet.subtype == 0x0c):
            print(f"!!! Deauth/Disassoc DETECTED: {ap_mac} at {time_now}!!!\n-------------------------------------------------------------")
            # Notify Telegram of the Detected Deauth/Disassoc
            notify(f"!!! Deauth/Disassoc DETECTED: {ap_mac} at {time_now}")
            time.sleep(wait_time)  # wait before sending the next notification

notify(f"Started Monitoring Connected Network at {time_now}")
print("DEAUTHENTICATION & DISASSOCIATION FRAME DETECTION")
print("Started Monitoring Connected Network 100%|===========|")
print("=================== Ready =====================")

sniff(iface="wlan0", monitor=True, prn=parse_packet, filter="link[0] == 0xc0 or link[0] == 0xa0")
