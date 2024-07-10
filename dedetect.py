from scapy.layers.dot11 import *
import requests
from time import time, strftime, gmtime
from scapy.sendrecv import sniff
import hashlib
import threading
import time

# Define the wait time, API Token and Channel ID before sending the Telegram notification.

wait_time =1 # in seconds
TOKEN = "******************************" # Telegram Bot API Token
chat_id = "************" # Telegram channel ID

def notify(message):  # send a notification to Telegram
    url = f"https://api.telegram.org/bot{TOKEN}/sendMessage?chat_id={chat_id}&text={message}" # Telegram API URL
    try:
        response = requests.get(url)
        if response.status_code == 200:
            print("- Notified")
    except Exception as e:
        print(f"- Failed to notify: {e}")


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

            details =("BSSID:", frame.addr3,"\nSSID:", (frame.info).decode('utf-8'),"\nChannel:", channel,"\nCountry:", country,
                      "\nSupported Rates:", frame.rates, "\nExtended Rates:", erates,"\nMax Transmit Power:", power,
                      "\nCapabilities:", cap, "\nMax_A_MSDU:", htmax, "\nVendor:", vendor, "\nSHA256:", hashlib.sha256(all.encode('utf-8')).hexdigest())

            airbasesig = str(country) + str(frame.rates) + str(erates) + str(power) + str(cap) + str(htmax) + str(vendor)
            if hashlib.sha256(airbasesig.encode('utf-8')).hexdigest() == "4c847490293ea0bf0cf2fe7ddb02703368aaf8e97ffb16455f0365a7497e2de2":
                print(details)
                print("******** AIRBASE-NG DETECTED AT THIS ACCESS POINT ********\n")
                notify(f"!!! AIRBASE-NG DETECTED AT THIS ACCESS POINT: {details}at {strftime('%H:%M:%S on %d/%m/%Y', gmtime())}")# send the notification

        except Exception as e:
            notify(f"Error parsing frame: {e}")
            print(f"Error parsing frame: {e}")

def parse_packet(packet):  # parse the packet to get the AP MAC address and send a notification if Detected Deauth
    if packet.haslayer(Dot11): # check if the packet contains a Dot11 layer
        try:
            ap_mac = packet.addr2 # get the AP MAC address from the packet
            if packet.type == 0 and (packet.subtype == 0x0a or packet.subtype == 0x0c): # check if the packet is a Deauth/Disassoc
                time_now = strftime("%H:%M:%S on %d/%m/%Y", gmtime())
                print(f"!!! Deauth/Disassoc DETECTED: {ap_mac} at {time_now} !!!\n-------------------------------------------------------------")  # print the detected Deauth/Disassoc message
                notify(f"!!! Deauth/Disassoc DETECTED: {ap_mac} at {time_now}") # send the notification
                time.sleep(wait_time)  # wait before sending the next notification
        except Exception as e:
            notify(f"Error parsing packet: {e}")
            print(f"Error parsing packet: {e}")

def start_sniffers():
    thread1 = threading.Thread(target=sniff,
                               kwargs={"iface": "wlan0", "monitor": True,"prn": parse, "filter": "wlan type mgt subtype beacon"})
    thread2 = threading.Thread(target=sniff, kwargs={"iface": "wlan0", "monitor": True, "prn": parse_packet,
                                                     "filter": "wlan type mgt subtype deauth or wlan type mgt subtype disassoc"})

    thread1.start()
    thread2.start()
    thread1.join()
    thread2.join()

if __name__ == "__main__":
    print("DeDetect a Deauth/Disassoc + Fake/Rogue AP Detection with Telegram Notifications")
    print("Inspired by the tool dedetect.py by spiderlabs at: https://github.com/SpiderLabs/snap.py")
    notify(f"Started Monitoring Connected Network at {strftime('%H:%M:%S on %d/%m/%Y', gmtime())}")
    print(f"Started Monitoring Connected Network at {strftime('%H:%M:%S on %d/%m/%Y', gmtime())}")
    start_sniffers()

# NOTE: Replace "wlan0" on thread1 & thread2 with your wireless interface name.
