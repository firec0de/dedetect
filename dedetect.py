from scapy import *
from scapy.layers.dot11 import Dot11, Dot11Elt, Dot11Beacon, Dot11EltRates, Dot11EltHTCapabilities, \
    Dot11EltVendorSpecific, Dot11EltCountryConstraintTriplet, Dot11EltCountry
from scapy.sendrecv import sniff
import hashlib
import sys

def parse(frame):
    if frame.haslayer(Dot11) and frame.type == 0 and frame.subtype == 8:
        print("BSSID:", frame.addr3)
        print("SSID:", (frame.info).decode('utf-8'))
        channel = int(ord(frame[Dot11Elt:3].info))
        print("Channel:", channel)
        if frame.haslayer(Dot11EltCountry):
            country = (frame[Dot11EltCountry].country_string).decode('utf-8')
        else:
            country = 0
        print("Country:", country)
        print("Supported Rates:", frame.rates)
        erates = frame[Dot11EltRates].info
        print("Extended Rates:", erates)
        if frame.haslayer(Dot11EltCountryConstraintTriplet):
            power = frame[Dot11EltCountryConstraintTriplet].mtp
        else:
            power = 0
        print("Max Transmit Power:", power)
        if frame.haslayer(Dot11Beacon):
            cap = frame[Dot11Beacon].cap
        else:
            cap = 0
        print("Capabilities:", cap)
        if frame.haslayer(Dot11EltHTCapabilities):
            htmax = frame[Dot11EltHTCapabilities].Max_A_MSDU
            ht = frame[Dot11EltHTCapabilities].summary
        else:
            htmax = 0
            ht = 0
        print("Max_A_MSDU:", htmax)
        if frame.haslayer(Dot11EltVendorSpecific):
            try:
                vendor = frame[Dot11EltVendorSpecific:2].oui
            except:
                vendor = 0
        else:
            vendor = 0
        print("Vendor:", vendor)
        all = frame.addr3 + str(frame.info) + str(channel) + str(country) + str(vendor) + str(frame.rates) + str(erates) + str(power) + str(cap) + str(htmax) + str(vendor)
        print("SHA256: " + (hashlib.sha256(all.encode('utf-8')).hexdigest()))
        airbasesig = str(country) + str(frame.rates) + str(erates) + str(power) + str(cap) + str(htmax) + str(vendor)
        if hashlib.sha256(airbasesig.encode('utf-8')).hexdigest() == "4c847490293ea0bf0cf2fe7ddb02703368aaf8e97ffb16455f0365a7497e2de2":
            print("******** AIRBASE-NG DETECTED AT THIS ACCESS POINT ********\n")
        else:
            print("")

sniff(iface="wlan0", prn=parse)
def parse_packet(packet):
    if packet.haslayer(Dot11):
        ap_mac = packet.addr2
        if packet.type == 0 and (packet.subtype == 0x0a or packet.subtype == 0x0c):
            print(f"Deauth/Disassoc frame detected from AP: {ap_mac}")

sniff(iface="wlan0", prn=parse_packet, filter="link[0] == 0xc0 or link[0] == 0xa0")
