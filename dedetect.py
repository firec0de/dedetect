from scapy import *
from scapy.layers.dot11 import Dot11, Dot11Elt, Dot11Beacon, Dot11EltRates, Dot11EltHTCapabilities, \
    Dot11EltVendorSpecific, Dot11EltCountryConstraintTriplet, Dot11EltCountry
from scapy.sendrecv import sniff


def parse_packet(packet):
    if packet.haslayer(Dot11):
        ap_mac = packet.addr2
        if packet.type == 0 and (packet.subtype == 0x0a or packet.subtype == 0x0c):
            print(f"Deauth/Disassoc frame detected from AP: {ap_mac}")

sniff(iface="wlan0", prn=parse_packet, filter="link[0] == 0xc0 or link[0] == 0xa0")
