# PCAP Scrubber, improved
# Using SCAPY

from scapy.all import *
from scapy.layers.l2 import Ether
import argparse
import binascii
import ipaddress
import random

### Globals
ipswap          = {}
strswap         = {}
scapcap         = ""

port_scrub      = {} # {port: UDP payload length}, mainly for TFTP

### Argument Parser Setup
ap = argparse.ArgumentParser(
    prog        = "pcap_scrub.py",
    description = "Reads in a PCAP, scrubs it, and writes modifications to a new PCAP file"
)

ap.add_argument("filename")
ap.add_argument("-sp", "--scrub-payload", action="store_true", help="Scrub >L3 payloads. Default only scrubs Eth\
                 src/dsts and IP src/dsts")
ap.add_argument("-np", "--nuke_payload", action="store_true", help="Unintelligently replaces TCP/UDP payload with random data. Overrides --scrub-payload option")
ap.add_argument("--skip_privip", action="store_true", help="Skip Private IP scrub")
ap.add_argument("-skIP", "--skip_allip", action="store_true", help="Skip ALL IP scrub")
ap.add_argument("-skSt", "--skip_string", action="store_true", help="Skip strings scrubbing (shouldn't\
                be used with -sp, unless IP addresses are in >L3 payloads)")

args = ap.parse_args()

### Helper Functions
def isValidIp(ip: str) -> bool:
    try:
        p = ipaddress.ip_address(ip)
    except ValueError:
        return False
    
    return True

def isNotPublic(ip: str) -> bool:
    addr = 0
    if not isValidIp(ip):
        return False

    addr = ipaddress.ip_address(ip)

    return not (addr.is_global)

def replaceIp4(ip: ipaddress.IPv4Address | str) -> ipaddress.IPv4Address:
    if args.skip_allip:
        return ip
    if ip in ipswap.keys():
        return ipswap[ip]
    
    if isNotPublic(str(ip)) and args.skip_privip:
        return ip
    
    if str(ip) in "0.0.0.0" or str(ip) in "255.255.255.255":
        return ip

    if isNotPublic(str(ip)):
        last = random.randint(1, 254)
        split = str(ip).split('.')
        ipswap[ip] = ipaddress.IPv4Address(f"{'.'.join(split[:-1])}.{last}")
        return ipswap[ip]

    replacement = ""
    for h in range(4):
        replacement += f"{random.randint(1,254)}."
    replacement = replacement[:-1]

    ipswap[ip] = ipaddress.IPv4Address(replacement)
    
    return ipaddress.IPv4Address(replacement)

def replaceIp6(ip: ipaddress.IPv6Address | str) -> ipaddress.IPv6Address:
    if args.skip_allip:
        return ip
    if ip in ipswap.keys():
        return ipswap[ip]
    
    if isNotPublic(str(ip)) and args.skip_privip:
        return ip

    replacement = ""
    for h in range(8):
        replacement = f"{hex(random.randrange(1, 65535))[2:]}:"
    replacement = replacement[:-1]

    ipswap[ip] = replacement
    
    return ipaddress.IPv6Address(replacement)

def replaceStr(s: str) -> str | bytes:
    if s in strswap.keys():
        return strswap[s]

    replacement = ""

    if isinstance(s, bytes):
        replacement = b""
        hexr = binascii.hexlify(s)

        for i in range(0, len(hexr[2:-1]), 2):
            c = hex(random.randint(0, 15))[2:]
            c += hex(random.randint(0, 15))[2:]
            c = bytes(c, 'utf-8')
            replacement += c

        return binascii.unhexlify(replacement)
    else:
        for i in range(len(s)):
            if (random.random() > .5):
                c = chr(random.randint(65,90))
            else:
                c = chr(random.randint(97, 122))
            
            replacement += c
    
    strswap[s] = replacement
    
    return replacement

def nuke_payload(p: scapy.packet) -> scapy.packet:
    if p.haslayer("UDP"):
        p['UDP'].payload = replaceStr(p['UDP'].payload)
    else:
        p['TCP'].payload = replaceStr(p['TCP'].payload)
    
    return p

def main():
    ### Read PCAP
    with open(args.filename, 'rb') as pcap:
        scapcap = rdpcap(pcap)

    ### Parse PCAP

    for pkt in scapcap:

        if pkt.haslayer('IP'):
            pkt["IP"].src = replaceIp4(pkt["IP"].src)
            pkt["IP"].dst = replaceIp4(pkt["IP"].dst)

        if pkt.haslayer('IPv6'):
            pkt["IPv6"].src = replaceIp4(pkt["IP"].src)
            pkt["IPv6"].dst = replaceIp4(pkt["IP"].dst)

        if pkt.haslayer('ARP'):
            pkt["ARP"].psrc = replaceIp4(pkt["ARP"].psrc)
            pkt["ARP"].pdst = replaceIp4(pkt["ARP"].pdst)

        if pkt.haslayer('BOOTP') and args.sp:
            pkt["BOOTP"].ciaddr = replaceIp4(pkt["BOOTP"].ciaddr)
            pkt["BOOTP"].yiaddr = replaceIp4(pkt["BOOTP"].yiaddr)
            pkt["BOOTP"].siaddr = replaceIp4(pkt["BOOTP"].siaddr)
            pkt["BOOTP"].giaddr = replaceIp4(pkt["BOOTP"].giaddr)

            for i in range(len(pkt["DHCP"].options)):
                if len(pkt["DHCP"].options[i]) < 2:
                    continue
                if "end" in pkt["DHCP"].options[i]:
                    break

                try:
                    if "server_id" in pkt["DHCP"].options[i][0]:
                        pkt["DHCP"].options[i] = (pkt["DHCP"].options[i][0], \
                                                replaceIp4(pkt["DHCP"].options[i][1]))
                    if "requested_addr" in pkt["DHCP"].options[i][0]:
                        pkt["DHCP"].options[i] = (pkt["DHCP"].options[i][0], \
                                                replaceIp4(pkt["DHCP"].options[i][1]))
                except Exception as e:
                print(f"{e} with this option:\n{pkt['DHCP'].options[i]}\n\n")

        if pkt.haslayer('TFTP') and args.sp:
            if pkt.sport not in port_scrub.keys():
                port_scrub[pkt.sport] = 0

        if pkt.dport in port_scrub.keys() and port_scrub[pkt.dport] == 0 and args.sp:
            if pkt.haslayer("TFTP_DATA"):
                # Take length of whole UDP packet, end stream if we get a packet smaller than this
                port_scrub[pkt.dport] = len(pkt["UDP"])
                pkt["TFTP_DATA"].block = replaceStr(pkt["TFTP_DATA"].block)
            else:
                last_layer = pkt.layers()[-1]
                port_scrub[pkt.dport] = len(pkt["Raw"].load)
                pkt[last_layer].load = pkt[last_layer].load[:4] + replaceStr(pkt[last_layer].load[3:])

        if pkt.dport in port_scrub.keys() and port_scrub[pkt.dport] != 0 and args.sp:
            if pkt.haslayer("TFTP_DATA"):
                pkt["TFTP_DATA"].block = replaceStr(pkt["TFTP_DATA"].block)
            else:
                last_layer = pkt.layers()[-1]
                pkt[last_layer].load = pkt[last_layer].load[:4] + replaceStr(pkt[last_layer].load[3:])

            if pkt.haslayer("UDP") and len(pkt['UDP']) < port_scrub[pkt.dport]:
                del port_scrub[pkt.dport]

        if args.np:
            pkt = nuke_payload(pkt)

    ### Write modifications
    wrpcap(f"obf_{args.filename}", scapcap)

if __name__ == "__main__":
    main()