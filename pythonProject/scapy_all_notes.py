from scapy.all import *

ether = Ether()
ether.src = "aa:bb:cc:dd:ee:ff"
ether.dst = "ff:ff:ff:ff:ff:ff"

arp = ARP(pdst="192.168.1.1")

pkt = ether / arp
sendp(pkt)

from scapy.all import *

print("Default interface:", conf.iface)
print("Local IP:", get_if_addr(conf.iface))
print("Local MAC:", get_if_hwaddr(conf.iface))
ls(Ether)
ls(IP)
ls(ICMP)
ls(TCP)
ls(UDP)


send(IP(dst="8.8.8.8")/ICMP())
p = sr1(IP(dst="8.8.8.8")/ICMP(), timeout=3, verbose=0)
if p:
    p.show()
else:
    print("No ICMP reply")


#TTL örneği (traceroute mantığı)

p = sr1(IP(dst="8.8.8.8", ttl=1)/ICMP(), timeout=3, verbose=0)
if p:
    print("TTL=1 reply from:", p.src)

#  Subnet discovery (ping sweep)

for k in range(1, 10):
    ip = IP(dst=f"192.168.1.{k}")
    p = sr1(ip/ICMP(), timeout=1, verbose=0)
    if p:
        print(f"[+] Host UP: 192.168.1.{k}")

# TCP SYN packet (raw TCP)

syn = IP(dst="192.168.1.1")/TCP(dport=80, flags="S")
syn.show()

#  TCP SYN scan (tek port)

p = sr1(IP(dst="192.168.1.1")/TCP(dport=80, flags="S"), timeout=2, verbose=0)
if p and p.haslayer(TCP):
    if p[TCP].flags == "SA":
        print("Port 80 OPEN")
    elif p[TCP].flags == "RA":
        print("Port 80 CLOSED")


# UDP packet + checksum (auto)
udp_pkt = IP(dst="8.8.8.8")/UDP(dport=53)/Raw(load="test")
udp_pkt.show()

# UDP packet (manuel checksum - spoof örneği)

udp_pkt[UDP].chksum = 0x1234
send(udp_pkt)

# IP spoofing
spoof = IP(src="1.2.3.4", dst="8.8.8.8")/ICMP()
send(spoof)

# Ethernet + ARP (Layer 2)
arp_req = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.1")
arp_req.show()

# ARP request gönder + cevapları al
ans, unans = srp(arp_req, timeout=2, verbose=0)
for snd, rcv in ans:
    print("IP:", rcv.psrc, "MAC:", rcv.hwsrc)

#ARP spoof (örnek – eğitim amaçlı)
arp_spoof = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
    op=2,
    psrc="192.168.1.1",
    pdst="192.168.1.10",
    hwsrc="aa:bb:cc:dd:ee:ff"
)
sendp(arp_spoof)

# Packet sniff (1 paket)
pkt = sniff(count=1)
pkt[0].show()

# Filtreli sniff (ICMP)
sniff(filter="icmp", count=3, prn=lambda x: x.summary())

#send vs sendp farkı

# send  -> Layer 3 (Ethernet OS ekler)
send(IP(dst="8.8.8.8")/ICMP())

# sendp -> Layer 2 (Ethernet'i sen yazarsın)
sendp(Ether()/ARP(pdst="192.168.1.1"))

