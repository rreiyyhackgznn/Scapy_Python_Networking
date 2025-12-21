from scapy.all import *
print("\nPaket Sahteciliği Aracı (Scapy)")
print("---------------------------------")
spoofmac = input('Enter the spoofed MAC address: ')
dst = input('Enter the destination IP address: ')

ether = Ether()
ether.src = spoofmac # Sahte MAC adresini kaynak olarak ayarlıyoruz

# ICMP Katmanı (Ping)
icmp = ICMP()
icmp.type = 8  # Echo Request (Ping isteği)
icmp.code = 0

# IP Katmanı
ip = IP()
ip.dst = dst
ip.src = '192.168.X.X'

packet = ether / ip / icmp  #katmanlar birleştiriliyor

print('\nSending spoofed Packet ......')
sendp(packet) #Layer 2 (Ethernet) seviyesinde gönderme yapar.
print('Packet sent successfully.')