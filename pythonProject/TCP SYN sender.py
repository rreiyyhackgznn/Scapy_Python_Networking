from scapy.all import *
dst = input('\n Hedef IP adresini girin (destination): ')

try:
    port = int(input(' Port numarasını girin: '))
except ValueError:
    print("HATA: Lütfen geçerli bir tamsayı port numarası girin.")
    exit()

ip = IP()
ip.dst = dst
ip.src = '192.168.X.X'

tcp = TCP()
tcp.flags = 'S'
tcp.dport = port

print(f"Paket gönderiliyor: {ip.src} -> {ip.dst}:{tcp.dport} (SYN)")
send(ip/tcp, verbose=0)