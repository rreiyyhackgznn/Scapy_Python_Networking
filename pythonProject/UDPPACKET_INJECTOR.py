from scapy.all import *
print("\nUDP Paket Enjektörü (Scapy)")
print("----------------------------")

dst = input('Enter the destination IP address: ')
port_input = input('Enter the port number: ')

try:
    port = int(port_input)
except ValueError:
    print("Error: Port number must be a valid integer.") #Port numarasını tamsayıya dönüştür (GEREKLİ)
    exit()

udp = UDP()     #UDP Katmanını Oluştur
udp.dport = port

ip = IP()
ip.dst = dst           # Hedef IP adresi

# Paketi gönderelim
# UDP paket enjektörleri genellikle rastgele veri de ekleriz
# payload = "Scapy Test Data"
# packet = ip / udp / payload
packet = ip / udp

print(f'\nSending UDP packet to {dst}:{port} ......')
send(packet) # send() fonksiyonu Katman 3 (IP) seviyesinde gönderir.

print('Packet sent successfully.')