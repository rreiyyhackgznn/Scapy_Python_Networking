from scapy.all import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

print("\n🔍 Yerel Ağ ARP Tarayıcı (MAC Adresi Bulucu)")
print("---------------------------------------------")
dst_ip = input('Lütfen MAC adresini bulmak istediğiniz hedef IP adresini girin: ')

# 1. Ethernet Katmanı (Broadcast'i belirtmek için)
# Kaynak MAC'i Scapy'nin otomatik kullanması için boş bırakıyoruz
ether_layer = Ether(dst="ff:ff:ff:ff:ff:ff")

# 2. ARP Katmanı (İstek mesajını oluşturma)
arp_layer = ARP(pdst=dst_ip, op=1)  # op=1 -> ARP Request

# 3. Paketi birleştirme ve gönderme
# srp1: Katman 2'de gönder, tek yanıt bekle
print(f"\n{dst_ip} adresi için ARP isteği gönderiliyor...")
response = srp1(ether_layer / arp_layer, timeout=1, verbose=0)

if response:
    target_mac = response.hwsrc
    print(f"\n {response.psrc} IP adresinin MAC adresi:")
    print(f" {target_mac}")
else:
    print(f"\n {dst_ip} adresi için ARP yanıtı alınamadı (Cihaz kapalı veya ağda değil).")
