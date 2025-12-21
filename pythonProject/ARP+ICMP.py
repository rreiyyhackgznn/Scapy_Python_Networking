from scapy.all import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
def combined_scan(subnet="192.168.1.0/24"):
    """ARP ve ICMP kullanarak ağdaki aktif cihazları tarar."""
# ARP Katmanlarını kullanarak yerel ağ taraması yapalım

    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
    print(f"\n[1/2] ARP taraması başlatılıyor ({subnet})...")

# srp() fonksiyonu gönderilen ve alınan paket çiftlerini döndürür.
    answered, unanswered = srp(arp_request, timeout=2, verbose=0)

    active_hosts = {}

    print("--------------------------------------------------")
    print("ARP Yanıtları (Yerel Ağ):")
    for sent, received in answered:
        ip = received.psrc
        mac = received.hwsrc   # ARP yanıtından IP ve MAC adreslerini çek
        active_hosts[ip] = mac
        print(f"  [ARP] IP: {ip} | MAC: {mac}")

#ICMP Katmanlarını kullanarak genel ping taraması
    ip_layer = IP(dst=subnet)
    icmp_layer = ICMP()
    print("\n[2/2] ICMP (Ping) taraması başlatılıyor...")
    # sr() fonksiyonu IP seviyesinde gönderir ve yanıtları alır.
    answered_ping, unanswered_ping = sr(ip_layer / icmp_layer, timeout=1, verbose=0)

    print("--------------------------------------------------")
    print("ICMP Yanıtları (Ağdaki Tüm Cihazlar):")
    for sent, received in answered_ping:
        ip = received.src
        if ip not in active_hosts:
            active_hosts[ip] = "Bilinmiyor (ICMP Yanıtı)"
            print(f"  [ICMP] IP: {ip} | MAC: Bilinmiyor (Ping)")

    print("--------------------------------------------------")
    print(f"Toplam Aktif Cihaz Sayısı: {len(active_hosts)}")
    return active_hosts

# Kendi yerel ağımız uygun subnet'i girelim (Örn: 192.168.x.0/24)
subnet_to_scan = input("Lütfen taranacak ağı CIDR formatında girin (örn: 192.168.x.0/24): ")
combined_scan(subnet_to_scan)