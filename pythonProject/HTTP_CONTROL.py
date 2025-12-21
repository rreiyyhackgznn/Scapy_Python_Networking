from scapy.all import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
def http_check(target_ip, port=80):
    """Hedef IP'nin belirtilen portunda hizmet çalışıp çalışmadığını kontrol ederiz. (SYN taraması)."""
 # IP ve TCP Katmanları
    ip_layer = IP(dst=target_ip)
    # dport: Hedef port, flags='S': SYN paketi gönderir
    tcp_layer = TCP(dport=port, flags='S', seq=1000)
# Paketi gönderip tek bir yanıtı bekle
    print(f"\n{target_ip}:{port} adresine TCP SYN paketi gönderiliyor...")
    # sr1, yanıtı yakalamayı ve diğer paketleri görmezden gelmeyi sağlar.
    response = sr1(ip_layer / tcp_layer, timeout=1, verbose=0)
# Yanıtı analiz ediyoruz
    if response:
        # Yanıt TCP katmanı içeriyor mu?
        if response.haslayer(TCP):
            # Flags alanını kontrol et: SYN-ACK (0x12) = Hizmet çalışıyor
            if response[TCP].flags == 'SA':  # S=SYN, A=ACK
                print(f"✅ {target_ip}:{port} -> AÇIK (SYN-ACK alındı)")
                # Bağlantıyı düzgün kapatmak için RST paketi gönderelim
                send(IP(dst=target_ip) / TCP(dport=port, flags='R', seq=response[TCP].ack, ack=response[TCP].seq + 1),
                     verbose=0)
                return True
            # Flags alanını kontrol et: RST-ACK (0x14) = Port kapalı/Filtreli
            elif response[TCP].flags == 'RA':  # R=RST, A=ACK
                print(f"{target_ip}:{port} -> KAPALI (RST-ACK alındı)")
                return False
# Yanıt yoksa (timeout)
    else:
        print(f"{target_ip}:{port} -> FILTRELENMIŞ/YANIT YOK (Timeout)")
        return False
hedef_ip = input("Lütfen HTTP durumunu kontrol etmek istediğiniz IP adresini girin: ")
http_check(hedef_ip, port=80)
http_check(hedef_ip, port=443)  # HTTPS için de kontrol edelim