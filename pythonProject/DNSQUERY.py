from scapy.all import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def dns_query(domain, dns_server='8.8.8.8'):
    """Belirtilen DNS sunucusuna bir domain için DNS sorgusu gönderiliyor."""

    ip_layer = IP(dst=dns_server)
    udp_layer = UDP(dport=53) # IP ve UDP Katmanları (DNS 53. portu kullanır)

    # DNS Katmanı (Sorgu oluşturma)
    # qd: Question Record (Sorgu kaydı)
    dns_layer = DNS(rd=1, qd=DNSQR(qname=domain))  # rd=1 (recursion desired)
    packet = ip_layer / udp_layer / dns_layer
    print(f"[{domain}] için {dns_server} adresine DNS sorgusu gönderiliyor...")
    response = sr1(packet, timeout=3, verbose=0)

    if response and response.haslayer(DNS):
        # Yanıtın answer alanını kontrol etmeliyiz
        if response[DNS].an:
            print(f"✅ Başarılı yanıt alındı!")
            for i in range(response[DNS].ancount):
                if response[DNS].an[i].type == 1:   # Yanıttaki A kaydını (IP adresi) gösterir # Tip 1, A kaydıdır
                    print(f"   {domain} -> {response[DNS].an[i].rdata}")
            return
        else:
            print("DNS sunucusundan yanıt alındı, ancak IP adresi bulunamadı.")
    else:
        print(f" DNS sunucusuna ulaşılamadı veya yanıt alınamadı.")


hedef_domain = input("Lütfen IP adresini sorgulamak istediğiniz domain adını girin (örn: google.com): ")
dns_query(hedef_domain)