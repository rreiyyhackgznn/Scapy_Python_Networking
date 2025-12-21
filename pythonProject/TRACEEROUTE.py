from scapy.all import *
import logging
import sys
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
def custom_traceroute(target):
    if not target:
        print("Hata: Lütfen geçerli bir hedef IP veya domain girin.") #Kullanıcı girdisinin kontrolü
        return

    print(f"\n[TRACEROUTE] Hedef: {target}")
    print("--------------------------------------------------")

    # TTL (Time-To-Live) değerini 1'den başlatıyoruz
    for ttl in range(1, 30):  # 30 hop'a kadar deneme yap
        ip_layer = IP(dst=target, ttl=ttl)  # IP Katmanını oluşturup ve TTL değerini ayarlıyoruz
        udp_layer = UDP(dport=33434)   # UDP Katmanını ekle (Traceroute genellikle UDP kullanır) geleneksel olarak kullanılan bir port

        # Paketi gönder ve yanıtı bekle
        # sr1: Katman 3'te gönder, tek yanıt bekle
        response = sr1(ip_layer / udp_layer, timeout=1.5, verbose=0)

        if response is None:
            print(f"{ttl:2}. * * * (Zaman Aşımı)")
        else:
            if response.haslayer(ICMP):  # ICMP yanıtı ise (Yönlendiriciden gelen "Süre Aşıldı" mesajı)
                # type=11, code=0: Time Exceeded (TTL sıfırlandı)
                if response.getlayer(ICMP).type == 11 and response.getlayer(ICMP).code == 0:
                    print(f"{ttl:2}. {response.src}")

                # type=3: Hedefe Ulaşılamadı (Yanıtı filtreleyen bir cihaz var)
                elif response.getlayer(ICMP).type == 3:
                    print(f"{ttl:2}. {response.src} (Hedeften ulaşılamaz - Filtre)")
                    break  # Yol kesildiği için çıkabiliriz

            # UDP yanıtı ise (Hedef cihaza ulaşıldı)
            elif response.haslayer(UDP):
                # UDP'den yanıt almak, hedefe ulaşıldığı anlamına gelir
                print(f"{ttl:2}. {response.src} (HEDEF!)")
                break  # Hedefe ulaşıldı, döngüyü bitir

            # Başka bir tür yanıt gelirse (örneğin hedef direkt ICMP/Ping yanıtı veriyorsa)
            else:
                print(f"{ttl:2}. {response.src} (Hedefe Ulaşıldı)")
                break
hedef_ip_or_domain = input("Lütfen Traceroute için hedef IP veya domain girin (örn: google.com): ")
custom_traceroute(hedef_ip_or_domain)