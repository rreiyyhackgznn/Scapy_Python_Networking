from scapy.all import *
import datetime
import logging
import sys
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

print("\n LAN Hız Test Aracı (Ping Gecikme Ölçer)")
print("------------------------------------------")

dst_ip = input("Lütfen ping atmak istediğiniz hedef IP adresini girin (örn: 192.168.1.1): ")

icmp = ICMP()
icmp.type = 8  # Ping isteği (Echo Request)
icmp.code = 0

ip = IP()
ip.src = '192.168.X.X'  # Sanal makinein kaynak IP adresi
ip.dst = dst_ip  # Kullanıcıdan alınan hedef IP

start_time = datetime.datetime.now() # 1. Göndermeden hemen önce zamanı kaydet

print(f"\n{dst_ip} hedefine ping gönderiliyor...") # 2. Paketi gönder ve yanıtı bekle
p = sr1(ip / icmp, timeout=2, verbose=0)  # sr1(paket, timeout=saniye, verbose=0)

#yanıt geldiini varsayarsak
if p:
    # Yanıt geldikten hemen sonra kaydettiğimiz zaman
    end_time = datetime.datetime.now()

    # Geçen süreyi hesapla
    elapsed_time = (end_time - start_time)

    # Daha hassas ölçüm için süreyi milisaniye cinsinden aldık
    # total_seconds() ile saniye cinsinden alıp 1000 ile çarpıyoruz.
    rtt_ms = round(elapsed_time.total_seconds() * 1000, 3)

    print(f"Başarılı yanıt alındı!")
    print(f"Yanıt Kaynağı: {p.src}")
    print(f"Geçen Süre (RTT): {rtt_ms} ms")  # Round Trip Time (Gidiş-Dönüş Süresi)


# 4. Yanıt gelmezse (Timeout)
else:
    print(f"{dst_ip} hedefine ulaşılamadı veya yanıt süresi doldu (2 saniye).")

print("\n--- Test Tamamlandı ---")