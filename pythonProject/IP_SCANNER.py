from scapy.all import *
import logging
import sys
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

print("\nAğdaki Aktif Cihazları Tarama (Ping Tarayıcı)")
print("------------------------------------------")

try:
    start_octet = int(input("Ağdaki başlangıç IP son oktetini girin (örn: 90): "))
    end_octet = int(input("Ağdaki bitiş IP son oktetini girin (örn: 102): "))         # Kullanıcıdan IP aralığının ilk ve son oktetini alalım
    base_ip = input("Ağ Temel IP'sini girin (örn: 192.168.1.): ")
except ValueError:
    print("Hata: Girdiler tamsayı olmalıdır.")
    sys.exit()

count = 0


ip = IP(src='192.168.X.X')  # Kaynak IP, ihtiyaca göre değiştirilebilir
icmp = ICMP()
icmp.type = 8  # Ping isteği (Echo Request)
icmp.code = 0

print(f"Tarama başlatılıyor: {base_ip}{start_octet} - {base_ip}{end_octet}\n")

# Belirtilen aralıkta döngü oluşturuyoruz
for i in range(start_octet, end_octet + 1):  # range() fonksiyonu üst sınırı dahil etmediği için (end_octet + 1) kullanıyoruz

    ip.dst = f"{base_ip}{i}" #heddef ip

    # Paketi gönderip ve yanıtı bekliyoruz
    # verbose=0: Çıktı gürültüsünü kapatır
    # timeout=1: Yanıt için 1 saniye bekler
    reply = sr1(ip / icmp, timeout=1, verbose=0)

    if reply:
        count += 1
        print(f"{reply.src} sistemi aktif.") # Yanıt geldiyse, cihaz aktif demektir
    else:
        print(f"{ip.dst} sistemi kapalı veya ulaşılamıyor.")

print(f"\n--- Tarama Tamamlandı ---")
print(f"Ağda tespit edilen aktif cihaz sayısı: {count}")