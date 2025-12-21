import logging #Scapy'nin runtime loglayıcısını alır.
logging.getLogger('scapy.runtime').setLevel(logging.ERROR) #Sadece ERROR ve üzeri seviyedeki mesajların gösterilmesini sağlar. WARNING, INFO, DEBUG mesajları görünmez.
from scapy.all import *  # Scapy'nin tüm fonksiyonlarını içe aktar

temp = ICMP()  # ICMP paketi nesnesi oluştur
temp.type = 8   # ICMP tipi (8 = echo request, yani ping isteği)
temp.code = 0   # ICMP kodu (genelde 0, tip 8 için standart)

tp = IP()  # IP paketi nesnesi oluştur
tp.src = '192.168.X.X'   # Kaynak IP adresi
tp.dst = '192.168.X.X'  # Hedef IP adresi

send(tp / temp)  # IP ve ICMP katmanlarını birleştir ve gönder