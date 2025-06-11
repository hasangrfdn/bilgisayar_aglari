"""
Güvenli Dosya Transfer Sistemi - Ana Program

Bu modul, guvenli dosya transfer sisteminin ana programini icerir.
Dosya gonderme ve alma islemlerini yonetir, komut satiri argumanlarini isler
ve guvenlik mekanizmalarini koordine eder.

Kullanim:
    python main.py --mode [send|receive] [diger_argumanlar]

Ornek:
    Gonderme: python main.py --mode send --file test.txt --dst-ip 127.0.0.1 --password <sifreniz>
    Alma: python main.py --mode receive --password <sifreniz>
"""

import os
import sys
import time
import argparse
import logging
from typing import Optional, Dict, Any

# Mutlak import kullanımı
from src.core.file_transfer import FileTransfer, FileMetadata
from src.network.packet_handler import PacketHandler
from src.security.auth import Authentication

class SecureFileTransfer:
    """
    Guvenli dosya transfer uygulamasi ana sinifi.
    
    Bu sinif, dosya transferi, ag islemleri ve guvenlik mekanizmalarini
    koordine eder. Dosyalarin guvenli bir sekilde transfer edilmesini saglar.
    """
    
    def __init__(self):
        """Uygulama bileşenlerini baslatir."""
        self.file_transfer = FileTransfer()  # Dosya transfer islemleri
        self.packet_handler = PacketHandler()  # Ag paket islemleri
        self.auth = Authentication()  # Guvenlik ve kimlik dogrulama
    
    def setup_keys(self, key_dir: str = "keys"):
        """
        RSA anahtar çiftini olusturur veya mevcut anahtarlari yukler.
        
        Args:
            key_dir: Anahtarlarin saklanacagi dizin yolu
        """
        os.makedirs(key_dir, exist_ok=True)
        
        private_key_path = os.path.join(key_dir, "private_key.pem")
        public_key_path = os.path.join(key_dir, "public_key.pem")
        
        if os.path.exists(private_key_path) and os.path.exists(public_key_path):
            print("Mevcut anahtarlar yukleniyor...")
            self.auth.load_keys(private_key_path, public_key_path)
        else:
            print("Yeni anahtar cifti olusturuluyor...")
            private_pem, public_pem = self.auth.generate_key_pair()
            self.auth.save_keys(private_key_path, public_key_path)
    
    def send_file(self, filepath: str, dst_ip: str, dst_port: int, password: str):
        """
        Dosyayi guvenli bir sekilde gonderir.
        
        Islem adimlari:
        1. Dosyayi hazirlar ve sifreler
        2. Oturum anahtari olusturur
        3. Meta verileri imzalar
        4. Veriyi paketlere boler
        5. Paketleri gonderir
        
        Args:
            filepath: Gonderilecek dosyanin yolu
            dst_ip: Hedef IP adresi
            dst_port: Hedef port numarasi
            password: Sifreleme anahtari
            
        Returns:
            bool: Islem basarili ise True, degilse False
        """
        try:
            # Dosyayi hazirla ve sifrele
            print("Dosya hazirlaniyor ve sifreleniyor...")
            metadata, encrypted_data = self.file_transfer.prepare_file(filepath, password)
            
            # Oturum anahtari olustur
            session_key = self.auth.generate_session_key()
            
            # Dosya meta verilerini imzala
            metadata_bytes = f"{metadata.filename}:{metadata.size}:{metadata.checksum}".encode()
            signature = self.auth.sign_data(metadata_bytes)
            
            # Veriyi paketlere bol
            print("Veri paketlere bolunuyor...")
            packets = self.packet_handler.fragment_data(encrypted_data, "0.0.0.0", dst_ip)
            
            # Paketleri gonder
            print(f"Toplam {len(packets)} paket gonderiliyor...")
            if self.packet_handler.send_packets(packets, dst_ip, dst_port):
                print("Dosya basariyla gonderildi!")
                return True
            else:
                print("Dosya gonderimi basarisiz!")
                return False
        
        except Exception as e:
            print(f"Hata: {e}")
            return False
        
        finally:
            self.packet_handler.close()
    
    def receive_file(self, output_dir: str, password: str, timeout: int = 30):
        """
        Dosyayi guvenli bir sekilde alir.
        
        Islem adimlari:
        1. Paketleri bekler ve alir
        2. Paketleri birlestirir
        3. Dosyayi cozer ve kaydeder
        
        Args:
            output_dir: Alinan dosyalarin kaydedilecegi dizin
            password: Sifreleme anahtari
            timeout: Paket bekleme suresi (saniye)
            
        Returns:
            bool: Islem basarili ise True, degilse False
        """
        try:
            print("Paketler bekleniyor...")
            packets = self.packet_handler.receive_packets(timeout)
            
            if not packets:
                print("Hic paket alinamadi!")
                return False
            
            # Paketleri birlestir
            print("Paketler birlestiriliyor...")
            encrypted_data = self.packet_handler.reassemble_packets(packets)
            
            if not encrypted_data:
                print("Paketler birlestirilemedi!")
                return False
            
            # Dosyayi kaydet
            print("Dosya kaydediliyor...")
            metadata = FileMetadata(
                filename="received_file",  # Gercek uygulamada meta veriler ayri bir pakette gonderilmeli
                size=len(encrypted_data),
                checksum="",  # Gercek uygulamada checksum dogrulanmali
                encryption_key=b"",  # Gercek uygulamada anahtar guvenli sekilde paylasilmali
                iv=b""
            )
            
            output_path = self.file_transfer.save_file(encrypted_data, metadata, output_dir)
            print(f"Dosya basariyla kaydedildi: {output_path}")
            
            return True
        
        except Exception as e:
            print(f"Hata: {e}")
            return False
        
        finally:
            self.packet_handler.close()

def parse_args():
    parser = argparse.ArgumentParser(description='Güvenli Dosya Transfer Sistemi')
    parser.add_argument('--mode', choices=['send', 'receive', 'gui'], 
                      help='Çalışma modu: send (gönder), receive (al), gui (arayüz)')
    parser.add_argument('--file', help='Gönderilecek dosya yolu')
    parser.add_argument('--dst-ip', help='Hedef IP adresi')
    parser.add_argument('--dst-port', type=int, default=5000, help='Hedef port (varsayılan: 5000)')
    parser.add_argument('--output-dir', default='received_files', help='Alınan dosyaların kaydedileceği dizin')
    parser.add_argument('--password', required=False, help='Şifre (GUI modunda opsiyonel)')
    return parser.parse_args()

def main():
    """
    Ana program fonksiyonu.
    
    Komut satiri argumanlarini isler ve uygun transfer modunu baslatir.
    """
    args = parse_args()
    
    if args.mode == 'gui':
        from PyQt5.QtWidgets import QApplication
        from src.gui.main_window import MainWindow  # Mutlak import kullanımı
        import sys
        
        app = QApplication(sys.argv)
        window = MainWindow()
        window.show()
        sys.exit(app.exec_())
    else:
        if not args.password:
            print("Hata: Şifre belirtilmedi!")
            sys.exit(1)
            
        if args.mode == 'send' and not args.file:
            print("Hata: Gönderilecek dosya belirtilmedi!")
            sys.exit(1)
            
        if args.mode == 'send' and not args.dst_ip:
            print("Hata: Hedef IP adresi belirtilmedi!")
            sys.exit(1)
            
        # Uygulamayi baslat
        app = SecureFileTransfer()
        app.setup_keys()
        
        # Moda gore islem yap
        if args.mode == "send":
            app.send_file(args.file, args.dst_ip, args.dst_port, args.password)
        
        else:  # receive mode
            app.receive_file(args.output_dir, args.password)

if __name__ == "__main__":
    main() 