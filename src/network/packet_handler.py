"""
Güvenli Dosya Transfer Sistemi - Paket İşleme Modülü

Bu modul, dusuk seviyeli ag islemleri icin gerekli fonksiyonlari icerir.
IP ve TCP paketlerinin olusturulmasi, gonderilmesi ve alinmasi islemlerini
yonetir. Raw socket kullanarak ozel protokol implementasyonu saglar.

Kullanim:
    from network.packet_handler import PacketHandler
    
    handler = PacketHandler()
    packets = handler.fragment_data(data, "192.168.1.1", "192.168.1.2")
    handler.send_packets(packets, "192.168.1.2", 12345)
"""

import socket
import time
from typing import List, Tuple, Optional, Dict

class PacketHandler:
    """
    TCP tabanlı ağ paket işleme sınıfı.

    Bu sınıf, ağ paketlerinin gönderilmesi ve alınması
    işlemlerini yönetir. Standart TCP soketleri kullanarak
    güvenli ve güvenilir iletişim sağlar.
    """

    def __init__(self):
        """PacketHandler sınıfını başlatır."""
        self._send_socket: Optional[socket.socket] = None
        self._listen_socket: Optional[socket.socket] = None
        self._conn_socket: Optional[socket.socket] = None

    def fragment_data(self, data: bytes, src_ip: str, dst_ip: str, dst_port: int) -> bytes:
        """
        TCP için bu metot, veriyi olduğu gibi döndürür.
        Parçalama TCP stack'i tarafından yapılır.
        """
        return data

    def reassemble_packets(self, data: bytes) -> Optional[bytes]:
        """
        TCP'de veri akışı olduğu için, bu metot sadece gelen veriyi döndürür.
        """
        return data

    def _send_bytes_with_length(self, sock: socket.socket, data: bytes) -> None:
        """
        Veriyi, 4 baytlık uzunluk ön ekiyle birlikte gönderir.
        """
        data_length = len(data)
        sock.sendall(data_length.to_bytes(4, 'big'))
        sock.sendall(data)

    def _receive_bytes_with_length(self, sock: socket.socket, timeout: int) -> Optional[bytes]:
        """
        Veriyi, 4 baytlık uzunluk ön ekiyle birlikte alır.
        """
        sock.settimeout(timeout)
        length_bytes = sock.recv(4)
        if not length_bytes:
            return None
        data_length = int.from_bytes(length_bytes, 'big')

        received_data = b''
        bytes_received = 0
        while bytes_received < data_length:
            chunk = sock.recv(min(data_length - bytes_received, 4096))
            if not chunk:
                break
            received_data += chunk
            bytes_received += len(chunk)

        return received_data

    def connect_to_host(self, dst_ip: str, dst_port: int, timeout: int = 5) -> bool:
        """
        Belirtilen hedefe TCP bağlantısı kurar.
        """
        print(f"[PacketHandler] Bağlantı kurulmaya çalışılıyor: {dst_ip}:{dst_port}")
        try:
            self._send_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._send_socket.settimeout(timeout)
            self._send_socket.connect((dst_ip, dst_port))
            print(f"[PacketHandler] [{dst_ip}:{dst_port}] hedefine bağlantı kuruldu.")
            return True
        except Exception as e:
            print(f"[PacketHandler] Bağlantı hatası: {e}")
            self._send_socket = None
            return False

    def send_packets(self, data: bytes) -> bool:
        """
        Önceden kurulmuş TCP bağlantısı üzerinden veriyi gönderir.
        """
        print(f"[PacketHandler] Gönderme işlemi başlatıldı. Veri uzunluğu: {len(data)} bayt.")
        if not self._send_socket:
            print("[PacketHandler] Gönderme soketi bağlı değil.")
            return False

        try:
            self._send_bytes_with_length(self._send_socket, data)
            print(f"[PacketHandler] TCP üzerinden {len(data)} bayt veri gönderildi.")
            return True
        except Exception as e:
            print(f"[PacketHandler] Paket gönderme hatası: {e}")
            return False

    def start_listening(self, listen_port: int, timeout: int = 5) -> bool:
        """
        Belirtilen portta TCP dinlemeye başlar.
        """
        print(f"[PacketHandler] Dinlemeye başlanıyor: {listen_port} portunda.")
        try:
            self._listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._listen_socket.bind(('', listen_port))
            self._listen_socket.listen(1)
            self._listen_socket.settimeout(timeout)
            print(f"[PacketHandler] [{listen_port}] portunda dinlemeye başlandı.")
            return True
        except Exception as e:
            print(f"[PacketHandler] Dinleme hatası: {e}")
            self._listen_socket = None
            return False

    def accept_connection(self, timeout: int = 5) -> bool:
        """
        Dinleme soketi üzerinde gelen bir bağlantıyı kabul eder.
        """
        print("[PacketHandler] Bağlantı kabul edilmesi bekleniyor...")
        if not self._listen_socket:
            print("[PacketHandler] Dinleme soketi başlatılmadı.")
            return False

        try:
            print("[PacketHandler] accept() çağrılıyor...")
            self._conn_socket, addr = self._listen_socket.accept()
            self._conn_socket.settimeout(timeout)
            print(f"[PacketHandler] Bağlantı kabul edildi: {addr}")
            return True
        except socket.timeout:
            print(f"[PacketHandler] Bağlantı kabul etme zaman aşımı: {timeout} saniye.")
            self._conn_socket = None
            return False
        except Exception as e:
            print(f"[PacketHandler] Bağlantı kabul hatası: {e}")
            self._conn_socket = None
            return False

    def receive_packets(self, timeout: int = 5) -> Optional[bytes]:
        """
        Kabul edilmiş TCP bağlantısı üzerinden veriyi alır.
        """
        print(f"[PacketHandler] Veri alımı başlatıldı. Zaman aşımı: {timeout} saniye.")
        if not self._conn_socket:
            print("[PacketHandler] Bağlantı soketi yok.")
            return None

        try:
            received_data = self._receive_bytes_with_length(self._conn_socket, timeout)
            if received_data is None:
                print("[PacketHandler] Veri alınamadı veya bağlantı kapandı.")
                return None
            print(f"[PacketHandler] Toplam {len(received_data)} bayt veri alındı.")
            return received_data
        except socket.timeout:
            print(f"[PacketHandler] Veri alma zaman aşımı: {timeout} saniye.")
            return None
        except Exception as e:
            print(f"[PacketHandler] Paket alma hatası: {e}")
            return None

    def close(self):
        """
        Tüm açık soket bağlantılarını kapatır.
        """
        print("[PacketHandler] Soketler kapatılıyor...")
        if self._send_socket:
            self._send_socket.close()
            self._send_socket = None
            print("[PacketHandler] Gönderme soketi kapatıldı.")
        if self._conn_socket:
            self._conn_socket.close()
            self._conn_socket = None
            print("[PacketHandler] Bağlantı soketi kapatıldı.")
        if self._listen_socket:
            self._listen_socket.close()
            self._listen_socket = None
            print("[PacketHandler] Dinleme soketi kapatıldı.")

    def send_test_packet(self, dst_ip: str, dst_port: int, ttl: int = 64, flags: str = "DF") -> bool:
        """
        Test amaçlı bir TCP paketi gönderir (Scapy bağımlılığı kaldırıldığı için bu metot basitleştirildi).
        """
        temp_socket = None
        try:
            temp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            temp_socket.connect((dst_ip, dst_port))
            self._send_bytes_with_length(temp_socket, b"TEST_PACKET")
            print(f"Test paketi {dst_ip}:{dst_port} adresine gönderildi.")
            return True
        except Exception as e:
            print(f"Test paketi gönderme hatası: {e}")
            return False
        finally:
            if temp_socket:
                temp_socket.close()

    def test_connection(self, dst_ip: str, dst_port: int) -> Dict:
        """
        Baglanti testi yapar ve sonuclari dondurur.
        
        Args:
            dst_ip: Hedef IP adresi
            dst_port: Hedef port numarasi
            
        Returns:
            Dict: Test sonuclari
                - success: Baglanti basarili mi
                - ttl: Yanit TTL degeri
                - flags: TCP bayraklari
                - error: Hata mesaji (varsa)
        """
        results = {
            'success': False,
            'ttl': 0,
            'flags': '',
            'error': None
        }
        
        try:
            # Test paketi gonder
            packet = IP(dst=dst_ip)/TCP(dport=dst_port, flags='S')
            reply = sr1(packet, timeout=2, verbose=0)
            
            if reply and reply.haslayer(TCP):
                results.update({
                    'success': True,
                    'ttl': reply.ttl,
                    'flags': reply[TCP].flags,
                    'window': reply[TCP].window
                })
            else:
                results['error'] = 'Yanit alinamadi'
                
        except Exception as e:
            results['error'] = str(e)
        
        return results 