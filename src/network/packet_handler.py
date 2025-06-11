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
import struct
import time
from typing import List, Tuple, Optional, Dict
from scapy.all import IP, TCP, Raw, fragment, ICMP, send, sr1

class PacketHandler:
    """
    IP paket isleme ve manipülasyon sinifi.
    
    Bu sinif, ag paketlerinin olusturulmasi, gonderilmesi ve alinmasi
    islemlerini yonetir. Raw socket kullanarak dusuk seviyeli ag
    islemleri yapar.
    """
    
    def __init__(self, mtu: int = 1500):
        """
        PacketHandler sinifini baslatir.
        
        Args:
            mtu: Maximum Transmission Unit (byte)
        """
        self.mtu = mtu
        self._socket = None
    
    def _create_ip_header(self, src_ip: str, dst_ip: str, ttl: int = 64) -> IP:
        """
        IP basligi olusturur.
        
        Args:
            src_ip: Kaynak IP adresi
            dst_ip: Hedef IP adresi
            ttl: Time To Live degeri
            
        Returns:
            IP: Scapy IP paketi
        """
        return IP(
            src=src_ip,
            dst=dst_ip,
            ttl=ttl,
            flags=0,  # Normal paket
            id=int(time.time() * 1000) & 0xFFFF  # Benzersiz ID
        )
    
    def _create_tcp_header(self, src_port: int, dst_port: int, seq: int = 0) -> TCP:
        """
        TCP basligi olusturur.
        
        Args:
            src_port: Kaynak port numarasi
            dst_port: Hedef port numarasi
            seq: Sira numarasi
            
        Returns:
            TCP: Scapy TCP paketi
        """
        return TCP(
            sport=src_port,
            dport=dst_port,
            seq=seq,
            flags="S",  # SYN flag
            window=65535
        )
    
    def _calculate_checksum(self, data: bytes) -> int:
        """
        IP basligi icin checksum hesaplar.
        
        Args:
            data: Checksum hesaplanacak veri
            
        Returns:
            int: 16-bit checksum degeri
        """
        if len(data) % 2 == 1:
            data += b'\0'
        
        words = struct.unpack('!%dH' % (len(data) // 2), data)
        checksum = sum(words)
        
        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
        
        return ~checksum & 0xFFFF
    
    def fragment_data(self, data: bytes, src_ip: str, dst_ip: str) -> List[IP]:
        """
        Veriyi IP paketlerine boler.
        
        Islem adimlari:
        1. IP ve TCP basliklarini olusturur
        2. Veriyi pakete ekler
        3. MTU'ya gore paketi parcalar
        
        Args:
            data: Parcalanacak veri
            src_ip: Kaynak IP adresi
            dst_ip: Hedef IP adresi
            
        Returns:
            List[IP]: Parcalanmis IP paketleri listesi
        """
        # IP ve TCP basliklarini olustur
        ip = self._create_ip_header(src_ip, dst_ip)
        tcp = self._create_tcp_header(12345, 12345)  # Ornek portlar
        
        # Veriyi paketlere ekle
        packet = ip/tcp/Raw(load=data)
        
        # Paketi parcala
        fragments = fragment(packet, fragsize=self.mtu - 40)  # 40 = IP + TCP baslik boyutu
        return fragments
    
    def reassemble_packets(self, packets: List[IP]) -> Optional[bytes]:
        """
        Parcalanmis paketleri birlestirir.
        
        Islem adimlari:
        1. Paketleri siraya dizer
        2. Tum parcalarin geldigini kontrol eder
        3. Veriyi birlestirir
        
        Args:
            packets: Birlestirilecek paketler listesi
            
        Returns:
            Optional[bytes]: Birlestirilmis veri veya None
        """
        if not packets:
            return None
        
        # Paketleri siraya diz
        sorted_packets = sorted(packets, key=lambda x: x.frag)
        
        # Tum parcalarin geldigini kontrol et
        if not all(p.flags & 0x2 == 0 for p in sorted_packets[:-1]):
            return None
        
        # Veriyi birlestir
        reassembled_data = b''
        for packet in sorted_packets:
            if Raw in packet:
                reassembled_data += packet[Raw].load
        
        return reassembled_data
    
    def send_packets(self, packets: List[IP], dst_ip: str, dst_port: int) -> bool:
        """
        Paketleri gonderir.
        
        Args:
            packets: Gonderilecek paketler listesi
            dst_ip: Hedef IP adresi
            dst_port: Hedef port numarasi
            
        Returns:
            bool: Islem basarili ise True, degilse False
        """
        try:
            if not self._socket:
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
                self._socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            for packet in packets:
                self._socket.sendto(bytes(packet), (dst_ip, dst_port))
                time.sleep(0.01)  # Paketler arasi kucuk gecikme
            
            return True
        except Exception as e:
            print(f"Paket gonderme hatasi: {e}")
            return False
    
    def receive_packets(self, timeout: int = 5) -> List[IP]:
        """
        Paketleri alir.
        
        Args:
            timeout: Paket bekleme suresi (saniye)
            
        Returns:
            List[IP]: Alinan paketler listesi
        """
        try:
            if not self._socket:
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                self._socket.bind(('0.0.0.0', 0))
            
            self._socket.settimeout(timeout)
            packets = []
            
            while True:
                try:
                    data, addr = self._socket.recvfrom(65535)
                    packet = IP(data)
                    packets.append(packet)
                except socket.timeout:
                    break
            
            return packets
        except Exception as e:
            print(f"Paket alma hatasi: {e}")
            return []
    
    def close(self):
        """Socket baglantisini kapatir."""
        if self._socket:
            self._socket.close()
            self._socket = None

    def send_test_packet(self, dst_ip: str, dst_port: int, ttl: int = 64, flags: str = "DF") -> bool:
        """
        Test amacli IP paketi gonderir.
        
        Args:
            dst_ip: Hedef IP adresi
            dst_port: Hedef port numarasi
            ttl: Time To Live degeri
            flags: IP bayraklari
            
        Returns:
            bool: Islem basarili ise True, degilse False
        """
        try:
            # Test paketi olustur
            packet = IP(dst=dst_ip, ttl=ttl, flags=flags)/TCP(dport=dst_port)/b"TEST"
            
            # Paketi gonder
            send(packet, verbose=0)
            return True
            
        except Exception as e:
            print(f"Test paketi gonderme hatasi: {e}")
            return False

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