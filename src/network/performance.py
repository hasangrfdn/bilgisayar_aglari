"""
Ag Performans Analiz Modulu

Bu modul, ag performans olcumleri icin gerekli fonksiyonlari icerir.
Gecikme, bant genisligi, paket kaybi ve ag kullanim istatistiklerini
olcer ve raporlar.

Kullanim:
    from network.performance import NetworkPerformance
    
    perf = NetworkPerformance()
    latency = perf.measure_latency("192.168.1.1")
    bandwidth = perf.measure_bandwidth("192.168.1.1")
"""

import subprocess
import time
import statistics
from typing import List, Dict, Tuple
import psutil
import netifaces
from scapy.all import sr1, IP, ICMP, TCP
import socket
import os

class NetworkPerformance:
    """
    Ag performans analizi ve olcum sinifi.
    
    Bu sinif, ag performans metriklerini olcmek ve analiz etmek icin
    cesitli yontemler sunar. ICMP, TCP ve iPerf gibi araclari kullanarak
    detayli performans analizi yapar.
    """
    
    def __init__(self):
        """Arayuz listesini baslatir."""
        self._interfaces = netifaces.interfaces()
    
    def get_interface_info(self) -> Dict[str, Dict]:
        """
        Ag arayuzlerinin bilgilerini dondurur.
        
        Returns:
            Dict[str, Dict]: Arayuz bilgileri
                - ip: IP adresi
                - netmask: Ag maskesi
                - broadcast: Yayin adresi
        """
        info = {}
        for iface in self._interfaces:
            try:
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    info[iface] = {
                        'ip': addrs[netifaces.AF_INET][0]['addr'],
                        'netmask': addrs[netifaces.AF_INET][0]['netmask'],
                        'broadcast': addrs[netifaces.AF_INET][0].get('broadcast', '')
                    }
            except Exception:
                continue
        return info
    
    def measure_latency(self, target: str, count: int = 4) -> Tuple[float, float, float]:
        """
        Hedef adrese ping atarak gecikme olcumu yapar.
        
        Args:
            target: Hedef IP adresi
            count: Ping sayisi
            
        Returns:
            Tuple[float, float, float]: (ortalama, medyan, standart sapma) gecikme degerleri (ms)
        """
        latencies = []
        
        for _ in range(count):
            try:
                # ICMP paketi olustur
                packet = IP(dst=target)/ICMP()
                
                # Paketi gonder ve yanit bekle
                start_time = time.time()
                reply = sr1(packet, timeout=2, verbose=0)
                end_time = time.time()
                
                if reply:
                    rtt = (end_time - start_time) * 1000  # milisaniye
                    latencies.append(rtt)
                
                time.sleep(0.2)  # Paketler arasi bekleme
            
            except Exception:
                continue
        
        if not latencies:
            return 0.0, 0.0, 0.0
        
        return (
            statistics.mean(latencies),  # Ortalama
            statistics.median(latencies),  # Medyan
            statistics.stdev(latencies) if len(latencies) > 1 else 0.0  # Standart sapma
        )
    
    def measure_bandwidth(self, target: str, duration: int = 10) -> Tuple[float, float]:
        """
        iPerf ile bant genisligi olcumu yapar.
        
        Args:
            target: Hedef IP adresi
            duration: Test suresi (saniye)
            
        Returns:
            Tuple[float, float]: (alma, gonderme) bant genisligi degerleri (Mbps)
        """
        try:
            # iPerf sunucusunu baslat
            server = subprocess.Popen(
                ['iperf3', '-s'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            time.sleep(1)  # Sunucunun baslamasini bekle
            
            # iPerf istemcisini calistir
            client = subprocess.Popen(
                ['iperf3', '-c', target, '-t', str(duration), '-J'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Sonuclari al
            stdout, stderr = client.communicate()
            
            if client.returncode == 0:
                import json
                result = json.loads(stdout)
                return (
                    result['end']['streams'][0]['receiver']['bits_per_second'] / 1e6,  # Mbps
                    result['end']['streams'][0]['sender']['bits_per_second'] / 1e6  # Mbps
                )
            
            return 0.0, 0.0
        
        except Exception as e:
            print(f"Bant genisligi olcum hatasi: {e}")
            return 0.0, 0.0
        
        finally:
            # Sunucuyu sonlandir
            try:
                server.terminate()
                server.wait(timeout=5)
            except:
                server.kill()
    
    def simulate_packet_loss(self, target: str, packet_count: int = 100) -> float:
        """
        Paket kaybi simulasyonu yapar.
        
        Args:
            target: Hedef IP adresi
            packet_count: Gonderilecek paket sayisi
            
        Returns:
            float: Paket kaybi orani (%)
        """
        lost_packets = 0
        
        for _ in range(packet_count):
            try:
                # TCP SYN paketi olustur
                packet = IP(dst=target)/TCP(dport=80, flags='S')
                
                # Paketi gonder ve yanit bekle
                reply = sr1(packet, timeout=1, verbose=0)
                
                if not reply:
                    lost_packets += 1
                
                time.sleep(0.1)  # Paketler arasi bekleme
            
            except Exception:
                lost_packets += 1
        
        return (lost_packets / packet_count) * 100  # Yuzde olarak kayip orani
    
    def get_network_usage(self) -> Dict[str, float]:
        """
        Ag arayuzlerinin kullanim istatistiklerini dondurur.
        
        Returns:
            Dict[str, float]: Arayuz kullanim istatistikleri
                - bytes_sent: Gonderilen veri (KB/s)
                - bytes_recv: Alinan veri (KB/s)
                - packets_sent: Gonderilen paket sayisi
                - packets_recv: Alinan paket sayisi
        """
        stats = psutil.net_io_counters(pernic=True)
        usage = {}
        
        for iface in self._interfaces:
            if iface in stats:
                # Son 1 saniyedeki degisimi hesapla
                current = stats[iface]
                time.sleep(1)
                new = psutil.net_io_counters(pernic=True)[iface]
                
                usage[iface] = {
                    'bytes_sent': (new.bytes_sent - current.bytes_sent) / 1024,  # KB/s
                    'bytes_recv': (new.bytes_recv - current.bytes_recv) / 1024,  # KB/s
                    'packets_sent': new.packets_sent - current.packets_sent,
                    'packets_recv': new.packets_recv - current.packets_recv
                }
        
        return usage
    
    def measure_simple_bandwidth(self, target: str, port: int = 5000, test_size: int = 1024 * 1024) -> float:
        """
        Basit dosya transfer testi ile bant genisligi olcumu yapar.
        
        Args:
            target: Hedef IP adresi
            port: Hedef port numarasi
            test_size: Test verisi boyutu (byte)
            
        Returns:
            float: Olculen bant genisligi (Mbps)
        """
        try:
            start_time = time.time()
            test_data = b'0' * test_size
            
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((target, port))
                s.send(test_data)
            
            end_time = time.time()
            duration = end_time - start_time
            bandwidth = (test_size / duration) / (1024 * 1024)  # MB/s
            return bandwidth * 8  # Mbps'e cevirme
            
        except Exception as e:
            print(f"Basit bant genisligi olcum hatasi: {e}")
            return 0.0

    def measure_simple_latency(self, target: str) -> float:
        """
        Ping komutu ile gecikme olcumu yapar.
        
        Args:
            target: Hedef IP adresi
            
        Returns:
            float: Olculen gecikme (ms)
        """
        try:
            start_time = time.time()
            if os.name == 'nt':  # Windows
                os.system(f"ping -n 1 {target} > nul")
            else:  # Linux/Unix
                os.system(f"ping -c 1 {target} > /dev/null")
            return (time.time() - start_time) * 1000  # milisaniye
            
        except Exception as e:
            print(f"Basit gecikme olcum hatasi: {e}")
            return 0.0

    def analyze_connection(self, target: str, port: int = 80) -> Dict:
        """
        Hedef baglantisinin detayli analizini yapar.
        
        Args:
            target: Hedef IP adresi
            port: Hedef port numarasi
            
        Returns:
            Dict: Analiz sonuclari
                - latency: Gecikme metrikleri
                - tcp: TCP baglanti durumu
                - bandwidth: Bant genisligi olcumleri
                - packet_loss: Paket kaybi orani
        """
        results = {}
        
        # Gecikme olcumu (hem ICMP hem ping)
        avg_latency, median_latency, std_latency = self.measure_latency(target)
        simple_latency = self.measure_simple_latency(target)
        
        results['latency'] = {
            'average': avg_latency,
            'median': median_latency,
            'std_dev': std_latency,
            'ping': simple_latency
        }
        
        # TCP baglanti testi
        try:
            packet = IP(dst=target)/TCP(dport=port, flags='S')
            reply = sr1(packet, timeout=2, verbose=0)
            
            if reply and reply.haslayer(TCP):
                results['tcp'] = {
                    'status': 'open' if reply[TCP].flags == 0x12 else 'closed',
                    'ttl': reply.ttl,
                    'window': reply[TCP].window
                }
            else:
                results['tcp'] = {'status': 'filtered'}
        
        except Exception as e:
            results['tcp'] = {'status': 'error', 'error': str(e)}
        
        # Bant genisligi olcumu (hem iPerf hem basit test)
        rx_bw, tx_bw = self.measure_bandwidth(target, duration=5)
        simple_bw = self.measure_simple_bandwidth(target, port)
        
        results['bandwidth'] = {
            'receive': rx_bw,
            'transmit': tx_bw,
            'simple_test': simple_bw
        }
        
        # Paket kaybi
        results['packet_loss'] = self.simulate_packet_loss(target, packet_count=50)
        
        return results 