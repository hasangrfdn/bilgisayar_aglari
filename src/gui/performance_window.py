"""
Güvenli Dosya Transfer Sistemi - Performans Ölçüm Penceresi Modülü

Bu modul, ag performans olcumlerini gerceklestiren ve sonuclari
grafiksel olarak gosteren pencereyi saglar. Bant genisligi, gecikme
ve paket kaybi gibi metrikleri olcer ve raporlar.

Kullanim:
    from gui.performance_window import PerformanceWindow
    
    window = PerformanceWindow()
    window.show()
"""

import sys
import time
from typing import Dict, List, Optional
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QSpinBox,
    QGroupBox, QFormLayout, QTextEdit, QMessageBox
)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QFont

from src.network.packet_handler import PacketHandler
from src.core.file_transfer import FileTransfer

class PerformanceWindow(QMainWindow):
    """
    Performans olcum penceresi sinifi.
    
    Bu sinif, ag performans olcumlerini gerceklestirir ve sonuclari
    grafiksel olarak gosterir. Bant genisligi, gecikme ve paket kaybi
    gibi metrikleri olcer ve raporlar.
    """
    
    def __init__(self):
        """
        PerformanceWindow sinifini baslatir.
        
        Pencereyi ve kullanici arayuzu bilesenlerini olusturur,
        olcum zamanlayicisini ayarlar.
        """
        super().__init__()
        self.setWindowTitle("Ag Performans Olcumu")
        self.setMinimumSize(600, 400)
        
        # Ana widget ve layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)
        
        # Hedef ayarlari
        target_group = QGroupBox("Hedef Ayarlari")
        target_layout = QFormLayout()
        
        self.target_ip = QLineEdit()
        self.target_ip.setPlaceholderText("Test edilecek IP adresi")
        target_layout.addRow("IP Adresi:", self.target_ip)
        
        self.target_port = QSpinBox()
        self.target_port.setRange(1024, 65535)
        self.target_port.setValue(5000)
        target_layout.addRow("Port:", self.target_port)
        
        self.test_size = QSpinBox()
        self.test_size.setRange(1, 100)
        self.test_size.setValue(10)
        self.test_size.setSuffix(" MB")
        target_layout.addRow("Test Boyutu:", self.test_size)
        
        target_group.setLayout(target_layout)
        layout.addWidget(target_group)
        
        # Olcum kontrolleri
        control_group = QGroupBox("Olcum Kontrolleri")
        control_layout = QHBoxLayout()
        
        self.start_btn = QPushButton("Olcumu Baslat")
        self.start_btn.clicked.connect(self._start_measurement)
        control_layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("Olcumu Durdur")
        self.stop_btn.clicked.connect(self._stop_measurement)
        self.stop_btn.setEnabled(False)
        control_layout.addWidget(self.stop_btn)
        
        control_group.setLayout(control_layout)
        layout.addWidget(control_group)
        
        # Sonuclar
        result_group = QGroupBox("Olcum Sonuclari")
        result_layout = QVBoxLayout()
        
        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        result_layout.addWidget(self.result_text)
        
        result_group.setLayout(result_layout)
        layout.addWidget(result_group)
        
        # Olcum durumu
        self.measurement_running = False
        self.measurement_timer: Optional[QTimer] = None
        self.packet_handler: Optional[PacketHandler] = None
        self.file_transfer: Optional[FileTransfer] = None
        
        # Sonuclar
        self.results: List[Dict[str, float]] = []
    
    def _start_measurement(self):
        """
        Performans olcumunu baslatir.
        
        Islem adimlari:
        1. Gerekli alanlarin dolu oldugunu kontrol eder
        2. Olcum zamanlayicisini baslatir
        3. Arayuzu gunceller
        """
        if not self.target_ip.text():
            QMessageBox.warning(self, "Hata", "Lutfen IP adresini girin")
            return
        
        self.measurement_running = True
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.result_text.clear()
        self.results.clear()
        
        # Olcum zamanlayicisi
        self.measurement_timer = QTimer()
        self.measurement_timer.timeout.connect(self._perform_measurement)
        self.measurement_timer.start(5000)  # 5 saniyede bir olcum
        
        # Ilk olcumu hemen yap
        self._perform_measurement()
    
    def _stop_measurement(self):
        """
        Performans olcumunu durdurur.
        
        Islem adimlari:
        1. Olcum zamanlayicisini durdurur
        2. Kaynaklari temizler
        3. Arayuzu gunceller
        """
        self.measurement_running = False
        if self.measurement_timer:
            self.measurement_timer.stop()
        
        if self.packet_handler:
            self.packet_handler.close()
            self.packet_handler = None
        
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        
        # Sonuclari ozetle
        if self.results:
            self._show_summary()
    
    def _perform_measurement(self):
        """
        Tek bir performans olcumu gerceklestirir.
        
        Islem adimlari:
        1. Baglanti testi yapar
        2. Bant genisligi olcumu yapar
        3. Sonuclari kaydeder ve gosterir
        """
        try:
            # Baglanti testi
            if not self.packet_handler:
                self.packet_handler = PacketHandler()
            
            test_result = self.packet_handler.test_connection(
                self.target_ip.text(),
                self.target_port.value()
            )
            
            if not test_result['success']:
                raise Exception("Baglanti testi basarisiz")
            
            # Bant genisligi olcumu
            if not self.file_transfer:
                self.file_transfer = FileTransfer()
            
            # Test verisi olustur
            test_data = b"0" * (self.test_size.value() * 1024 * 1024)
            
            # Gonderim hizini olc
            start_time = time.time()
            self.packet_handler.send_packets(
                self.packet_handler.fragment_data(
                    test_data,
                    "0.0.0.0",
                    self.target_ip.text()
                ),
                self.target_ip.text(),
                self.target_port.value()
            )
            end_time = time.time()
            
            # Sonuclari hesapla
            duration = end_time - start_time
            data_size = len(test_data)
            bandwidth = (data_size * 8) / (duration * 1000000)  # Mbps
            
            result = {
                'timestamp': time.time(),
                'bandwidth': bandwidth,
                'latency': test_result['latency'],
                'packet_loss': test_result['packet_loss']
            }
            self.results.append(result)
            
            # Sonuclari goster
            self._update_results(result)
            
        except Exception as e:
            self.result_text.append(f"\nHata: {str(e)}")
            self._stop_measurement()
    
    def _update_results(self, result: Dict[str, float]):
        """
        Olcum sonuclarini gunceller.
        
        Args:
            result: Son olcum sonuclari
        """
        self.result_text.append("\nYeni Olcum Sonuclari:")
        self.result_text.append(f"Zaman: {time.strftime('%H:%M:%S', time.localtime(result['timestamp']))}")
        self.result_text.append(f"Bant Genisligi: {result['bandwidth']:.2f} Mbps")
        self.result_text.append(f"Gecikme: {result['latency']:.2f} ms")
        self.result_text.append(f"Paket Kaybi: {result['packet_loss']:.1f}%")
    
    def _show_summary(self):
        """
        Olcum sonuclarinin ozetini gosterir.
        
        Islem adimlari:
        1. Ortalama degerleri hesaplar
        2. En iyi ve en kotu degerleri bulur
        3. Sonuclari gosterir
        """
        if not self.results:
            return
        
        # Ortalamalari hesapla
        avg_bandwidth = sum(r['bandwidth'] for r in self.results) / len(self.results)
        avg_latency = sum(r['latency'] for r in self.results) / len(self.results)
        avg_packet_loss = sum(r['packet_loss'] for r in self.results) / len(self.results)
        
        # En iyi ve en kotu degerler
        best_bandwidth = max(r['bandwidth'] for r in self.results)
        worst_bandwidth = min(r['bandwidth'] for r in self.results)
        best_latency = min(r['latency'] for r in self.results)
        worst_latency = max(r['latency'] for r in self.results)
        
        self.result_text.append("\n=== OZET ===")
        self.result_text.append(f"Toplam Olcum Sayisi: {len(self.results)}")
        self.result_text.append("\nBant Genisligi:")
        self.result_text.append(f"  Ortalama: {avg_bandwidth:.2f} Mbps")
        self.result_text.append(f"  En Iyi: {best_bandwidth:.2f} Mbps")
        self.result_text.append(f"  En Kotu: {worst_bandwidth:.2f} Mbps")
        
        self.result_text.append("\nGecikme:")
        self.result_text.append(f"  Ortalama: {avg_latency:.2f} ms")
        self.result_text.append(f"  En Iyi: {best_latency:.2f} ms")
        self.result_text.append(f"  En Kotu: {worst_latency:.2f} ms")
        
        self.result_text.append(f"\nOrtalama Paket Kaybi: {avg_packet_loss:.1f}%")
    
    def closeEvent(self, event):
        """
        Pencere kapatilirken calisan olay.
        
        Args:
            event: Kapatma olayi
        """
        self._stop_measurement()
        event.accept()