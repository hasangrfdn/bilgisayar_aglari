"""
Güvenli Dosya Transfer Sistemi - Ana Pencere Modülü

Bu modul, guvenli dosya transfer uygulamasinin grafiksel kullanici
arayuzunu saglar. Dosya gonderme/alma, baglanti testi ve performans
olcum islemlerini yonetir.

Kullanim:
    from gui.main_window import MainWindow
    
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
"""

import os
import sys
import time
from typing import Optional, Dict, Any
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QFileDialog,
    QProgressBar, QMessageBox, QComboBox, QSpinBox,
    QGroupBox, QFormLayout, QTabWidget, QTextEdit
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QIcon

from src.core.file_transfer import FileTransfer
from src.network.packet_handler import PacketHandler
from src.security.auth import Authentication
from src.gui.performance_window import PerformanceWindow

class SecureFileTransfer:
    def __init__(self):
        self.file_transfer = FileTransfer()      # Dosya işlemleri
        self.packet_handler = PacketHandler()    # Ağ işlemleri
        self.auth = Authentication()             # Güvenlik işlemleri

class TransferThread(QThread):
    """
    Dosya transfer islemlerini arka planda yapan thread sinifi.
    
    Bu sinif, dosya gonderme ve alma islemlerini arka planda
    gerceklestirerek ana pencereyi bloklamadan calismasini saglar.
    
    Signals:
        progress_updated: Transfer ilerleme durumu guncellendiginde
        transfer_completed: Transfer tamamlandiginda
        error_occurred: Hata olustugunda
    """
    
    progress_updated = pyqtSignal(int)
    transfer_completed = pyqtSignal(str)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, mode: str, **kwargs):
        """
        TransferThread sinifini baslatir.
        
        Args:
            mode: Transfer modu ('send' veya 'receive')
            **kwargs: Transfer parametreleri
        """
        super().__init__()
        self.mode = mode
        self.kwargs = kwargs
        self.is_running = True
    
    def run(self):
        """
        Thread'in ana calisma metodu.
        
        Secilen moda gore dosya gonderme veya alma islemini
        gerceklestirir ve ilerleme durumunu raporlar.
        """
        try:
            if self.mode == 'send':
                self._send_file()
            else:
                self._receive_file()
        except Exception as e:
            self.error_occurred.emit(str(e))
    
    def _send_file(self):
        """
        Dosya gonderme islemini gerceklestirir.
        
        Islem adimlari:
        1. Dosya transfer nesnesini olusturur
        2. Dosyayi hazirlar ve gonderir
        3. Ilerleme durumunu raporlar
        """
        transfer = FileTransfer(
            self.kwargs['src_file'],
            self.kwargs['dst_ip'],
            self.kwargs['dst_port'],
            self.kwargs['password']
        )
        
        def progress_callback(progress: int):
            if self.is_running:
                self.progress_updated.emit(progress)
        
        transfer.send_file(progress_callback)
        self.transfer_completed.emit("Dosya basariyla gonderildi")
    
    def _receive_file(self):
        """
        Dosya alma islemini gerceklestirir.
        
        Islem adimlari:
        1. Dosya transfer nesnesini olusturur
        2. Dosyayi alir ve kaydeder
        3. Ilerleme durumunu raporlar
        """
        transfer = FileTransfer(
            output_dir=self.kwargs['output_dir'],
            password=self.kwargs['password']
        )
        
        def progress_callback(progress: int):
            if self.is_running:
                self.progress_updated.emit(progress)
        
        transfer.receive_file(
            self.kwargs['listen_port'],
            progress_callback
        )
        self.transfer_completed.emit("Dosya basariyla alindi")
    
    def stop(self):
        """
        Thread'i durdurur.
        """
        self.is_running = False

class MainWindow(QMainWindow):
    """
    Ana pencere sinifi.
    
    Bu sinif, uygulamanin ana penceresini ve kullanici arayuzunu
    yonetir. Dosya transfer, baglanti testi ve performans olcum
    islemlerini kullaniciya sunar.
    """
    
    def __init__(self):
        """
        MainWindow sinifini baslatir.
        
        Pencereyi ve kullanici arayuzu bilesenlerini olusturur,
        sinyal-baglanti islemlerini yapar.
        """
        super().__init__()
        self.setWindowTitle("Guvenli Dosya Transfer Sistemi")
        self.setMinimumSize(800, 600)
        
        # Ana widget ve layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)
        
        # Tab widget
        tab_widget = QTabWidget()
        layout.addWidget(tab_widget)
        
        # Transfer tab'i
        transfer_tab = QWidget()
        transfer_layout = QVBoxLayout(transfer_tab)
        
        # Dosya gonderme grubu
        send_group = QGroupBox("Dosya Gonderme")
        send_layout = QFormLayout()
        
        self.file_path = QLineEdit()
        self.file_path.setReadOnly(True)
        browse_btn = QPushButton("Dosya Sec")
        browse_btn.clicked.connect(self._browse_file)
        
        file_layout = QHBoxLayout()
        file_layout.addWidget(self.file_path)
        file_layout.addWidget(browse_btn)
        send_layout.addRow("Dosya:", file_layout)
        
        self.dst_ip = QLineEdit()
        self.dst_ip.setPlaceholderText("Hedef IP adresi")
        send_layout.addRow("Hedef IP:", self.dst_ip)
        
        self.dst_port = QSpinBox()
        self.dst_port.setRange(1024, 65535)
        self.dst_port.setValue(5000)
        send_layout.addRow("Hedef Port:", self.dst_port)
        
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.Password)
        self.password.setPlaceholderText("Sifre")
        send_layout.addRow("Sifre:", self.password)
        
        self.send_btn = QPushButton("Gonder")
        self.send_btn.clicked.connect(self._send_file)
        send_layout.addRow("", self.send_btn)
        
        send_group.setLayout(send_layout)
        transfer_layout.addWidget(send_group)
        
        # Dosya alma grubu
        receive_group = QGroupBox("Dosya Alma")
        receive_layout = QFormLayout()
        
        self.listen_port = QSpinBox()
        self.listen_port.setRange(1024, 65535)
        self.listen_port.setValue(5000)
        receive_layout.addRow("Dinleme Portu:", self.listen_port)
        
        self.receive_password = QLineEdit()
        self.receive_password.setEchoMode(QLineEdit.Password)
        self.receive_password.setPlaceholderText("Sifre")
        receive_layout.addRow("Sifre:", self.receive_password)
        
        self.output_dir = QLineEdit()
        self.output_dir.setReadOnly(True)
        self.output_dir.setText("received_files")
        output_btn = QPushButton("Klasor Sec")
        output_btn.clicked.connect(self._browse_output_dir)
        
        output_layout = QHBoxLayout()
        output_layout.addWidget(self.output_dir)
        output_layout.addWidget(output_btn)
        receive_layout.addRow("Kayit Klasoru:", output_layout)
        
        self.receive_btn = QPushButton("Al")
        self.receive_btn.clicked.connect(self._receive_file)
        receive_layout.addRow("", self.receive_btn)
        
        receive_group.setLayout(receive_layout)
        transfer_layout.addWidget(receive_group)
        
        # Ilerleme cubugu
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        transfer_layout.addWidget(self.progress_bar)
        
        # Durum mesaji
        self.status_label = QLabel()
        self.status_label.setAlignment(Qt.AlignCenter)
        transfer_layout.addWidget(self.status_label)
        
        tab_widget.addTab(transfer_tab, "Dosya Transfer")
        
        # Baglanti testi tab'i
        test_tab = QWidget()
        test_layout = QVBoxLayout(test_tab)
        
        test_group = QGroupBox("Baglanti Testi")
        test_form = QFormLayout()
        
        self.test_ip = QLineEdit()
        self.test_ip.setPlaceholderText("Test edilecek IP adresi")
        test_form.addRow("IP Adresi:", self.test_ip)
        
        self.test_port = QSpinBox()
        self.test_port.setRange(1024, 65535)
        self.test_port.setValue(5000)
        test_form.addRow("Port:", self.test_port)
        
        self.test_btn = QPushButton("Test Et")
        self.test_btn.clicked.connect(self._test_connection)
        test_form.addRow("", self.test_btn)
        
        self.test_result = QTextEdit()
        self.test_result.setReadOnly(True)
        test_form.addRow("Sonuc:", self.test_result)
        
        test_group.setLayout(test_form)
        test_layout.addWidget(test_group)
        
        tab_widget.addTab(test_tab, "Baglanti Testi")
        
        # Performans olcum tab'i
        self.performance_btn = QPushButton("Performans Olcum Penceresi")
        self.performance_btn.clicked.connect(self._show_performance_window)
        layout.addWidget(self.performance_btn)
        
        # Transfer thread'i
        self.transfer_thread: Optional[TransferThread] = None
    
    def _browse_file(self):
        """
        Dosya secme dialogunu acar.
        """
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Dosya Sec",
            "",
            "Tum Dosyalar (*.*)"
        )
        if file_path:
            self.file_path.setText(file_path)
    
    def _browse_output_dir(self):
        """
        Kayit klasoru secme dialogunu acar.
        """
        dir_path = QFileDialog.getExistingDirectory(
            self,
            "Kayit Klasoru Sec",
            self.output_dir.text()
        )
        if dir_path:
            self.output_dir.setText(dir_path)
    
    def _send_file(self):
        """
        Dosya gonderme islemini baslatir.
        
        Islem adimlari:
        1. Gerekli alanlarin dolu oldugunu kontrol eder
        2. Transfer thread'ini baslatir
        3. Arayuzu gunceller
        """
        if not self.file_path.text():
            QMessageBox.warning(self, "Hata", "Lutfen bir dosya secin")
            return
        
        if not self.dst_ip.text():
            QMessageBox.warning(self, "Hata", "Lutfen hedef IP adresini girin")
            return
        
        if not self.password.text():
            QMessageBox.warning(self, "Hata", "Lutfen sifre girin")
            return
        
        self.send_btn.setEnabled(False)
        self.receive_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.status_label.setText("Dosya gonderiliyor...")
        
        self.transfer_thread = TransferThread(
            'send',
            src_file=self.file_path.text(),
            dst_ip=self.dst_ip.text(),
            dst_port=self.dst_port.value(),
            password=self.password.text()
        )
        
        self.transfer_thread.progress_updated.connect(self._update_progress)
        self.transfer_thread.transfer_completed.connect(self._transfer_completed)
        self.transfer_thread.error_occurred.connect(self._transfer_error)
        self.transfer_thread.start()
    
    def _receive_file(self):
        """
        Dosya alma islemini baslatir.
        
        Islem adimlari:
        1. Gerekli alanlarin dolu oldugunu kontrol eder
        2. Transfer thread'ini baslatir
        3. Arayuzu gunceller
        """
        if not self.receive_password.text():
            QMessageBox.warning(self, "Hata", "Lutfen sifre girin")
            return
        
        self.send_btn.setEnabled(False)
        self.receive_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.status_label.setText("Dosya aliniyor...")
        
        self.transfer_thread = TransferThread(
            'receive',
            listen_port=self.listen_port.value(),
            output_dir=self.output_dir.text(),
            password=self.receive_password.text()
        )
        
        self.transfer_thread.progress_updated.connect(self._update_progress)
        self.transfer_thread.transfer_completed.connect(self._transfer_completed)
        self.transfer_thread.error_occurred.connect(self._transfer_error)
        self.transfer_thread.start()
    
    def _update_progress(self, value: int):
        """
        Ilerleme cubugunu gunceller.
        
        Args:
            value: Yeni ilerleme degeri (0-100)
        """
        self.progress_bar.setValue(value)
    
    def _transfer_completed(self, message: str):
        """
        Transfer tamamlandiginda arayuzu gunceller.
        
        Args:
            message: Tamamlanma mesaji
        """
        self.send_btn.setEnabled(True)
        self.receive_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.status_label.setText(message)
        QMessageBox.information(self, "Bilgi", message)
    
    def _transfer_error(self, error: str):
        """
        Transfer hatasi durumunda arayuzu gunceller.
        
        Args:
            error: Hata mesaji
        """
        self.send_btn.setEnabled(True)
        self.receive_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.status_label.setText(f"Hata: {error}")
        QMessageBox.critical(self, "Hata", error)
    
    def _test_connection(self):
        """
        Baglanti testi islemini gerceklestirir.
        
        Islem adimlari:
        1. Gerekli alanlarin dolu oldugunu kontrol eder
        2. Baglanti testini gerceklestirir
        3. Sonuclari gosterir
        """
        if not self.test_ip.text():
            QMessageBox.warning(self, "Hata", "Lutfen IP adresini girin")
            return
        
        self.test_btn.setEnabled(False)
        self.test_result.clear()
        self.test_result.append("Baglanti testi yapiliyor...")
        
        try:
            handler = PacketHandler()
            result = handler.test_connection(
                self.test_ip.text(),
                self.test_port.value()
            )
            
            self.test_result.append("\nTest Sonuclari:")
            self.test_result.append(f"Baglanti Durumu: {'Basarili' if result['success'] else 'Basarisiz'}")
            self.test_result.append(f"Gecikme: {result['latency']:.2f} ms")
            self.test_result.append(f"Paket Kaybi: {result['packet_loss']:.1f}%")
            
            if result['success']:
                self.test_result.append("\nBaglanti detaylari:")
                self.test_result.append(f"Yerel IP: {result['local_ip']}")
                self.test_result.append(f"Yerel Port: {result['local_port']}")
                self.test_result.append(f"Uzak IP: {result['remote_ip']}")
                self.test_result.append(f"Uzak Port: {result['remote_port']}")
            
        except Exception as e:
            self.test_result.append(f"\nHata: {str(e)}")
        finally:
            self.test_btn.setEnabled(True)
    
    def _show_performance_window(self):
        """
        Performans olcum penceresini acar.
        """
        self.performance_window = PerformanceWindow()
        self.performance_window.show()
    
    def closeEvent(self, event):
        """
        Pencere kapatilirken calisan olay.
        
        Args:
            event: Kapatma olayi
        """
        if self.transfer_thread and self.transfer_thread.isRunning():
            self.transfer_thread.stop()
            self.transfer_thread.wait()
        event.accept()

def main():
    from PyQt5.QtWidgets import QApplication
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_()) 