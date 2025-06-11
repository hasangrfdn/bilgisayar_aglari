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
import json
import base64
from typing import Optional, Dict, Any
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QFileDialog,
    QProgressBar, QMessageBox, QComboBox, QSpinBox,
    QGroupBox, QFormLayout, QTabWidget, QTextEdit
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QIcon

from src.core.file_transfer import FileTransfer, FileMetadata
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
    
    def __init__(self, mode: str, file_transfer_instance: FileTransfer, packet_handler_instance: PacketHandler, auth_instance: Authentication, **kwargs):
        """
        TransferThread sinifini baslatir.
        
        Args:
            mode: Transfer modu ('send' veya 'receive')
            file_transfer_instance: Dosya transfer nesnesi
            packet_handler_instance: Paket işlemleri nesnesi
            auth_instance: Güvenlik işlemleri nesnesi
            **kwargs: Transfer parametreleri
        """
        super().__init__()
        self.mode = mode
        self.file_transfer = file_transfer_instance
        self.packet_handler = packet_handler_instance
        self.auth = auth_instance
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
        src_file = self.kwargs['src_file']
        dst_ip = self.kwargs['dst_ip']
        dst_port = self.kwargs['dst_port']
        password = self.kwargs['password']

        try:
            # 1. Dosyayı şifrele ve meta verilerini al
            metadata, encrypted_data = self.file_transfer.prepare_file(src_file, password)
            
            # 2. Meta verilerini JSON'a dönüştür ve kodla
            metadata_json = json.dumps({
                "filename": metadata.filename,
                "size": metadata.size,
                "checksum": metadata.checksum,
                "encryption_key": base64.urlsafe_b64encode(metadata.encryption_key).decode('utf-8'),
                "iv": base64.urlsafe_b64encode(metadata.iv).decode('utf-8')
            }).encode('utf-8')

            # 3. Meta verilerini parçala ve gönder
            local_ip = "127.0.0.1" 
            
            # Bağlantıyı kur
            if not self.packet_handler.connect_to_host(dst_ip, dst_port):
                raise Exception("Hedefe bağlantı kurulamadı.")

            metadata_to_send = self.packet_handler.fragment_data(metadata_json, local_ip, dst_ip, dst_port)
            self.packet_handler.send_packets(metadata_to_send)

            # Küçük bir bekleme, meta verilerin önce ulaşmasını sağlamak için
            time.sleep(0.1) 
            
            # 4. Şifrelenmiş veriyi gönder
            data_to_send = self.packet_handler.fragment_data(encrypted_data, local_ip, dst_ip, dst_port)

            total_bytes = len(data_to_send)
            bytes_sent_so_far = 0
            chunk_size = 4096 # Örneğin 4KB'lik parçalar halinde ilerleme gösterelim

            # İlerleme çubuğunu güncellemek için
            while bytes_sent_so_far < total_bytes:
                if not self.is_running:
                    break
                
                current_chunk = data_to_send[bytes_sent_so_far : bytes_sent_so_far + chunk_size]
                
                # Sadece ilerleme için, gerçek gönderme PacketHandler içinde
                self.progress_updated.emit(int((bytes_sent_so_far + len(current_chunk)) / total_bytes * 100))
                bytes_sent_so_far += len(current_chunk)
                time.sleep(0.001) # Çok hızlı olmamak için küçük bir bekleme

            success = self.packet_handler.send_packets(data_to_send)
            if not success:
                raise Exception("Dosya gönderme başarısız oldu.")
            
            self.transfer_completed.emit("Dosya başarıyla gönderildi")

        except Exception as e:
            self.error_occurred.emit(f"Gönderme hatası: {e}")
        finally:
            self.packet_handler.close() # Soketleri kapat
    
    def _receive_file(self):
        """
        Dosya alma işlemini gerçekleştirir.
        
        İşlem adımları:
        1. Dosya transfer nesnesini oluşturur
        2. Dosyayı alır ve kaydeder
        3. İlerleme durumunu raporlar
        """
        listen_port = self.kwargs['listen_port']
        password = self.kwargs['password']
        output_dir = self.kwargs['output_dir']

        try:
            print(f"[{listen_port}] portunda dinlemeye başlanıyor...")
            # Dinlemeye başla ve bağlantıyı kabul et
            if not self.packet_handler.start_listening(listen_port, timeout=30):
                raise Exception(f"[{listen_port}] portunda dinleme başlatılamadı.")
            
            print("Bağlantı kabul edilmesi bekleniyor...")
            if not self.packet_handler.accept_connection(timeout=30):
                raise Exception("Bağlantı kabul edilemedi veya zaman aşımı.")

            print("Meta veri paketleri bekleniyor...")
            # 1. Önce meta veri paketlerini al
            # İlk başta kısa bir süre meta veriler için dinle
            metadata_bytes = self.packet_handler.receive_packets(timeout=10)
            if not metadata_bytes:
                raise Exception("Meta veri paketleri alınamadı veya zaman aşımı!")
            
            print("Meta veriler alındı, dosya verileri bekleniyor...")
            metadata_dict = json.loads(metadata_bytes.decode('utf-8'))
            
            # Metadata'yı FileMetadata objesine dönüştür
            metadata = FileMetadata(
                filename=metadata_dict["filename"],
                size=metadata_dict["size"],
                checksum=metadata_dict["checksum"],
                encryption_key=base64.urlsafe_b64decode(metadata_dict["encryption_key"]),
                iv=base64.urlsafe_b64decode(metadata_dict["iv"])
            )

            # 2. Sonra dosya veri paketlerini al
            # Metadata alındıktan sonra daha uzun süre dosya için dinle
            encrypted_data = self.packet_handler.receive_packets(timeout=120)
            if not encrypted_data:
                raise Exception("Dosya veri paketleri alınamadı veya zaman aşımı!")
            print("Dosya verileri alındı.")
            
            # 3. Dosyayı kaydet ve şifresini çöz
            final_output_path = self.file_transfer.save_file(encrypted_data, metadata, output_dir)
            
            # Kaydedilen şifreli dosyayı çöz
            decrypted_data = self.file_transfer.decrypt_file(final_output_path, metadata)
            
            # Çözülmüş veriyi tekrar orjinal dosya adıyla kaydet (veya geçici bir isimle)
            decrypted_filepath = os.path.join(output_dir, f"decrypted_{metadata.filename}")
            with open(decrypted_filepath, 'wb') as f:
                f.write(decrypted_data)
            
            self.transfer_completed.emit(f"Dosya başarıyla alındı ve çözüldü: {decrypted_filepath}")

        except Exception as e:
            self.error_occurred.emit(f"Alma hatası: {e}")
        finally:
            self.packet_handler.close() # Soketleri kapat
    
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
        
        # Ana bileşenlerin örneklerini oluştur
        self.file_transfer = FileTransfer()
        self.packet_handler = PacketHandler()
        self.auth = Authentication()
        
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
        try:
            file_path = self.file_path.text()
            dst_ip = self.dst_ip.text()
            dst_port = self.dst_port.value()
            password = self.password.text()

            if not file_path or not dst_ip or not password:
                QMessageBox.warning(self, "Hata", "Lutfen tum alanlari doldurun.")
                return
            
            # Onceki thread'i durdur
            if self.transfer_thread and self.transfer_thread.isRunning():
                self.transfer_thread.stop()
                self.transfer_thread.wait()

            self.transfer_thread = TransferThread(
                'send',
                self.file_transfer,
                self.packet_handler,
                self.auth,
                src_file=file_path,
                dst_ip=dst_ip,
                dst_port=dst_port,
                password=password
            )
            self.transfer_thread.progress_updated.connect(self._update_progress)
            self.transfer_thread.transfer_completed.connect(self._transfer_completed)
            self.transfer_thread.error_occurred.connect(self._transfer_error)
            self.transfer_thread.start()
            self.send_btn.setEnabled(False)
            self.receive_btn.setEnabled(False)
            self.progress_bar.setValue(0)
            self.status_label.setText("Dosya gonderiliyor...")

        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Dosya gonderme baslatilamadi: {e}")
            print(f"Dosya gonderme baslatma hatasi: {e}") # Debug print
    
    def _receive_file(self):
        """
        Dosya alma islemini baslatir.
        
        Islem adimlari:
        1. Gerekli alanlarin dolu oldugunu kontrol eder
        2. Transfer thread'ini baslatir
        3. Arayuzu gunceller
        """
        try:
            listen_port = self.listen_port.value()
            password = self.receive_password.text()
            output_dir = self.output_dir.text()

            if not password or not output_dir:
                QMessageBox.warning(self, "Hata", "Lutfen sifre ve kayit klasorunu doldurun.")
                return
            
            # Onceki thread'i durdur
            if self.transfer_thread and self.transfer_thread.isRunning():
                self.transfer_thread.stop()
                self.transfer_thread.wait()

            self.transfer_thread = TransferThread(
                'receive',
                self.file_transfer,
                self.packet_handler,
                self.auth,
                listen_port=listen_port,
                output_dir=output_dir,
                password=password
            )
            self.transfer_thread.progress_updated.connect(self._update_progress)
            self.transfer_thread.transfer_completed.connect(self._transfer_completed)
            self.transfer_thread.error_occurred.connect(self._transfer_error)
            self.transfer_thread.start()
            self.send_btn.setEnabled(False)
            self.receive_btn.setEnabled(False)
            self.progress_bar.setValue(0)
            self.status_label.setText("Dosya bekleniyor...")

        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Dosya alma baslatilamadi: {e}")
            print(f"Dosya alma baslatma hatasi: {e}") # Debug print
    
    def _update_progress(self, value: int):
        """
        Transfer ilerleme durumunu gunceller.
        """
        self.progress_bar.setValue(value)
        self.status_label.setText(f"Ilerleme: %{value}")
    
    def _transfer_completed(self, message: str):
        """
        Transfer tamamlandiginda calisir.
        """
        QMessageBox.information(self, "Bilgi", message)
        self.status_label.setText(message)
        self.send_btn.setEnabled(True)
        self.receive_btn.setEnabled(True)
        self.progress_bar.setValue(100)
        if self.transfer_thread: # Stop thread explicitly if not already stopped
            self.transfer_thread.stop()
            self.transfer_thread.wait()
    
    def _transfer_error(self, error: str):
        """
        Transfer sirasinda hata olustugunda calisir.
        """
        QMessageBox.critical(self, "Hata", error)
        self.status_label.setText(f"Hata: {error}")
        self.send_btn.setEnabled(True)
        self.receive_btn.setEnabled(True)
        self.progress_bar.setValue(0)
        if self.transfer_thread: # Stop thread explicitly if not already stopped
            self.transfer_thread.stop()
            self.transfer_thread.wait()
    
    def _test_connection(self):
        """
        Baglanti testi islemini baslatir.
        """
        target_ip = self.test_ip.text()
        target_port = self.test_port.value()

        if not target_ip:
            QMessageBox.warning(self, "Hata", "Lutfen hedef IP adresini girin.")
            return
        
        try:
            self.test_status_label.setText("Baglanti test ediliyor...")
            result = self.packet_handler.test_connection(target_ip, target_port)
            
            status = result.get("status", "BILINMIYOR")
            message = result.get("message", "Bilinmeyen hata.")
            ping_avg = result.get("ping_avg_ms", "N/A")
            packet_loss = result.get("packet_loss_percent", "N/A")

            if status == "BASARILI":
                self.test_status_label.setText(f"Baglanti basarili! Ping: {ping_avg} ms, Paket Kaybi: {packet_loss}%")
            else:
                self.test_status_label.setText(f"Baglanti basarisiz: {message}")
                
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Baglanti testi sirasinda hata: {e}")
            self.test_status_label.setText(f"Hata: {e}")
            print(f"Baglanti testi hatasi: {e}") # Debug print
    
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