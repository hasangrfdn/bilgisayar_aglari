"""
Güvenli Dosya Transfer Sistemi - Dosya Transfer Modülü

Bu modul, dosyalarin guvenli bir sekilde transfer edilmesi icin gerekli
fonksiyonlari icerir. Dosyalarin sifrelenmesi, cozulmesi ve butunluk
kontrolu islemlerini yonetir.

Kullanim:
    from core.file_transfer import FileTransfer, FileMetadata
    
    # Dosya gonderme
    transfer = FileTransfer()
    metadata, encrypted_data = transfer.prepare_file("dosya.txt", "sifre")
    
    # Dosya alma
    transfer.save_file(encrypted_data, metadata, "alınan_dosyalar")
"""

import os
import json
import time
import base64
from typing import Dict, Any, Optional, Tuple
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

# Mutlak import kullanımı
from src.network.packet_handler import PacketHandler
from src.security.auth import Authentication
from dataclasses import dataclass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

@dataclass
class FileMetadata:
    """
    Dosya meta verilerini tutan sinif.
    
    Bu sinif, transfer edilen dosyanin temel ozelliklerini ve
    guvenlik bilgilerini icerir.
    
    Attributes:
        filename: Dosya adi
        size: Dosya boyutu (byte)
        checksum: SHA-256 ile hesaplanan dosya ozeti
        encryption_key: Sifreleme anahtari
        iv: Baslangic vektoru (salt)
    """
    filename: str
    size: int
    checksum: str
    encryption_key: bytes
    iv: bytes

class FileTransfer:
    """
    Guvenli dosya transfer islemlerini yoneten sinif.
    
    Bu sinif, dosyalarin sifrelenmesi, cozulmesi ve transfer
    edilmesi icin gerekli tum islemleri yonetir. PBKDF2 ile
    anahtar uretimi ve Fernet ile sifreleme kullanir.
    """
    
    def __init__(self, chunk_size: int = 1024 * 1024):  # 1MB varsayilan chunk boyutu
        """
        FileTransfer sinifini baslatir.
        
        Args:
            chunk_size: Dosya okuma/yazma islemlerinde kullanilacak
                       parca boyutu (byte)
        """
        self.chunk_size = chunk_size
        self._fernet: Optional[Fernet] = None
    
    def _generate_key(self, password: str, salt: bytes) -> bytes:
        """
        PBKDF2 ile sifreleme anahtari uretir.
        
        Args:
            password: Kullanici sifresi
            salt: Rastgele uretilen tuz degeri
            
        Returns:
            bytes: Base64 ile kodlanmis sifreleme anahtari
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,  # Guvenlik icin yuksek iterasyon sayisi
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    def prepare_file(self, filepath: str, password: str) -> Tuple[FileMetadata, bytes]:
        """
        Dosyayi sifreler ve meta verileri hazirlar.
        
        Islem adimlari:
        1. Dosya varligini kontrol eder
        2. Meta verileri olusturur
        3. Sifreleme anahtari uretir
        4. Dosyayi sifreler
        5. Checksum hesaplar
        
        Args:
            filepath: Sifrelenecek dosyanin yolu
            password: Sifreleme anahtari icin kullanilacak sifre
            
        Returns:
            Tuple[FileMetadata, bytes]: Meta veriler ve sifrelenmis dosya
            
        Raises:
            FileNotFoundError: Dosya bulunamazsa
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Dosya bulunamadi: {filepath}")
        
        # Dosya meta verilerini olustur
        filename = os.path.basename(filepath)
        size = os.path.getsize(filepath)
        
        # Sifreleme anahtarini olustur
        salt = os.urandom(16)  # 16 byte rastgele tuz
        key = self._generate_key(password, salt)
        self._fernet = Fernet(key)
        
        # Dosyayi sifrele
        with open(filepath, 'rb') as f:
            data = f.read()
            encrypted_data = self._fernet.encrypt(data)
        
        # SHA-256 ile checksum hesapla
        digest = hashes.Hash(hashes.SHA256())
        digest.update(encrypted_data)
        checksum = digest.finalize().hex()
        
        metadata = FileMetadata(
            filename=filename,
            size=size,
            checksum=checksum,
            encryption_key=key,
            iv=salt
        )
        
        return metadata, encrypted_data
    
    def save_file(self, data: bytes, metadata: FileMetadata, output_dir: str) -> str:
        """
        Sifrelenmis dosyayi kaydeder ve butunlugunu dogrular.
        
        Islem adimlari:
        1. Cikis dizinini olusturur
        2. Dosyayi kaydeder
        3. Checksum dogrulamasi yapar
        4. Hatali dosyayi siler
        
        Args:
            data: Kaydedilecek sifrelenmis veri
            metadata: Dosya meta verileri
            output_dir: Cikis dizini
            
        Returns:
            str: Kaydedilen dosyanin tam yolu
            
        Raises:
            ValueError: Checksum dogrulamasi basarisiz olursa
        """
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        output_path = os.path.join(output_dir, metadata.filename)
        
        # Dosyayi kaydet
        with open(output_path, 'wb') as f:
            f.write(data)
        
        # Checksum dogrulamasi
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data)
        calculated_checksum = digest.finalize().hex()
        
        if calculated_checksum != metadata.checksum:
            os.remove(output_path)  # Hatali dosyayi sil
            raise ValueError("Dosya butunlugu dogrulanamadi")
        
        return output_path
    
    def decrypt_file(self, filepath: str, metadata: FileMetadata) -> bytes:
        """
        Sifrelenmis dosyayi cozer.
        
        Args:
            filepath: Cozulecek dosyanin yolu
            metadata: Dosya meta verileri
            
        Returns:
            bytes: Cozulmus dosya verisi
        """
        if not self._fernet:
            self._fernet = Fernet(metadata.encryption_key)
        
        with open(filepath, 'rb') as f:
            encrypted_data = f.read()
        
        return self._fernet.decrypt(encrypted_data) 