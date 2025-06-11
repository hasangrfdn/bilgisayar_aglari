"""
Güvenli Dosya Transfer Sistemi - Kimlik Doğrulama ve Güvenlik Modülü

Bu modul, guvenli dosya transferi icin gerekli kimlik dogrulama ve
sifreleme islemlerini yonetir. RSA anahtar cifti yonetimi, oturum
anahtari olusturma ve challenge-response mekanizmasi saglar.

Kullanim:
    from security.auth import Authentication
    
    auth = Authentication()
    private_pem, public_pem = auth.generate_key_pair()
    session_key = auth.generate_session_key()
"""

import os
import hmac
import hashlib
import time
from typing import Optional, Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import base64
from cryptography.fernet import Fernet

class Authentication:
    """
    Kimlik dogrulama ve guvenlik islemlerini yoneten sinif.
    
    Bu sinif, RSA anahtar cifti yonetimi, oturum anahtari olusturma
    ve challenge-response mekanizmasi gibi guvenlik islemlerini
    yonetir.
    """
    
    def __init__(self):
        """
        Authentication sinifini baslatir.
        
        Attributes:
            _private_key: RSA ozel anahtari
            _public_key: RSA acik anahtari
            _session_key: Oturum anahtari
        """
        self._private_key: Optional[rsa.RSAPrivateKey] = None
        self._public_key: Optional[rsa.RSAPublicKey] = None
        self._session_key: Optional[bytes] = None
    
    def generate_key_pair(self) -> Tuple[bytes, bytes]:
        """
        RSA anahtar cifti olusturur.
        
        Islem adimlari:
        1. 2048-bit RSA ozel anahtari olusturur
        2. Acik anahtari cikarir
        3. Anahtarlari PEM formatina donusturur
        
        Returns:
            Tuple[bytes, bytes]: (ozel_anahtar_pem, acik_anahtar_pem)
        """
        # Ozel anahtar olustur
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Acik anahtari al
        public_key = private_key.public_key()
        
        # Anahtarlari PEM formatina donustur
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        self._private_key = private_key
        self._public_key = public_key
        
        return private_pem, public_pem
    
    def load_keys(self, private_key_path: str, public_key_path: str):
        """
        Kayitli anahtarlari yukler.
        
        Args:
            private_key_path: Ozel anahtar dosya yolu
            public_key_path: Acik anahtar dosya yolu
            
        Raises:
            FileNotFoundError: Anahtar dosyalari bulunamazsa
        """
        with open(private_key_path, 'rb') as f:
            private_pem = f.read()
            self._private_key = serialization.load_pem_private_key(
                private_pem,
                password=None
            )
        
        with open(public_key_path, 'rb') as f:
            public_pem = f.read()
            self._public_key = serialization.load_pem_public_key(public_pem)
    
    def save_keys(self, private_key_path: str, public_key_path: str):
        """
        Anahtarlari dosyaya kaydeder.
        
        Args:
            private_key_path: Ozel anahtar kayit yolu
            public_key_path: Acik anahtar kayit yolu
            
        Raises:
            ValueError: Anahtarlar olusturulmamissa
        """
        if not self._private_key or not self._public_key:
            raise ValueError("Anahtarlar olusturulmamis")
        
        # Ozel anahtari kaydet
        private_pem = self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(private_key_path, 'wb') as f:
            f.write(private_pem)
        
        # Acik anahtari kaydet
        public_pem = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(public_key_path, 'wb') as f:
            f.write(public_pem)
    
    def generate_session_key(self) -> bytes:
        """
        Oturum anahtari olusturur.
        
        Returns:
            bytes: 32 byte uzunlugunda rastgele oturum anahtari
        """
        self._session_key = os.urandom(32)
        return self._session_key
    
    def encrypt_session_key(self, public_key: rsa.RSAPublicKey) -> bytes:
        """
        Oturum anahtarini RSA ile sifreler.
        
        Args:
            public_key: RSA acik anahtari
            
        Returns:
            bytes: Sifrelenmis oturum anahtari
            
        Raises:
            ValueError: Oturum anahtari olusturulmamissa
        """
        if not self._session_key:
            raise ValueError("Oturum anahtari olusturulmamis")
        
        return public_key.encrypt(
            self._session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    def decrypt_session_key(self, encrypted_key: bytes) -> bytes:
        """
        Sifrelenmis oturum anahtarini cozer.
        
        Args:
            encrypted_key: Sifrelenmis oturum anahtari
            
        Returns:
            bytes: Cozulmus oturum anahtari
            
        Raises:
            ValueError: Ozel anahtar yuklenmemisse
        """
        if not self._private_key:
            raise ValueError("Ozel anahtar yuklenmemis")
        
        self._session_key = self._private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return self._session_key
    
    def generate_challenge(self) -> Tuple[bytes, bytes]:
        """
        Kimlik dogrulama icin challenge-response mekanizmasi olusturur.
        
        Returns:
            Tuple[bytes, bytes]: (challenge, zaman_damgasi)
        """
        challenge = os.urandom(32)
        timestamp = int(time.time()).to_bytes(8, 'big')
        return challenge, timestamp
    
    def verify_challenge(self, challenge: bytes, timestamp: bytes, response: bytes) -> bool:
        """
        Challenge-response dogrulamasi yapar.
        
        Islem adimlari:
        1. Zaman damgasini kontrol eder (5 dakika tolerans)
        2. HMAC ile yaniti dogrular
        
        Args:
            challenge: Orijinal challenge degeri
            timestamp: Zaman damgasi
            response: Dogrulanacak yanit
            
        Returns:
            bool: Dogrulama basarili ise True, degilse False
            
        Raises:
            ValueError: Oturum anahtari yuklenmemisse
        """
        if not self._session_key:
            raise ValueError("Oturum anahtari yuklenmemis")
        
        # Zaman damgasini kontrol et (5 dakika tolerans)
        current_time = int(time.time())
        challenge_time = int.from_bytes(timestamp, 'big')
        if abs(current_time - challenge_time) > 300:
            return False
        
        # HMAC ile dogrulama
        expected_response = hmac.new(
            self._session_key,
            challenge + timestamp,
            hashlib.sha256
        ).digest()
        
        return hmac.compare_digest(response, expected_response)
    
    def sign_data(self, data: bytes) -> bytes:
        """
        Veriyi imzalar.
        
        Args:
            data: Imzalanacak veri
            
        Returns:
            bytes: RSA imzasi
            
        Raises:
            ValueError: Ozel anahtar yuklenmemisse
        """
        if not self._private_key:
            raise ValueError("Ozel anahtar yuklenmemis")
        
        signature = self._private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
    
    def verify_signature(self, data: bytes, signature: bytes) -> bool:
        """
        Imzayi dogrular.
        
        Args:
            data: Orijinal veri
            signature: Dogrulanacak imza
            
        Returns:
            bool: Dogrulama basarili ise True, degilse False
            
        Raises:
            ValueError: Acik anahtar yuklenmemisse
        """
        if not self._public_key:
            raise ValueError("Acik anahtar yuklenmemis")
        
        try:
            self._public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False