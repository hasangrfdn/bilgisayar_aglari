# Guvenli Dosya Transfer Sistemi

Bu proje, guvenli ve hizli dosya transferi saglayan gelismis bir sistemdir. Dosyalarin guvenli bir sekilde transfer edilmesini, sifrelenmesini ve ag performansinin olculmesini saglar.

## Ozellikler

- **Guvenli Dosya Transferi**: AES-256 sifreleme ile dosyalarin guvenli transferi
- **Ag Performans Analizi**: Transfer hizi, gecikme ve paket kaybi olcumu
- **Dusuk Seviye Ag Islemleri**: Raw socket kullanimi ile ozel protokol implementasyonu
- **Coklu Dosya Transferi**: Ayni anda birden fazla dosya transferi desteği
- **Hata Toleransi**: Paket kaybi durumunda otomatik yeniden gonderme
- **Baglanti Testi**: Hedef sistemin erisilebilirlik kontrolu

## Kurulum

1. Python 3.8 veya daha yuksek bir surum gerekir
2. Sanal ortam olusturun ve aktif edin:
```bash
python -m venv .venv
# Windows icin:
.venv\Scripts\activate
# Linux/Mac icin:
source .venv/bin/activate
```

3. Gerekli paketleri yukleyin:
```bash
pip install -r requirements.txt
```

## Kullanim

### Dosya Gonderme

```bash
python src/main.py --mode send --file "dosya_yolu.txt" --dst-ip "hedef_ip" --password "sifre"
```

### Dosya Alma

```bash
python src/main.py --mode receive --password "sifre" --output-dir "alınan_dosyalar"
```

## Parametreler

- `--mode`: Calisma modu (send/receive)
- `--file`: Gondermek istediginiz dosyanin yolu
- `--dst-ip`: Hedef IP adresi
- `--dst-port`: Hedef port numarasi (varsayilan: 12345)
- `--output-dir`: Alinan dosyalarin kaydedilecegi dizin (varsayilan: "received")
- `--password`: Sifreleme anahtari

## Proje Yapisi

```
├── src/
│   ├── core/           # Temel dosya transfer islemleri
│   ├── network/        # Ag islemleri ve paket yonetimi
│   ├── security/       # Sifreleme ve guvenlik mekanizmalari
│   ├── utils/          # Yardimci fonksiyonlar
│   └── main.py         # Ana program
├── keys/               # Sifreleme anahtarlari
├── received/           # Alinan dosyalarin kaydedildigi dizin
├── requirements.txt    # Gerekli Python paketleri
└── README.md          # Bu dosya
```

## Guvenlik

- AES-256 sifreleme kullanilir
- Her transfer icin benzersiz oturum anahtari olusturulur
- Dosya butunlugu kontrolu yapilir
- RSA anahtar cifti ile guvenli anahtar degisimi saglanir

## Performans

- Raw socket kullanimi ile hizli veri transferi
- Paket fragmentasyonu ile buyuk dosya desteği
- Paralel transfer ile coklu dosya gonderme
- Ag performans metriklerinin olculmesi

## Hata Ayiklama

Eger bir hata ile karsilasirsaniz:

1. Hedef sistemin erisilebilir oldugundan emin olun
2. Port numarasinin acik oldugunu kontrol edin
3. Sifreleme anahtarinin dogru oldugunu kontrol edin
4. Dosya izinlerinin uygun oldugunu kontrol edin

## Güvenlik Notları

- Projeyi kullanmadan önce `keys` dizininde kendi anahtar çiftinizi oluşturun
- Şifreleme anahtarlarınızı asla GitHub'a push etmeyin
- Hassas bilgileri içeren dosyaları `.gitignore` dosyasına ekleyin
- Üretim ortamında güçlü şifreler kullanın
- Anahtar dosyalarınızı güvenli bir yerde yedekleyin

## Iletisim

Sorulariniz ve onerileriniz icin https://www.linkedin.com/in/hasangrfdn/ 
