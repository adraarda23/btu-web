# Gelişmiş Güvenli Dosya Aktarım Sistemi

**Proje**: Gelişmiş Güvenli Dosya Aktarım Sistemi: Şifreleme, Düşük Seviyeli IP İşleme ve Ağ Performansı Analizi  
**Geliştirici**: Arda Aydın Kılınç  
**Danışman**: İzzet Fatih Şentürk  
**Kurum**: Bursa Teknik Üniversitesi  

## 📋 Proje Hakkında

Bu proje, güvenli dosya aktarımı için geliştirilmiş kapsamlı bir sistem olup şifreleme, düşük seviyeli IP işleme, ağ performansı analizi ve güvenlik testlerini içermektedir. Sistem, Flask tabanlı web arayüzü ile kullanıcı dostu bir deneyim sunar.

## ✨ Özellikler

### 🔐 Güvenlik
- **AES (Fernet) Şifreleme**: Dosyaların güvenli şifrelenmesi
- **SHA-256 Hash Kontrolü**: Dosya bütünlüğü doğrulama
- **Kimlik Doğrulama**: Kullanıcı adı ve şifre tabanlı güvenlik
- **MITM Saldırı Tespiti**: Man-in-the-Middle saldırılarına karşı koruma
- **Replay Saldırı Koruması**: Tekrarlanan paket saldırılarını engelleme

### 🌐 Ağ İşlemleri
- **TCP Socket Tabanlı İletişim**: Güvenilir veri aktarımı
- **Paket Parçalama**: Büyük dosyaların küçük parçalara bölünmesi
- **Otomatik Yeniden Gönderim**: Kayıp paketlerin otomatik tekrar gönderimi
- **Düşük Seviyeli IP İşleme**: Scapy ile IP başlık manipülasyonu

### 📊 Performans ve İzleme
- **Gerçek Zamanlı Performans İzleme**: Bant genişliği, gecikme, paket kaybı
- **WebSocket Tabanlı Canlı Loglar**: Anlık sistem durumu takibi
- **Detaylı Raporlama**: Transfer istatistikleri ve analiz

### 🖥️ Kullanıcı Arayüzü
- **Web Tabanlı Arayüz**: Modern ve kullanıcı dostu tasarım
- **Canlı Log Görüntüleme**: Sunucu, istemci, performans ve güvenlik logları
- **Dosya Yükleme**: Sürükle-bırak destekli dosya yükleme

## 🚀 Kurulum ve Çalıştırma

### Gereksinimler
- Python 3.8 veya üzeri
- pip paket yöneticisi
- Bazı işlemler için root/admin yetkisi (Scapy için)

### 1. Depoyu Klonlayın
```bash
git clone <repository-url>
cd secure-file-transfer-system
```

### 2. Sanal Ortam Oluşturun ve Aktifleştirin
```bash
# Sanal ortam oluşturma
python3 -m venv venv

# Sanal ortamı aktifleştirme
# macOS/Linux:
source venv/bin/activate

# Windows:
.\venv\Scripts\activate
```

### 3. Bağımlılıkları Yükleyin
```bash
pip install -r requirements.txt
```

### 4. Uygulamayı Başlatın
```bash
python3 main.py
```

### 5. Web Arayüzüne Erişin
Tarayıcınızda aşağıdaki adresi açın:
```
http://localhost:5000
```

## 📦 Gerekli Paketler (requirements.txt)

```txt
Flask==2.3.2
Flask-SocketIO==5.3.4
cryptography==41.0.1
scapy==2.5.0
python-socketio==5.8.0
eventlet==0.33.3
```

## 🎯 Kullanım

### 1. Sunucu Başlatma
- Web arayüzünde "Sunucu Başlat" butonuna tıklayın
- Port numarasını belirleyin (varsayılan: 12345)
- Sunucu loglarını izleyin

### 2. Dosya Gönderme
- "Dosya Gönder" sekmesine gidin
- Hedef sunucu IP adresini girin
- Port numarasını belirleyin
- Kullanıcı bilgilerini girin:
  - **Kullanıcı Adı**: admin
  - **Şifre**: password123
- Dosyayı seçin ve "Gönder" butonuna tıklayın

### 3. Performans Testi
- "Performans Testi" butonuna tıklayın
- Bant genişliği, gecikme ve paket kaybı metriklerini görüntüleyin

### 4. Güvenlik Testi
- "Güvenlik Testi" butonuna tıklayın
- MITM ve Replay saldırı simülasyonlarını çalıştırın
- Tespit oranlarını kontrol edin

## 🏗️ Sistem Mimarisi

### Temel Bileşenler

1. **Flask Web Sunucusu**: HTTP API ve web arayüzü
2. **SocketIO**: Gerçek zamanlı komunikasyon
3. **TCP Socket Sunucusu**: Dosya aktarım sunucusu
4. **Şifreleme Modülü**: Fernet (AES) tabanlı şifreleme
5. **Performans İzleyici**: Ağ performansı ölçüm araçları
6. **Güvenlik Tester**: Saldırı tespit ve simülasyon

### Veri Akışı

1. **Dosya Yükleme**: Kullanıcı dosyayı web arayüzünden yükler
2. **Şifreleme**: Dosya AES algoritması ile şifrelenir
3. **Parçalama**: Şifreli dosya küçük parçalara bölünür
4. **Güvenilir İletim**: TCP socket ile parçalar gönderilir
5. **Yeniden Birleştirme**: Sunucu parçaları birleştirir
6. **Şifre Çözme**: Dosya çözülür ve doğrulanır

## 🔧 Yapılandırma

### Varsayılan Ayarlar
```python
# Sunucu ayarları
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 12345
WEB_PORT = 5000

# Güvenlik ayarları
DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "password123"  # SHA-256: ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f

# Transfer ayarları
FRAGMENT_SIZE = 1024  # bytes
MAX_RETRIES = 3
SOCKET_TIMEOUT = 10.0  # seconds
```

### Özelleştirme
Ayarları değiştirmek için `main.py` dosyasındaki ilgili değişkenleri düzenleyin.

## 📊 Performans Metrikleri

Sistem aşağıdaki performans metriklerini ölçer:

- **Bant Genişliği**: Mbps cinsinden veri transfer hızı
- **Ortalama Gecikme (RTT)**: Milisaniye cinsinden round-trip time
- **Paket Kaybı Oranı**: Yüzde cinsinden kayıp paket oranı
- **Transfer Süresi**: Saniye cinsinden toplam aktarım süresi
- **Toplam Byte**: Aktarılan toplam veri miktarı

## 🛡️ Güvenlik Özellikleri

### Şifreleme
- **Algoritma**: AES-256 (Fernet implementasyonu)
- **Anahtar Yönetimi**: Otomatik anahtar üretimi
- **Hash Kontrolü**: SHA-256 ile dosya bütünlüğü

### Saldırı Korumaları
- **MITM Tespiti**: Veri değişikliği kontrolü
- **Replay Koruması**: Paket ID takibi
- **Kimlik Doğrulama**: Hash tabanlı şifre kontrolü

## 🧪 Test Senaryoları

### Performans Testleri
1. Farklı dosya boyutları (1KB - 100MB)
2. Çeşitli ağ koşulları (WiFi, Ethernet, VPN)
3. Eşzamanlı aktarım testleri

### Güvenlik Testleri
1. MITM saldırı simülasyonu
2. Replay saldırı tespiti
3. Şifreleme kırma denemeleri
4. Kimlik doğrulama bypass testleri

## 🐛 Bilinen Sorunlar ve Sınırlamalar

### Bilinen Sorunlar
- Scapy kullanımı için root/admin yetkisi gerekebilir
- Çok büyük dosyalarda (>1GB) bellek kullanımı artabilir
- Windows'ta bazı firewall ayarları gerekebilir

### Sınırlamalar
- Tek dosya aktarımı (çoklu dosya desteği yok)
- IPv4 desteği (IPv6 henüz desteklenmiyor)
- Yerel ağ odaklı tasarım (WAN optimizasyon gerekebilir)

## 🔮 Gelecek Geliştirmeler

- [ ] UDP desteği eklenmesi
- [ ] Çoklu dosya aktarımı
- [ ] IPv6 desteği
- [ ] Grafik performans göstergeleri
- [ ] API dokümantasyonu
- [ ] Docker containerization
- [ ] SSL/TLS desteği
- [ ] Veritabanı entegrasyonu

## 📝 Log Türleri

Sistem dört farklı log kategorisi kullanır:

1. **Server Logs**: Sunucu durum bilgileri
2. **Client Logs**: İstemci işlem logları  
3. **Performance Logs**: Performans test sonuçları
4. **Security Logs**: Güvenlik olayları ve testler

## 🤝 Katkıda Bulunma

1. Bu depoyu fork edin
2. Feature branch oluşturun (`git checkout -b feature/amazing-feature`)
3. Değişikliklerinizi commit edin (`git commit -m 'Add amazing feature'`)
4. Branch'inizi push edin (`git push origin feature/amazing-feature`)
5. Pull Request oluşturun

## 📄 Lisans

Bu proje akademik amaçlı geliştirilmiştir. Ticari kullanım için izin alınması gerekmektedir.

## 📞 İletişim

**Geliştirici**: Arda Aydın Kılınç  
**Danışman**: İzzet Fatih Şentürk  
**Kurum**: Bursa Teknik Üniversitesi  

## 🙏 Teşekkürler

- Bursa Teknik Üniversitesi
- Python ve Flask toplulukları
- Açık kaynak kütüphane geliştiricileri

---

**Not**: Bu sistem eğitim ve araştırma amaçlıdır. Üretim ortamında kullanımdan önce ek güvenlik önlemleri alınması önerilir.