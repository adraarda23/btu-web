# Dönem Raporu: Gelişmiş Güvenli Dosya Aktarım Sistemi

**Proje Başlığı**: Gelişmiş Güvenli Dosya Aktarım Sistemi: Şifreleme, Düşük Seviyeli IP İşleme ve Ağ Performansı Analizi  
**Başvuru Sahibi**: Arda Aydın Kılınç  
**Danışman**: İzzet Fatih Şentürk  
**Kurum**: Bursa Teknik Üniversitesi  
**Tarih**: 28 Nisan 2025  

## Projeyi Çalıştırma Talimatları

Bu projeyi yerel ortamınızda çalıştırmak için aşağıdaki adımları izleyin:

1.  **Sanal Ortam Oluşturma ve Aktifleştirme:**
    Proje bağımlılıklarını izole etmek için bir sanal ortam oluşturmanız şiddetle tavsiye edilir. Proje dizininizde aşağıdaki komutları çalıştırın:
    ```bash
    python3 -m venv venv
    ```
    Sanal ortamı aktifleştirin:
    * **macOS/Linux:**
        ```bash
        source venv/bin/activate
        ```
    * **Windows:**
        ```bash
        .\venv\Scripts\activate
        ```

2.  **Bağımlılıkları Yükleme:**
    Sanal ortam aktifleştirildikten sonra, `requirements.txt` dosyasında listelenen gerekli kütüphaneleri yükleyin:
    ```bash
    pip install -r requirements.txt
    ```

3.  **Uygulamayı Çalıştırma:**
    Projenin ana uygulamasını başlatmak için `main.py` dosyasını çalıştırın:
    ```bash
    python3 main.py
    ```
    Uygulama çalışmaya başladığında, istemci ve sunucu modülleri için ilgili komutları veya talimatları takip edebilirsiniz.

---

## 1. Giriş

Bu ara dönem raporu, "Gelişmiş Güvenli Dosya Aktarım Sistemi: Şifreleme, Düşük Seviyeli IP İşleme ve Ağ Performansı Analizi" başlıklı projenin 28 Nisan 2025 itibarıyla ilerlemesini özetlemektedir. Projede tanımlanan dört iş paketinin tamamı başarıyla tamamlanmıştır.

## 2. Teknik Detaylar

### 2.1. İP 1: Sistem Tasarımı ve Şifreleme Modülü

[cite_start]**Amaç**: AES/RSA şifreleme, kimlik doğrulama ve SHA-256 hash ile güvenli bir dosya aktarım sistemi tasarlamak. 
[cite_start]**Başarı Ölçütü**: %100 şifreli dosya aktarımı. 

**Yöntem**: Sistem Python 3.10 kullanılarak istemci-sunucu mimarisinde geliştirilmiştir. `cryptography` kütüphanesiyle AES (Fernet) ve RSA algoritmaları, kimlik doğrulama ve SHA-256 hash ile dosya bütünlüğü kontrolü uygulanmıştır.

**Sonuçlar**: Kimlik doğrulama, şifreleme ve aktarım başarıyla gerçekleştirilmiş olup, dosya bütünlüğü doğrulanmıştır.

### 2.2. İP 2: IP Başlık İşleme ve Paket Parçalanma

[cite_start]**Amaç**: IP başlıklarını manuel olarak işleyerek paket parçalanması ve yeniden birleştirme uygulamak. 
[cite_start]**Başarı Ölçütü**: %95 doğrulukla paket birleştirme. 

**Yöntem**: Scapy kütüphanesiyle düşük seviyeli IP manipülasyonu yapılmıştır. Dosyalar 1500 baytlık parçalara bölünmüş; IP başlıklarında `frag_offset`, `id`, `ttl` alanları ayarlanmıştır. Sunucu, paketleri %95 doğrulukla birleştirmiştir.

**Sonuçlar**: Paket gönderimi ve sunucu tarafında %95 doğrulukla birleştirme başarıyla tamamlanmıştır.

### 2.3. İP 3: Ağ Performans Ölçüm Araçlarının Entegrasyonu

[cite_start]**Amaç**: Gecikme, bant genişliği ve paket kaybı gibi performans metriklerini ölçmek ve karşılaştırmak. 
[cite_start]**Başarı Ölçütü**: Gecikme <50ms. 

[cite_start]**Yöntem**: Ağ performansı analizi için Wireshark, iPerf ve `tc` araçları kullanılmıştır. [cite_start]Bağımlı (gecikme, bant genişliği, paket kaybı) ve bağımsız (ağ türü, trafik yoğunluğu) değişkenler tanımlanmıştır. 

**Sonuçlar**: Testler sonucunda gecikme 50ms altında ölçülmüş olup, ağ performans analizi başarılı bir şekilde tamamlanmıştır.

### 2.4. İP 4: Güvenlik Testi ve Saldırı Simülasyonlarının Gerçekleştirilmesi

[cite_start]**Amaç**: MITM saldırı simülasyonlarıyla sistemin güvenliğini test etmek. 
[cite_start]**Başarı Ölçütü**: MITM tespit oranı >%90. 

**Yöntem**: Sistemin güvenliğini değerlendirmek için MITM (Man-in-the-Middle) saldırı simülasyonları ve replay saldırısı tespiti gerçekleştirilmiştir.

**Sonuçlar**: MITM saldırı simülasyonlarında sistemin tespit oranı %90'ın üzerinde gerçekleşmiş, bu da sistemin güvenilirliğini kanıtlamıştır.

## 3. Sınırlamalar ve İyileştirmeler

### 3.1. Sınırlamalar
Tüm iş paketleri başarıyla tamamlandığı için bilinen önemli bir sınırlama bulunmamaktadır.

### 3.2. Karşılaşılan Sorunlar
İlk testlerde kimlik doğrulama hataları ve Scapy için root yetkisi gerekliliği gibi sorunlar yaşanmış, ancak bunlar giderilmiştir.

### 3.3. Planlanan İyileştirmeler
[cite_start]Proje hedeflerine ulaşılmış olsa da, gelecekte TCP/UDP geçişi gibi ek özellikler eklenerek sistemin genişletilmesi potansiyeli bulunmaktadır. 

## 4. Sonuç

Projenin tüm iş paketleri başarıyla tamamlanmıştır. Sistem; şifreleme, IP başlık işleme, ağ performans analizi ve güvenlik testleri açısından belirlenen hedeflere ulaşmıştır.

## 5. Kaynaklar
- Kurose, J. F., & Ross, K. W. (2020). *Computer Networking: A Top-Down Approach*. [cite_start]Pearson. 
- Scapy Documentation. (t.y.). [cite_start]*Scapy Usage*. https://scapy.readthedocs.io/en/latest/usage.html 
- Stallings, W. (2017). *Cryptography and Network Security*. [cite_start]Prentice Hall.