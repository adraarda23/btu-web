import os
import hashlib
import socket
import time
import sys
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

try:
    from scapy.all import IP, Raw, send, sniff
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Uyarı: Scapy yüklü değil. Sadece TCP modu kullanılabilir.")

# Kullanıcı veritabanı
USERS = {"user1": "password1"}

# Yardımcı Fonksiyonlar
def send_data(sock, data):
    """Veriyi uzunluk bilgisiyle gönderir."""
    data_bytes = data.encode('utf-8') if isinstance(data, str) else data
    length = len(data_bytes)
    sock.sendall(f"{length}:".encode('utf-8') + data_bytes)

def recv_data(sock, timeout=10):
    """Veriyi uzunluk bilgisiyle alır ve bytes olarak döndürür."""
    sock.settimeout(timeout)
    length_data = b""
    while not length_data.endswith(b":"):
        chunk = sock.recv(1)
        if not chunk:
            raise ConnectionError("Veri alımı kesildi: Uzunluk bilgisi eksik.")
        length_data += chunk
    try:
        length = int(length_data.decode().rstrip(":"))
    except ValueError:
        raise ValueError(f"Geçersiz uzunluk bilgisi: {length_data.decode()}")
    
    data = b""
    while len(data) < length:
        remaining = length - len(data)
        chunk = sock.recv(4096 if remaining > 4096 else remaining)
        if not chunk:
            raise ConnectionError("Veri alımı kesildi: Eksik veri.")
        data += chunk
    return data

# İş Paketi 1: Şifreleme ve Kimlik Doğrulama
def generate_rsa_keys():
    """RSA-2048 anahtar çifti oluşturur."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_symmetric_key(aes_key, public_key):
    """AES anahtarını RSA ile şifreler."""
    try:
        encrypted_key = public_key.encrypt(
            aes_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        return encrypted_key
    except Exception as e:
        print(f"AES anahtar şifreleme hatası: {e}")
        raise

def decrypt_symmetric_key(encrypted_key, private_key):
    """Şifreli AES anahtarını çözer."""
    try:
        aes_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        return aes_key
    except Exception as e:
        print(f"AES anahtar çözme hatası: {e}")
        raise

def encrypt_file(file_path, aes_key):
    """Dosyayı AES-256 ile şifreler."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Dosya bulunamadı: {file_path}")
    cipher = Fernet(aes_key)
    with open(file_path, "rb") as file:
        data = file.read()
    encrypted_data = cipher.encrypt(data)
    output_path = file_path + ".encrypted"
    with open(output_path, "wb") as file:
        file.write(encrypted_data)
    return output_path

def decrypt_file(encrypted_file_path, aes_key):
    """Şifreli dosyayı AES-256 ile çözer."""
    try:
        cipher = Fernet(aes_key)
        with open(encrypted_file_path, "rb") as file:
            encrypted_data = file.read()
        decrypted_data = cipher.decrypt(encrypted_data)
        output_path = encrypted_file_path.replace(".encrypted", ".decrypted")
        with open(output_path, "wb") as file:
            file.write(decrypted_data)
        return output_path
    except Exception as e:
        print(f"Dosya çözme hatası: {e}")
        raise

def calculate_file_hash(file_path):
    """Dosyanın SHA-256 hash'ini hesaplar."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as file:
        while chunk := file.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()

def authenticate_user(username, password):
    """Kullanıcı kimlik doğrulamasını yapar."""
    print(f"Alınan kullanıcı adı (ham): {repr(username)}")
    print(f"Alınan şifre (ham): {repr(password)}")
    username = username.strip()
    password = password.strip()
    result = USERS.get(username) == password
    print(f"Kimlik doğrulama kontrolü: username={repr(username)}, password={repr(password)}, sonuç={result}")
    return result

# İş Paketi 2: IP Başlık İşleme ve Paket Parçalanma (Scapy ile)
def fragment_file(file_path, chunk_size=1500):
    """Dosyayı sabit boyutlu parçalara böler."""
    fragments = []
    with open(file_path, "rb") as file:
        data = file.read()
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        fragments.append((i // chunk_size, chunk))
    return fragments

def send_fragmented_packets(fragments, dst_ip, ident=12345):
    """Parçalanmış dosyayı IP paketleriyle gönderir."""
    if not SCAPY_AVAILABLE:
        raise RuntimeError("Scapy yüklü değil. IP paket gönderimi yapılamaz.")
    try:
        for frag_offset, chunk in fragments:
            packet = IP(dst=dst_ip, id=ident, frag=frag_offset, ttl=64) / Raw(chunk)
            send(packet, verbose=0)  # iface parametresi kaldırıldı
            time.sleep(0.01)
    except PermissionError:
        print("Hata: Scapy için root yetkisi gerekiyor. 'sudo' ile çalıştırın.")
        raise
    except Exception as e:
        print(f"Paket gönderme hatası: {e}")
        raise

def receive_fragments(ident=12345, timeout=10):
    """Parçalanmış IP paketlerini alır ve birleştirir."""
    if not SCAPY_AVAILABLE:
        raise RuntimeError("Scapy yüklü değil. IP paket alımı yapılamaz.")
    fragments = {}
    def packet_filter(pkt):
        return IP in pkt and pkt[IP].id == ident

    try:
        print("Paketler alınıyor (MacOS en0 arabirimi)...")
        packets = sniff(filter="ip", lfilter=packet_filter, timeout=timeout, iface="en0")
        if not packets:
            print("Hata: Hiç paket alınmadı. Sunucu IP/port veya ağ ayarlarını kontrol edin.")
            return b""
        for pkt in packets:
            frag_offset = pkt[IP].frag
            fragments[frag_offset] = pkt[Raw].load
        sorted_keys = sorted(fragments.keys())
        reassembled_data = b"".join(fragments[key] for key in sorted_keys)
        return reassembled_data
    except PermissionError:
        print("Hata: Scapy için root yetkisi gerekiyor. 'sudo' ile çalıştırın.")
        raise
    except Exception as e:
        print(f"Paket alma hatası: {e}")
        raise

# Sunucu
def server(host="0.0.0.0", port=12345, use_scapy=True):
    """Sunucu: Kimlik doğrulama, şifreleme ve dosya alma."""
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        server_socket.bind((host, port))
        server_socket.listen(1)
        print(f"Sunucu başlatıldı, {host}:{port} üzerinde istemci bekleniyor...")
    except Exception as e:
        print(f"Sunucu başlatılamadı: {e}")
        return

    try:
        conn, addr = server_socket.accept()
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        print(f"Bağlantı: {addr}")
    except Exception as e:
        print(f"İstemci bağlantısı kabul edilemedi: {e}")
        server_socket.close()
        return

    try:
        # Kimlik doğrulama
        username = recv_data(conn).decode('utf-8')
        print(f"Alınan kullanıcı adı: {repr(username)}")
        password = recv_data(conn).decode('utf-8')
        print(f"Alınan şifre: {repr(password)}")
        if not authenticate_user(username, password):
            send_data(conn, "Authentication failed")
            conn.close()
            server_socket.close()
            print("Kimlik doğrulama başarısız!")
            return
        send_data(conn, "Authentication successful")
        print("Kimlik doğrulama başarılı!")
    except Exception as e:
        print(f"Kimlik doğrulama hatası: {e}")
        conn.close()
        server_socket.close()
        return

    try:
        private_key, public_key = generate_rsa_keys()
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.PKCS1
        )
        send_data(conn, public_key_pem)
        print("Public anahtar gönderildi.")
    except Exception as e:
        print(f"RSA anahtar hatası: {e}")
        conn.close()
        server_socket.close()
        return

    try:
        encrypted_aes_key = recv_data(conn)
        aes_key = decrypt_symmetric_key(encrypted_aes_key, private_key)
        print("AES anahtarı alındı ve çözüldü.")
    except Exception as e:
        print(f"AES anahtar alma hatası: {e}")
        conn.close()
        server_socket.close()
        return

    try:
        if use_scapy and SCAPY_AVAILABLE:
            received_data = receive_fragments()
            if not received_data:
                print("Hata: Dosya verisi alınamadı.")
                conn.close()
                server_socket.close()
                return
        else:
            received_data = recv_data(conn)
            if not received_data:
                print("Hata: Dosya verisi alınamadı.")
                conn.close()
                server_socket.close()
                return
        
        with open("received.encrypted", "wb") as file:
            file.write(received_data)
        print("Şifreli dosya alındı ve kaydedildi.")
    except Exception as e:
        print(f"Dosya alma hatası: {e}")
        conn.close()
        server_socket.close()
        return

    try:
        decrypted_file = decrypt_file("received.encrypted", aes_key)
        received_hash = recv_data(conn)
        received_hash = received_hash.decode('utf-8')  # Hash string olarak gönderiliyor
        calculated_hash = calculate_file_hash(decrypted_file)
        if received_hash == calculated_hash:
            print("Dosya bütünlüğü doğrulandı!")
        else:
            print("Dosya bütünlüğü doğrulanamadı!")
    except Exception as e:
        print(f"Dosya çözme/doğrulama hatası: {e}")

    conn.close()
    server_socket.close()

# İstemci
def client(server_ip, server_port=12345, file_path="test.txt", username="user1", password="password1", use_scapy=True):
    """İstemci: Dosyayı şifreler, parçalar ve sunucuya gönderir."""
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.settimeout(10)
    client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    print(f"Bağlanılıyor: {server_ip}:{server_port}")
    try:
        client_socket.connect((server_ip, server_port))
        print("Bağlantı başarılı!")
    except socket.timeout:
        print(f"Hata: {server_ip}:{server_port} adresine bağlanılamadı. Sunucunun çalıştığından ve ağın doğru olduğundan emin olun.")
        return
    except Exception as e:
        print(f"Bağlantı hatası: {e}")
        return

    try:
        # Kimlik doğrulama
        send_data(client_socket, username.strip())
        print(f"Gönderilen kullanıcı adı: {repr(username)}")
        send_data(client_socket, password.strip())
        print(f"Gönderilen şifre: {repr(password)}")
        response = recv_data(client_socket)
        response_str = response.decode('utf-8')
        print(f"Sunucudan yanıt: {response_str}")
        if "failed" in response_str.lower():
            print("Kimlik doğrulama başarısız!")
            client_socket.close()
            return
        print("Kimlik doğrulama başarılı!")
    except Exception as e:
        print(f"Kimlik doğrulama hatası: {e}")
        client_socket.close()
        return

    try:
        public_key_pem = recv_data(client_socket)
        public_key = serialization.load_pem_public_key(public_key_pem)
        print("Public anahtar alındı.")
    except Exception as e:
        print(f"RSA public anahtar alma hatası: {e}")
        client_socket.close()
        return

    try:
        aes_key = Fernet.generate_key()
        encrypted_file = encrypt_file(file_path, aes_key)
        print(f"Dosya şifrelendi: {encrypted_file}")
    except Exception as e:
        print(f"Dosya şifreleme hatası: {e}")
        client_socket.close()
        return

    try:
        encrypted_aes_key = encrypt_symmetric_key(aes_key, public_key)
        send_data(client_socket, encrypted_aes_key)
        print("Şifreli AES anahtarı gönderildi.")
    except Exception as e:
        print(f"AES anahtar gönderme hatası: {e}")
        client_socket.close()
        return

    try:
        if use_scapy and SCAPY_AVAILABLE:
            fragments = fragment_file(encrypted_file)
            send_fragmented_packets(fragments, server_ip)
            print("Dosya parçaları Scapy ile gönderildi.")
        else:
            with open(encrypted_file, "rb") as file:
                file_data = file.read()
                send_data(client_socket, file_data)
            print("Dosya TCP ile gönderildi.")
    except Exception as e:
        print(f"Dosya gönderme hatası: {e}")
        client_socket.close()
        return

    try:
        file_hash = calculate_file_hash(file_path)
        send_data(client_socket, file_hash)
        print("Dosya hash'i gönderildi.")
    except Exception as e:
        print(f"Hash gönderme hatası: {e}")
        client_socket.close()
        return

    client_socket.close()
    print("Dosya transferi tamamlandı!")

# Ana program
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Kullanım: python secure_file_transfer_macos.py [server|client] [server_ip] [file_path] [--no-scapy]")
        sys.exit(1)

    mode = sys.argv[1]
    use_scapy = "--no-scapy" not in sys.argv

    if not use_scapy:
        print("Scapy devre dışı. Sadece TCP aktarımı kullanılacak (İş Paketi 1).")
    elif not SCAPY_AVAILABLE:
        print("Scapy yüklü değil. TCP moduna geçiliyor.")
        use_scapy = False

    if mode == "server":
        server(use_scapy=use_scapy)
    elif mode == "client":
        server_ip = sys.argv[2]
        file_path = sys.argv[3] if len(sys.argv) > 3 else "test.txt"
        client(server_ip, file_path=file_path, use_scapy=use_scapy)
    else:
        print("Geçersiz mod! 'server' veya 'client' kullanın.")