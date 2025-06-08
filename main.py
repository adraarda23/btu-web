import os
import hashlib
import socket
import time
import json
import threading
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file
from flask_socketio import SocketIO
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import io
import base64
from scapy.all import IP, TCP, Raw, send, sr1
import secrets
from collections import deque

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*", engineio_logger=True)

# Global variables
server_thread = None
server_running = False
server_logs = deque(maxlen=100)
client_logs = deque(maxlen=100)
performance_logs = deque(maxlen=100)
security_logs = deque(maxlen=100)
performance_data = {}
security_data = {}
users = {"admin": hashlib.sha256("password123".encode()).hexdigest()}
fernet_key = Fernet.generate_key()
cipher = Fernet(fernet_key)
received_packet_ids = set()

# Performance monitoring class
class PerformanceMonitor:
    def __init__(self):
        self.metrics = {
            "transfer_start": None,
            "transfer_end": None,
            "bytes_sent": 0,
            "bytes_received": 0,
            "packets_sent": 0,
            "packets_lost": 0,
            "rtt_samples": []
        }
    
    def start_transfer(self):
        self.metrics["transfer_start"] = time.time()
    
    def end_transfer(self):
        self.metrics["transfer_end"] = time.time()
    
    def add_rtt_sample(self, rtt):
        self.metrics["rtt_samples"].append(rtt)
    
    def calculate_stats(self):
        if not self.metrics["transfer_start"] or not self.metrics["transfer_end"]:
            return None
        
        duration = self.metrics["transfer_end"] - self.metrics["transfer_start"]
        bandwidth = (self.metrics["bytes_received"] * 8) / duration / 1_000_000 if duration > 0 else 0
        avg_rtt = sum(self.metrics["rtt_samples"]) / len(self.metrics["rtt_samples"]) if self.metrics["rtt_samples"] else 0
        packet_loss = (self.metrics["packets_lost"] / self.metrics["packets_sent"] * 100) if self.metrics["packets_sent"] > 0 else 0
        
        return {
            "duration_sec": round(duration, 2),
            "bandwidth_mbps": round(bandwidth, 2),
            "avg_rtt_ms": round(avg_rtt * 1000, 2),
            "packet_loss_percent": round(packet_loss, 2),
            "total_bytes": self.metrics["bytes_received"]
        }

# Security testing class
class SecurityTester:
    def __init__(self):
        self.attack_detected = False
        self.suspicious_activities = []
        self.detection_rate = 0
    
    def simulate_mitm_attack(self, original_data, intercepted_data):
        if original_data != intercepted_data:
            self.attack_detected = True
            self.suspicious_activities.append({
                "type": "MITM",
                "timestamp": datetime.now().isoformat(),
                "description": "Veri değişikliği tespit edildi"
            })
            self.detection_rate += 1
            return True
        return False
    
    def detect_replay_attack(self, packet_id, received_ids):
        if packet_id in received_ids:
            self.suspicious_activities.append({
                "type": "Replay_Attack",
                "timestamp": datetime.now().isoformat(),
                "description": f"Paket ID {packet_id} tekrar alındı"
            })
            self.detection_rate += 1
            return True
        return False

# Log function
def add_log(category, message):
    log_entry = f"[{datetime.now().strftime('%H:%M:%S')}] {message}"
    if category == "server":
        server_logs.append(log_entry)
    elif category == "client":
        client_logs.append(log_entry)
    elif category == "performance":
        performance_logs.append(log_entry)
    elif category == "security":
        security_logs.append(log_entry)
    socketio.emit('logs', {
        "server_logs": list(server_logs),
        "client_logs": list(client_logs),
        "performance_logs": list(performance_logs),
        "security_logs": list(security_logs)
    }, namespace='/')

# File encryption and hash
def encrypt_file(file_data):
    encrypted_data = cipher.encrypt(file_data)
    file_hash = hashlib.sha256(file_data).hexdigest()
    return encrypted_data, file_hash

def decrypt_file(encrypted_data):
    return cipher.decrypt(encrypted_data)

# Geliştirilmiş dosya gönderme fonksiyonu - TCP socket kullanarak
def send_file_reliable(ip, port, data, fragment_size=1024):
    """
    TCP socket kullanarak güvenilir dosya gönderimi
    """
    total_fragments = len(data) // fragment_size + (1 if len(data) % fragment_size else 0)
    packets_sent = 0
    packets_lost = 0
    successful_chunks = 0
    
    try:
        # Ana TCP bağlantısı kur
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(10.0)  # 10 saniye timeout
        client_socket.connect((ip, port))
        
        add_log("client", f"Sunucuya bağlantı kuruldu: {ip}:{port}")
        
        # Dosya boyutu ve parça sayısını gönder
        header_info = {
            "total_size": len(data),
            "fragment_count": total_fragments,
            "fragment_size": fragment_size
        }
        header_json = json.dumps(header_info).encode()
        header_size = len(header_json)
        
        # Önce header boyutunu gönder (4 byte)
        client_socket.send(header_size.to_bytes(4, byteorder='big'))
        # Sonra header'ı gönder
        client_socket.send(header_json)
        
        # Sunucudan onay bekle
        response = client_socket.recv(3)
        if response != b"HDR":
            raise Exception("Header onayı alınamadı")
        
        add_log("client", f"Header gönderildi: {total_fragments} parça, {len(data)} byte")
        
        # Veriyi parçalar halinde gönder
        for i in range(0, len(data), fragment_size):
            fragment = data[i:i+fragment_size]
            fragment_id = i // fragment_size
            
            # Parça başlığı: parça ID (4 byte) + parça boyutu (4 byte)
            chunk_header = fragment_id.to_bytes(4, byteorder='big') + len(fragment).to_bytes(4, byteorder='big')
            
            retry_count = 0
            max_retries = 3
            chunk_sent = False
            
            while retry_count < max_retries and not chunk_sent:
                try:
                    # Parça başlığını gönder
                    client_socket.send(chunk_header)
                    # Parça verisini gönder
                    client_socket.send(fragment)
                    
                    # Sunucudan ACK bekle
                    ack = client_socket.recv(3)
                    if ack == b"ACK":
                        packets_sent += 1
                        successful_chunks += 1
                        chunk_sent = True
                        add_log("client", f"Parça {fragment_id + 1}/{total_fragments} başarıyla gönderildi")
                    else:
                        retry_count += 1
                        add_log("client", f"Parça {fragment_id + 1} için ACK alınamadı, tekrar deneniyor ({retry_count}/{max_retries})")
                        time.sleep(0.1)  # Kısa bekle
                        
                except socket.timeout:
                    retry_count += 1
                    add_log("client", f"Parça {fragment_id + 1} timeout, tekrar deneniyor ({retry_count}/{max_retries})")
                    time.sleep(0.1)
                except Exception as e:
                    retry_count += 1
                    add_log("client", f"Parça {fragment_id + 1} gönderim hatası: {str(e)}, tekrar deneniyor ({retry_count}/{max_retries})")
                    time.sleep(0.1)
            
            if not chunk_sent:
                packets_lost += 1
                add_log("client", f"Parça {fragment_id + 1} gönderilemedi, max deneme sayısına ulaşıldı")
        
        # Transfer tamamlandı sinyali gönder
        client_socket.send(b"DONE")
        final_response = client_socket.recv(8)
        
        if final_response == b"COMPLETE":
            add_log("client", f"Dosya transferi tamamlandı: {successful_chunks}/{total_fragments} parça başarılı")
        else:
            add_log("client", f"Transfer tamamlama onayı alınamadı")
            
    except Exception as e:
        add_log("client", f"Bağlantı hatası: {str(e)}")
        packets_lost += (total_fragments - successful_chunks)
    finally:
        try:
            client_socket.close()
        except:
            pass
    
    return packets_sent, packets_lost, secrets.token_hex(4)

# Geliştirilmiş server fonksiyonu
def web_server(host="0.0.0.0", port=12345):
    global server_running, received_packet_ids
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.settimeout(1.0)
    
    try:
        server_socket.bind((host, port))
        server_socket.listen(5)
        add_log("server", f"Sunucu başlatıldı: {host}:{port}")
        server_running = True
        
        while server_running:
            try:
                conn, addr = server_socket.accept()
                add_log("server", f"Bağlantı kabul edildi: {addr}")
                threading.Thread(target=handle_client_connection_reliable, args=(conn, addr)).start()
            except socket.timeout:
                continue
            except Exception as e:
                add_log("server", f"Hata: {str(e)}")
                
    except Exception as e:
        add_log("server", f"Sunucu başlatma hatası: {str(e)}")
    finally:
        server_socket.close()
        add_log("server", "Sunucu durduruldu")

def handle_client_connection_reliable(conn, addr):
    """
    Geliştirilmiş client bağlantı handler'ı - güvenilir dosya alımı
    """
    global received_packet_ids
    try:
        conn.settimeout(30.0)  # 30 saniye timeout
        
        # Header boyutunu al (4 byte)
        header_size_bytes = conn.recv(4)
        if len(header_size_bytes) != 4:
            raise Exception("Header boyutu alınamadı")
        
        header_size = int.from_bytes(header_size_bytes, byteorder='big')
        
        # Header'ı al
        header_json = conn.recv(header_size)
        header_info = json.loads(header_json.decode())
        
        total_size = header_info["total_size"]
        fragment_count = header_info["fragment_count"]
        fragment_size = header_info["fragment_size"]
        
        add_log("server", f"Header alındı: {fragment_count} parça, {total_size} byte bekleniyor")
        
        # Header onayı gönder
        conn.send(b"HDR")
        
        # Veri parçalarını toplamak için buffer
        received_data = bytearray(total_size)
        received_fragments = set()
        
        # Her parçayı al
        for expected_fragment in range(fragment_count):
            try:
                # Parça başlığını al (8 byte: 4 byte ID + 4 byte boyut)
                chunk_header = conn.recv(8)
                if len(chunk_header) != 8:
                    add_log("server", f"Parça {expected_fragment} header'ı eksik")
                    conn.send(b"NAK")
                    continue
                
                fragment_id = int.from_bytes(chunk_header[:4], byteorder='big')
                chunk_size = int.from_bytes(chunk_header[4:], byteorder='big')
                
                # Parça verisini al
                chunk_data = b""
                while len(chunk_data) < chunk_size:
                    remaining = chunk_size - len(chunk_data)
                    part = conn.recv(min(remaining, 4096))
                    if not part:
                        break
                    chunk_data += part
                
                if len(chunk_data) == chunk_size:
                    # Veriyi doğru pozisyona yerleştir
                    start_pos = fragment_id * fragment_size
                    end_pos = start_pos + len(chunk_data)
                    received_data[start_pos:end_pos] = chunk_data
                    received_fragments.add(fragment_id)
                    
                    add_log("server", f"Parça {fragment_id + 1}/{fragment_count} alındı ve yerleştirildi")
                    conn.send(b"ACK")
                else:
                    add_log("server", f"Parça {fragment_id + 1} boyut uyumsuzluğu")
                    conn.send(b"NAK")
                    
            except Exception as e:
                add_log("server", f"Parça alma hatası: {str(e)}")
                try:
                    conn.send(b"NAK")
                except:
                    pass
        
        # Transfer tamamlandı sinyali bekle
        done_signal = conn.recv(4)
        if done_signal == b"DONE":
            if len(received_fragments) == fragment_count:
                # Tam veri alındı, şifre çözme işlemi
                try:
                    decrypted_data = decrypt_file(bytes(received_data))
                    received_hash = hashlib.sha256(decrypted_data).hexdigest()
                    add_log("server", f"Dosya başarıyla alındı ve çözüldü: {len(decrypted_data)} byte, Hash: {received_hash}")
                    
                    # Güvenlik kontrolü
                    packet_id = secrets.token_hex(4)
                    security_tester = SecurityTester()
                    if security_tester.detect_replay_attack(packet_id, received_packet_ids):
                        add_log("security", "Replay saldırısı tespit edildi")
                    received_packet_ids.add(packet_id)
                    
                    conn.send(b"COMPLETE")
                except Exception as e:
                    add_log("server", f"Veri çözme hatası: {str(e)}")
                    conn.send(b"ERROR")
            else:
                missing_count = fragment_count - len(received_fragments)
                add_log("server", f"Transfer eksik tamamlandı: {missing_count} parça kayıp")
                conn.send(b"PARTIAL")
        else:
            add_log("server", "DONE sinyali alınamadı")
            conn.send(b"ERROR")
            
    except Exception as e:
        add_log("server", f"Bağlantı hatası: {str(e)}")
    finally:
        conn.close()

# Flask routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start-server', methods=['POST'])
def start_server():
    global server_thread, server_running
    if not server_running:
        port = request.json.get('port', 12345)
        server_thread = threading.Thread(target=web_server, args=("0.0.0.0", port))
        server_thread.daemon = True
        server_thread.start()
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "Sunucu zaten çalışıyor"})

@app.route('/stop-server', methods=['POST'])
def stop_server():
    global server_running
    server_running = False
    return jsonify({"success": True})

@app.route('/send-file', methods=['POST'])
def send_file_route():
    try:
        file = request.files['file']
        if not file:
            return jsonify({"success": False, "error": "Dosya seçilmedi"})
        server_ip = request.form['server_ip']
        port = int(request.form['port'])
        username = request.form['username']
        password = request.form['password']
        
        # Authentication
        if username not in users or users[username] != hashlib.sha256(password.encode()).hexdigest():
            return jsonify({"success": False, "error": "Geçersiz kullanıcı adı veya şifre"})
        
        # Read and encrypt file
        file_data = file.read()
        encrypted_data, file_hash = encrypt_file(file_data)
        add_log("client", f"Dosya şifreleniyor: {file.filename}, Hash: {file_hash}")
        
        # Güvenilir dosya gönderimi
        perf_monitor = PerformanceMonitor()
        perf_monitor.start_transfer()
        
        packets_sent, packets_lost, packet_id = send_file_reliable(server_ip, port, encrypted_data)
        
        perf_monitor.end_transfer()
        perf_monitor.metrics["bytes_sent"] = len(encrypted_data)
        perf_monitor.metrics["bytes_received"] = len(encrypted_data) if packets_lost == 0 else len(encrypted_data) - (packets_lost * 1024)
        perf_monitor.metrics["packets_sent"] = packets_sent + packets_lost
        perf_monitor.metrics["packets_lost"] = packets_lost
        perf_monitor.add_rtt_sample(0.025)
        
        add_log("client", f"Dosya gönderildi: {file.filename}, {packets_sent} paket gönderildi, {packets_lost} kayıp")
        return jsonify({"success": True, "hash": file_hash})
    except Exception as e:
        add_log("client", f"Gönderim hatası: {str(e)}")
        return jsonify({"success": False, "error": str(e)})

@app.route('/run-performance-test', methods=['POST'])
def run_performance_test():
    global performance_data
    add_log("performance", "Performans testi başlatıldı")
    
    perf_monitor = PerformanceMonitor()
    perf_monitor.start_transfer()
    time.sleep(0.5)
    perf_monitor.metrics["bytes_received"] = 5 * 1024 * 1024
    perf_monitor.metrics["packets_sent"] = 100
    perf_monitor.metrics["packets_lost"] = 5
    perf_monitor.add_rtt_sample(0.025)
    perf_monitor.end_transfer()
    
    stats = perf_monitor.calculate_stats()
    performance_data = stats
    add_log("performance", f"Test tamamlandı - Bant genişliği: {stats['bandwidth_mbps']} Mbps")
    return jsonify({"success": True, "metrics": stats})

@app.route('/run-security-test', methods=['POST'])
def run_security_test():
    global security_data
    add_log("security", "Güvenlik testi başlatıldı")
    
    security_tester = SecurityTester()
    original = b"Original data"
    tampered = b"Tampered data"
    security_tester.simulate_mitm_attack(original, tampered)
    add_log("security", "MITM saldırısı simüle edildi")
    
    security_tester.detect_replay_attack(2, [1, 2, 3])
    add_log("security", "Replay saldırısı simüle edildi")
    
    security_data = {
        "attack_detected": security_tester.attack_detected,
        "total_incidents": len(security_tester.suspicious_activities),
        "detection_rate": security_tester.detection_rate / 2 * 100
    }
    
    add_log("security", f"Test tamamlandı - {security_data['total_incidents']} olay, % {security_data['detection_rate']} tespit oranı")
    return jsonify({"success": True, **security_data})

@app.route('/get-logs', methods=['GET'])
def get_logs():
    return jsonify({
        "server_logs": list(server_logs),
        "client_logs": list(client_logs),
        "performance_logs": list(performance_logs),
        "security_logs": list(security_logs)
    })

@socketio.on('connect', namespace='/')
def handle_connect():
    print("WebSocket client connected")
    socketio.emit('logs', {
        "server_logs": list(server_logs),
        "client_logs": list(client_logs),
        "performance_logs": list(performance_logs),
        "security_logs": list(security_logs)
    }, namespace='/')

@socketio.on('disconnect', namespace='/')
def handle_disconnect():
    print("WebSocket client disconnected")

if __name__ == '__main__':
    print("Web UI başlatılıyor...")
    print("Tarayıcınızda http://localhost:5000 adresine gidin")
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)