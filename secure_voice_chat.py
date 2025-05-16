import sys
import time
import socket
import threading
import numpy as np
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QLabel, QPushButton, QTextEdit, 
                            QGroupBox, QRadioButton, QLineEdit, QProgressBar,
                            QListWidget, QSlider)
from PyQt5.QtCore import Qt, pyqtSignal, QObject, QTimer
import pyaudio
import rsa
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Configuration
HOST_PORT_TCP = 5008  # For key exchange
HOST_PORT_UDP = 5009  # For audio data
BUFFER_SIZE = 4096
AES_KEY_SIZE = 16
AES_IV_SIZE = 16
FORMAT = pyaudio.paInt16
CHANNELS = 1
RATE = 44100
CHUNK = 1024
LATENCY_UPDATE_INTERVAL = 2000  # ms

class VoiceSignals(QObject):
    message_received = pyqtSignal(str)
    participant_update = pyqtSignal(list)
    quality_update = pyqtSignal(dict)

class VoiceChatGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        
        # Initialize components
        self.public_key, self.private_key = rsa.newkeys(2048)
        self.clients = []
        self.running = False
        self.audio = pyaudio.PyAudio()
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Audio control
        self.mic_active = True
        self.speaker_active = True
        self.speaker_volume = 80  # Default speaker volume (0-100)
        self.input_stream = None
        self.output_stream = None
        
        # Network metrics
        self.last_packet_time = 0
        self.packet_loss = 0
        self.latency = 0
        self.signal_strength = 100
        
        # Signals
        self.signals = VoiceSignals()
        self.signals.message_received.connect(self.log_message)
        self.signals.participant_update.connect(self.update_participants_list)
        self.signals.quality_update.connect(self.update_quality_indicators)
        
        self.init_ui()
        self.init_quality_monitor()

    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("SecureVoice Pro")
        self.setGeometry(100, 100, 900, 600)
        
        # Main widget
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QHBoxLayout()
        main_widget.setLayout(main_layout)
        
        # Left panel - Controls
        control_panel = QGroupBox("Session Controls")
        control_layout = QVBoxLayout()
        
        # Mode selection
        mode_group = QGroupBox("Session Mode")
        self.host_radio = QRadioButton("Host Session")
        self.join_radio = QRadioButton("Join Session")
        self.host_radio.setChecked(True)
        
        mode_layout = QVBoxLayout()
        mode_layout.addWidget(self.host_radio)
        mode_layout.addWidget(self.join_radio)
        mode_group.setLayout(mode_layout)
        
        # Host IP input
        self.host_ip_label = QLabel("Host IP:")
        self.host_ip_entry = QLineEdit("127.0.0.1")
        self.host_ip_entry.setEnabled(False)
        
        # Connection Quality Group
        quality_group = QGroupBox("Connection Status")
        quality_layout = QVBoxLayout()
        
        self.quality_bars = QProgressBar()
        self.quality_bars.setRange(0, 100)
        self.quality_bars.setTextVisible(False)
        
        self.latency_label = QLabel("Latency: -- ms")
        self.packet_loss_label = QLabel("Packet Loss: 0%")
        self.encryption_label = QLabel("Encryption: Inactive")
        
        # Speaker Volume Control
        self.volume_label = QLabel("Speaker Volume: 80%")
        self.volume_slider = QSlider(Qt.Horizontal)
        self.volume_slider.setRange(0, 100)
        self.volume_slider.setValue(80)
        self.volume_slider.valueChanged.connect(self.update_speaker_volume)
        
        # Audio Toggles
        self.mic_toggle = QPushButton("🎤 Microphone: ON")
        self.mic_toggle.setCheckable(True)
        self.mic_toggle.setChecked(True)
        self.mic_toggle.clicked.connect(self.toggle_microphone)
        
        self.speaker_toggle = QPushButton("🔈 Speaker: ON")
        self.speaker_toggle.setCheckable(True)
        self.speaker_toggle.setChecked(True)
        self.speaker_toggle.clicked.connect(self.toggle_speaker)
        
        quality_layout.addWidget(self.quality_bars)
        quality_layout.addWidget(self.latency_label)
        quality_layout.addWidget(self.packet_loss_label)
        quality_layout.addWidget(self.encryption_label)
        quality_layout.addWidget(self.volume_label)
        quality_layout.addWidget(self.volume_slider)
        quality_layout.addWidget(self.mic_toggle)
        quality_layout.addWidget(self.speaker_toggle)
        quality_group.setLayout(quality_layout)
        
        # Action buttons
        self.start_btn = QPushButton("Start Session")
        self.start_btn.clicked.connect(self.start_session)
        
        self.stop_btn = QPushButton("Stop Session")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_session)
        
        control_layout.addWidget(mode_group)
        control_layout.addWidget(self.host_ip_label)
        control_layout.addWidget(self.host_ip_entry)
        control_layout.addWidget(quality_group)
        control_layout.addWidget(self.start_btn)
        control_layout.addWidget(self.stop_btn)
        control_layout.addStretch()
        control_panel.setLayout(control_layout)
        
        # Right panel - Status
        status_panel = QWidget()
        status_layout = QVBoxLayout()
        
        self.status_log = QTextEdit()
        self.status_log.setReadOnly(True)
        
        participants_group = QGroupBox("Participants")
        self.participants_list = QListWidget()
        
        participants_layout = QVBoxLayout()
        participants_layout.addWidget(self.participants_list)
        participants_group.setLayout(participants_layout)
        
        status_layout.addWidget(self.status_log)
        status_layout.addWidget(participants_group)
        status_panel.setLayout(status_layout)
        
        main_layout.addWidget(control_panel, stretch=1)
        main_layout.addWidget(status_panel, stretch=2)
        
        self.host_radio.toggled.connect(self.update_mode)
        
        # Set styles
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f5f5f5;
                font-family: Segoe UI, Arial;
            }
            QGroupBox {
                border: 1px solid #ddd;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 15px;
                font-weight: bold;
            }
            QTextEdit, QListWidget {
                border: 1px solid #ddd;
                border-radius: 3px;
                padding: 5px;
            }
            QSlider::handle:horizontal {
                background: #4CAF50;
                width: 10px;
                margin: -2px 0;
                border-radius: 5px;
            }
            QPushButton {
                padding: 5px;
                border: 1px solid #aaa;
                border-radius: 3px;
            }
            QPushButton:checked {
                background-color: #4CAF50;
                color: white;
            }
        """)

    def update_speaker_volume(self, value):
        """Update speaker volume level (0-100)"""
        self.speaker_volume = value
        self.volume_label.setText(f"Speaker Volume: {value}%")
        self.log_message(f"Speaker volume set to {value}%")

    def adjust_speaker_volume(self, data):
        """Adjust volume for speaker output only"""
        if self.speaker_volume == 80:  # Default level (no adjustment)
            return data
        
        # Convert volume level to multiplier (0.5-1.5 range for safety)
        multiplier = 0.5 + (self.speaker_volume / 100)
        
        # Convert bytes to numpy array of 16-bit samples
        samples = np.frombuffer(data, dtype=np.int16)
        
        # Apply volume adjustment with clipping protection
        adjusted_samples = np.clip(samples * multiplier, -32768, 32767).astype(np.int16)
        
        # Convert back to bytes
        return adjusted_samples.tobytes()

    def log_message(self, message):
        """Add message to status log"""
        self.status_log.append(message)
        self.status_log.ensureCursorVisible()

    def update_participants_list(self, participants):
        """Update the participants list"""
        self.participants_list.clear()
        for participant in participants:
            self.participants_list.addItem(participant)

    def update_mode(self, checked):
        """Update UI based on selected mode"""
        self.host_ip_entry.setEnabled(not self.host_radio.isChecked())

    def init_quality_monitor(self):
        """Initialize the network quality monitoring timer"""
        self.quality_timer = QTimer()
        self.quality_timer.timeout.connect(self.update_network_metrics)
        self.quality_timer.start(LATENCY_UPDATE_INTERVAL)

    def update_network_metrics(self):
        """Calculate and emit network quality metrics"""
        if not self.running:
            return
            
        # Simulate metrics - replace with actual calculations
        metrics = {
            'latency': self.simulate_latency(),
            'packet_loss': self.simulate_packet_loss(),
            'signal_strength': self.simulate_signal_strength()
        }
        self.signals.quality_update.emit(metrics)

    def simulate_latency(self):
        """Simulate latency between 20-200ms"""
        return 20 + (hash(str(time.time())) % 180)

    def simulate_packet_loss(self):
        """Simulate packet loss between 0-5%"""
        return hash(str(time.time())) % 6

    def simulate_signal_strength(self):
        """Simulate signal strength between 60-100%"""
        return 60 + (hash(str(time.time())) % 41)

    def update_quality_indicators(self, metrics):
        """Update UI with new quality metrics"""
        self.latency = metrics.get('latency', 0)
        self.packet_loss = metrics.get('packet_loss', 0)
        self.signal_strength = metrics.get('signal_strength', 100)
        
        self.latency_label.setText(f"Latency: {self.latency}ms")
        self.packet_loss_label.setText(f"Packet Loss: {self.packet_loss}%")
        self.quality_bars.setValue(self.signal_strength)
        
        # Update encryption status when connection is active
        if self.running:
            self.encryption_label.setText("Encryption: AES-128 Active")
        else:
            self.encryption_label.setText("Encryption: Inactive")

    def toggle_microphone(self):
        """Toggle microphone on/off"""
        self.mic_active = self.mic_toggle.isChecked()
        status = "ON" if self.mic_active else "OFF"
        self.mic_toggle.setText(f"🎤 Microphone: {status}")
        self.log_message(f"Microphone turned {status}")

    def toggle_speaker(self):
        """Toggle speaker on/off"""
        self.speaker_active = self.speaker_toggle.isChecked()
        status = "ON" if self.speaker_active else "OFF"
        self.speaker_toggle.setText(f"🔈 Speaker: {status}")
        self.log_message(f"Speaker turned {status}")

    def start_session(self):
        """Start a new voice chat session"""
        if self.host_radio.isChecked():
            threading.Thread(target=self.start_host, daemon=True).start()
        else:
            host_ip = self.host_ip_entry.text().strip()
            if not host_ip:
                self.log_message("Error: Please enter host IP address")
                return
            threading.Thread(target=self.join_session, args=(host_ip,), daemon=True).start()
        
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.host_radio.setEnabled(False)
        self.join_radio.setEnabled(False)
        self.host_ip_entry.setEnabled(False)

    def stop_session(self):
        """Stop the current session"""
        self.running = False
        self.cleanup()
        self.log_message("Session stopped")
        
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.host_radio.setEnabled(True)
        self.join_radio.setEnabled(True)
        self.update_mode(True)

    def start_host(self):
        """Start hosting a voice chat session"""
        self.running = True
        self.signals.message_received.emit("Starting host session...")
        
        # TCP server for key exchange
        tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp_server.bind(('', HOST_PORT_TCP))
        tcp_server.listen(5)
        
        # UDP server for audio
        self.udp_socket.bind(('', HOST_PORT_UDP))
        
        self.signals.message_received.emit(f"🔗 Listening for TCP connections on port {HOST_PORT_TCP}...")
        self.signals.message_received.emit(f"🔗 UDP audio port: {HOST_PORT_UDP}")

        def handle_client(client_socket, address):
            self.signals.message_received.emit(f"✅ New connection from {address}")
            try:
                # Send our public key first
                client_socket.sendall(self.public_key.save_pkcs1())
                
                # Receive client's public key
                client_public_key = rsa.PublicKey.load_pkcs1(client_socket.recv(1024))
                self.signals.message_received.emit(f"🔑 Received public key from {address}")

                # Receive client's UDP port
                client_udp_port = int.from_bytes(client_socket.recv(4), 'big')
                client_udp_addr = (address[0], client_udp_port)
                self.signals.message_received.emit(f"📡 Client UDP port: {client_udp_port}")

                # Generate AES key and IV
                aes_key = get_random_bytes(AES_KEY_SIZE)
                aes_iv = get_random_bytes(AES_IV_SIZE)

                # Encrypt and send AES key and IV
                encrypted_key = rsa.encrypt(aes_key, client_public_key)
                encrypted_iv = rsa.encrypt(aes_iv, client_public_key)
                
                client_socket.sendall(len(encrypted_key).to_bytes(2, 'big') + encrypted_key)
                client_socket.sendall(len(encrypted_iv).to_bytes(2, 'big') + encrypted_iv)
                self.signals.message_received.emit(f"🔒 Sent AES key and IV to {address}")

                # Add client to list
                with threading.Lock():
                    self.clients.append((client_udp_addr, aes_key, aes_iv))
                    self.signals.participant_update.emit([f"{addr[0]}:{addr[1]}" for addr, _, _ in self.clients])

                # Start receiving audio via UDP
                threading.Thread(target=self.receive_audio_udp, daemon=True).start()

            except Exception as e:
                self.signals.message_received.emit(f"⚠ Error with client {address}: {str(e)}")
                client_socket.close()

        def accept_connections():
            while self.running:
                try:
                    client_socket, address = tcp_server.accept()
                    threading.Thread(target=handle_client, args=(client_socket, address), daemon=True).start()
                except Exception as e:
                    if self.running:
                        self.signals.message_received.emit(f"⚠ Error accepting connection: {str(e)}")

        threading.Thread(target=accept_connections, daemon=True).start()
        self.stream_audio_udp()

        tcp_server.close()

    def join_session(self, host_ip):
        """Join an existing voice chat session"""
        self.running = True
        self.signals.message_received.emit(f"Connecting to host at {host_ip}...")
        
        tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        try:
            tcp_socket.connect((host_ip, HOST_PORT_TCP))
            self.signals.message_received.emit(f"🔗 Connected to host at {host_ip}:{HOST_PORT_TCP}")
            
            # Exchange public keys
            host_public_key = rsa.PublicKey.load_pkcs1(tcp_socket.recv(1024))
            tcp_socket.sendall(self.public_key.save_pkcs1())
            
            # Send our UDP port
            self.udp_socket.bind(('', 0))
            udp_port = self.udp_socket.getsockname()[1]
            tcp_socket.sendall(udp_port.to_bytes(4, 'big'))
            self.signals.message_received.emit(f"📡 Our UDP port: {udp_port}")

            # Receive AES key and IV
            key_length = int.from_bytes(tcp_socket.recv(2), 'big')
            encrypted_key = tcp_socket.recv(key_length)
            aes_key = rsa.decrypt(encrypted_key, self.private_key)

            iv_length = int.from_bytes(tcp_socket.recv(2), 'big')
            encrypted_iv = tcp_socket.recv(iv_length)
            aes_iv = rsa.decrypt(encrypted_iv, self.private_key)

            self.signals.message_received.emit("🔓 AES key and IV successfully decrypted.")
            
            host_udp_addr = (host_ip, HOST_PORT_UDP)
            self.clients.append((host_udp_addr, aes_key, aes_iv))
            self.signals.participant_update.emit([f"{host_ip}:{HOST_PORT_UDP}"])
            
            threading.Thread(target=self.receive_audio_udp, daemon=True).start()
            self.stream_audio_udp()

        except Exception as e:
            self.signals.message_received.emit(f"⚠ Error connecting to host: {str(e)}")
            self.stop_session()
        finally:
            tcp_socket.close()

    def stream_audio_udp(self):
        """Stream audio to connected clients"""
        self.signals.message_received.emit("🎤 Starting audio streaming...")
        
        self.input_stream = self.audio.open(
            format=FORMAT,
            channels=CHANNELS,
            rate=RATE,
            input=True,
            frames_per_buffer=CHUNK
        )

        try:
            while self.running:
                try:
                    if self.mic_active:
                        data = self.input_stream.read(CHUNK, exception_on_overflow=False)
                        
                        for client_info in self.clients[:]:
                            client_addr, aes_key, aes_iv = client_info
                            try:
                                cipher = AES.new(aes_key, AES.MODE_CFB, iv=aes_iv)
                                encrypted_data = cipher.encrypt(data)
                                self.udp_socket.sendto(encrypted_data, client_addr)
                            except Exception as e:
                                self.signals.message_received.emit(f"⚠ Client error: {str(e)}")
                                with threading.Lock():
                                    if client_info in self.clients:
                                        self.clients.remove(client_info)
                    else:
                        threading.Event().wait(0.01)
                        
                except Exception as e:
                    self.signals.message_received.emit(f"⚠ Streaming error: {str(e)}")
                    continue

        except Exception as e:
            if self.running:
                self.signals.message_received.emit(f"⚠ Audio streaming error: {str(e)}")
        finally:
            if self.input_stream:
                self.input_stream.stop_stream()
                self.input_stream.close()

    def receive_audio_udp(self):
        """Receive and play audio data with volume adjustment"""
        self.signals.message_received.emit("🔊 Starting audio reception...")
        
        self.output_stream = self.audio.open(
            format=FORMAT,
            channels=CHANNELS,
            rate=RATE,
            output=True,
            frames_per_buffer=CHUNK
        )

        try:
            while self.running:
                try:
                    encrypted_data, addr = self.udp_socket.recvfrom(BUFFER_SIZE)
                    if not encrypted_data:
                        continue

                    if self.speaker_active:
                        client_info = next((c for c in self.clients if c[0] == addr), None)
                        if client_info:
                            _, aes_key, aes_iv = client_info
                            cipher = AES.new(aes_key, AES.MODE_CFB, iv=aes_iv)
                            decrypted_data = cipher.decrypt(encrypted_data)
                            
                            # Apply speaker volume adjustment
                            adjusted_data = self.adjust_speaker_volume(decrypted_data)
                            self.output_stream.write(adjusted_data)

                except Exception as e:
                    self.signals.message_received.emit(f"⚠ Receiving error: {str(e)}")
                    continue

        except Exception as e:
            if self.running:
                self.signals.message_received.emit(f"⚠ Audio playback error: {str(e)}")
        finally:
            if self.output_stream:
                self.output_stream.stop_stream()
                self.output_stream.close()

    def cleanup(self):
        """Clean up resources"""
        self.signals.message_received.emit("Cleaning up resources...")
        
        if hasattr(self, 'input_stream') and self.input_stream:
            self.input_stream.stop_stream()
            self.input_stream.close()
        if hasattr(self, 'output_stream') and self.output_stream:
            self.output_stream.stop_stream()
            self.output_stream.close()
        
        if hasattr(self, 'udp_socket') and self.udp_socket:
            self.udp_socket.close()
        
        with threading.Lock():
            self.clients.clear()
            self.signals.participant_update.emit([])
        
        if hasattr(self, 'audio') and self.audio:
            self.audio.terminate()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = VoiceChatGUI()
    window.show()
    sys.exit(app.exec_())