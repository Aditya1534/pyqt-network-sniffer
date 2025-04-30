import sys
import csv
import yaml
import random
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QWidget, QPushButton, QTableWidget,
    QTableWidgetItem, QLabel, QComboBox, QHBoxLayout, QTextEdit
)
from PyQt5.QtCore import QTimer, QThread, pyqtSignal
from scapy.all import sniff, IP, TCP, UDP, Raw, send

# Predefined payloads dictionary
payloads = {
    "ping": b"\x08\x00\xe5\x48\x00\x01\x00\x01",
    "sql_injection": b"' OR 1=1--",
    "xss_test": b"<script>alert('XSS')</script>",
    "hello_msg": b"Hello from Packet Sniffer"
}

# ✅ Sniffer thread class
class SnifferThread(QThread):
    packet_captured = pyqtSignal(object)

    def __init__(self):
        super().__init__()
        self.running = True

    def run(self):
        sniff(prn=self.emit_packet, store=False, stop_filter=lambda x: not self.running)

    def emit_packet(self, pkt):
        self.packet_captured.emit(pkt)

    def stop(self):
        self.running = False

# ✅ Main GUI Class
class PacketSniffer(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Packet Sniffer & Injector")
        self.resize(1000, 600)
        self.packets = []
        self.unique_ips = set()
        self.sniffer_thread = None

        layout = QVBoxLayout()

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["Time", "Source", "Destination", "Protocol", "Length", "Info"])
        layout.addWidget(self.table)

        # Controls layout
        controls = QHBoxLayout()

        self.protocol_dropdown = QComboBox()
        self.protocol_dropdown.addItems(["TCP", "UDP"])
        controls.addWidget(QLabel("Protocol:"))
        controls.addWidget(self.protocol_dropdown)

        self.ip_dropdown = QComboBox()
        controls.addWidget(QLabel("Destination IP:"))
        controls.addWidget(self.ip_dropdown)

        self.payload_dropdown = QComboBox()
        self.payload_dropdown.addItems(list(payloads.keys()))
        controls.addWidget(QLabel("Payload:"))
        controls.addWidget(self.payload_dropdown)

        self.inject_button = QPushButton("Inject Packet")
        self.inject_button.clicked.connect(self.inject_packet)
        controls.addWidget(self.inject_button)

        # ✅ Start & Stop buttons
        self.start_button = QPushButton("Start Sniffing")
        self.start_button.clicked.connect(self.start_sniffing)
        controls.addWidget(self.start_button)

        self.stop_button = QPushButton("Stop Sniffing")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_sniffing)
        controls.addWidget(self.stop_button)

        # ✅ Export buttons
        self.export_csv_btn = QPushButton("Export to CSV")
        self.export_csv_btn.clicked.connect(self.export_to_csv)
        controls.addWidget(self.export_csv_btn)

        self.export_yaml_btn = QPushButton("Export to YAML")
        self.export_yaml_btn.clicked.connect(self.export_to_yaml)
        controls.addWidget(self.export_yaml_btn)

        layout.addLayout(controls)

        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        layout.addWidget(self.log_output)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        self.timer = QTimer()
        self.timer.timeout.connect(self.update_ip_dropdown)
        self.timer.start(2000)

    # ✅ Start sniffing
    def start_sniffing(self):
        self.sniffer_thread = SnifferThread()
        self.sniffer_thread.packet_captured.connect(self.process_packet)
        self.sniffer_thread.start()
        self.log_output.append("🔍 Started sniffing packets.")
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)

    # ✅ Stop sniffing
    def stop_sniffing(self):
        if self.sniffer_thread:
            self.sniffer_thread.stop()
            self.sniffer_thread.wait()
            self.log_output.append("🛑 Stopped sniffing.")
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    # ✅ Process captured packet
    def process_packet(self, packet):
        proto = "OTHER"
        length = len(packet)
        src = dst = info = "N/A"

        if IP in packet:
            ip_layer = packet[IP]
            src = ip_layer.src
            dst = ip_layer.dst
            self.unique_ips.update([src, dst])

            if TCP in packet:
                proto = "HTTPS" if (ip_layer.dport == 443 or ip_layer.sport == 443) else "TCP"
            elif UDP in packet:
                proto = "UDP"

            if Raw in packet:
                try:
                    info = packet[Raw].load[:40].decode('utf-8', errors='ignore')
                except:
                    info = "Raw Data"
            else:
                info = "No Payload"

            self.packets.append((src, dst, proto, length, info))

            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(str(row + 1)))
            self.table.setItem(row, 1, QTableWidgetItem(src))
            self.table.setItem(row, 2, QTableWidgetItem(dst))
            self.table.setItem(row, 3, QTableWidgetItem(proto))
            self.table.setItem(row, 4, QTableWidgetItem(str(length)))
            self.table.setItem(row, 5, QTableWidgetItem(info))

    # ✅ Update dropdown with IPs
    def update_ip_dropdown(self):
        current = self.ip_dropdown.currentText()
        self.ip_dropdown.clear()
        self.ip_dropdown.addItems(sorted(self.unique_ips))
        index = self.ip_dropdown.findText(current)
        if index >= 0:
            self.ip_dropdown.setCurrentIndex(index)

    # ✅ Inject packet logic
    def inject_packet(self):
        dst_ip = self.ip_dropdown.currentText()
        proto = self.protocol_dropdown.currentText()
        payload_key = self.payload_dropdown.currentText()
        payload_data = payloads.get(payload_key, b"")

        if not dst_ip:
            self.log_output.append("❌ No destination IP selected.")
            return

        if proto == "TCP":
            pkt = IP(dst=dst_ip)/TCP(dport=80, sport=random.randint(1024, 65535))/Raw(load=payload_data)
        elif proto == "UDP":
            pkt = IP(dst=dst_ip)/UDP(dport=53, sport=random.randint(1024, 65535))/Raw(load=payload_data)
        else:
            self.log_output.append("❌ Unsupported protocol selected.")
            return

        send(pkt, verbose=0)
        self.log_output.append(f"✅ Injected {proto} packet to {dst_ip} with payload: {payload_key}")

    # ✅ Export to CSV
    def export_to_csv(self):
        with open("packets_export.csv", "w", newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Source", "Destination", "Protocol", "Length", "Info"])
            for pkt in self.packets:
                writer.writerow(pkt)
        self.log_output.append("📁 Exported packets to packets_export.csv")

    # ✅ Export to YAML
    def export_to_yaml(self):
        with open("packets_export.yaml", "w") as f:
            data = [
                {"Source": p[0], "Destination": p[1], "Protocol": p[2], "Length": p[3], "Info": p[4]}
                for p in self.packets
            ]
            yaml.dump(data, f)
        self.log_output.append("📁 Exported packets to packets_export.yaml")

# ✅ Run the app
if __name__ == '__main__':
    app = QApplication(sys.argv)
    sniffer = PacketSniffer()
    sniffer.show()
    sys.exit(app.exec_())
