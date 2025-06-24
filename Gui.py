import sys
import os
import yara
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QPushButton, QTextEdit, QLabel,
    QVBoxLayout, QWidget, QFileDialog
)
from PyQt5.QtCore import QThread, pyqtSignal

# Path to YARA rule
YARA_RULE_FILE = "C:/Users/student/Desktop/ICS_Lab/modbus_backdoor.yar"
WATCH_FOLDER = "C:/Users/student/Desktop/ICS_Lab/projects/"

class YaraScanner(QThread):
    log_signal = pyqtSignal(str)

    def __init__(self, path, parent=None):
        super().__init__(parent)
        self.path = path
        self.running = True
        try:
            self.rules = yara.compile(filepath=YARA_RULE_FILE)
        except Exception as e:
            print(f"[!] YARA Load Error: {e}")
            self.rules = None

    def run(self):
        if not self.rules:
            self.log_signal.emit("[!] YARA rules could not be loaded. Monitoring aborted.")
            return

        class Handler(FileSystemEventHandler):
            def __init__(self, log_signal, rules):
                self.log_signal = log_signal
                self.rules = rules

            def on_modified(self, event):
                if event.src_path.endswith(".xml"):
                    try:
                        matches = self.rules.match(event.src_path)
                        if matches:
                            self.log_signal.emit(f"[✔] THREAT DETECTED: {event.src_path} - {matches}")
                        else:
                            self.log_signal.emit(f"[✓] CLEAN: {event.src_path}")
                    except Exception as e:
                        self.log_signal.emit(f"[!] ERROR: {str(e)}")

        observer = Observer()
        handler = Handler(self.log_signal, self.rules)
        observer.schedule(handler, self.path, recursive=True)
        observer.start()

        while self.running:
            time.sleep(1)

        observer.stop()
        observer.join()

    def stop(self):
        self.running = False

class YaraGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SCADA YARA Monitor Dashboard")
        self.setGeometry(100, 100, 800, 600)

        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)

        self.status_label = QLabel("Status: Idle")
        self.start_button = QPushButton("Start Monitoring")
        self.stop_button = QPushButton("Stop Monitoring")
        self.export_button = QPushButton("Export Logs")

        self.start_button.clicked.connect(self.start_monitoring)
        self.stop_button.clicked.connect(self.stop_monitoring)
        self.export_button.clicked.connect(self.export_logs)

        layout = QVBoxLayout()
        layout.addWidget(self.status_label)
        layout.addWidget(self.log_area)
        layout.addWidget(self.start_button)
        layout.addWidget(self.stop_button)
        layout.addWidget(self.export_button)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        self.scanner = None

    def start_monitoring(self):
        self.log_area.clear()
        self.status_label.setText("Status: Monitoring...")
        try:
            self.scanner = YaraScanner(WATCH_FOLDER)
            self.scanner.log_signal.connect(self.update_log)
            self.scanner.start()
        except Exception as e:
            self.update_log(f"[!] GUI ERROR: {str(e)}")
            self.status_label.setText("Status: ERROR")

    def stop_monitoring(self):
        if self.scanner:
            self.scanner.stop()
            self.status_label.setText("Status: Stopped")

    def update_log(self, message):
        print(message)  # For debug visibility
        self.log_area.append(message)

    def export_logs(self):
        filename, _ = QFileDialog.getSaveFileName(self, "Save Log", "scan_log.txt", "Text Files (*.txt)")
        if filename:
            with open(filename, 'w') as f:
                f.write(self.log_area.toPlainText())

if __name__ == '__main__':
    if not os.path.exists(WATCH_FOLDER):
        print(f"[!] Watch folder not found: {WATCH_FOLDER}")
        sys.exit(1)

    app = QApplication(sys.argv)
    gui = YaraGUI()
    gui.show()
    sys.exit(app.exec_())
