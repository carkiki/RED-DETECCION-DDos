from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel
from main import BandwidthMonitor, INITIAL_THRESHOLD, MONITOR_INTERVAL, WINDOW_SIZE

class StatsWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout()

        # Labels para mostrar estadísticas
        self.label_max_traffic = QLabel("Max Traffic: 0 bytes/s", self)
        self.label_max_traffic.setStyleSheet("color: white;")
        layout.addWidget(self.label_max_traffic)

        self.setLayout(layout)
        self.setStyleSheet("background-color: #2E2E2E; color: white;")

    def update_stats(self, max_traffic):
        self.label_max_traffic.setText(f"Max Traffic: {max_traffic:.2f} bytes/s")
