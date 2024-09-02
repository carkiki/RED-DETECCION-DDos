import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel, QVBoxLayout, QWidget, QTabWidget, QTextEdit, QHBoxLayout
from PyQt5.QtCore import QThread, pyqtSignal
from matplotlib.figure import Figure
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib import style
from main import BandwidthMonitor, INITIAL_THRESHOLD, MONITOR_INTERVAL, WINDOW_SIZE
import csv

class MonitorThread(QThread):
    update_signal = pyqtSignal(str, str, str, float, float, float, str)

    def __init__(self):
        super().__init__()
        self.monitor = BandwidthMonitor()
        self.running = True

    def run(self):
        for result, threshold_msg, alert_msg, max_traffic, avg_traffic, security_score, arp_scan_results in self.monitor.monitor_bandwidth(
                INITIAL_THRESHOLD, MONITOR_INTERVAL, WINDOW_SIZE):
            if not self.running:
                break

            # Asegúrate de que security_score sea un float, si es una cadena, conviértelo.
            if isinstance(security_score, str):
                try:
                    security_score = float(security_score)
                except ValueError:
                    security_score = 0.0  # Valor predeterminado en caso de error de conversión.

            # Emite el valor de seguridad como float
            self.update_signal.emit(result, threshold_msg, alert_msg, max_traffic, avg_traffic, security_score, arp_scan_results)

    def stop(self):
        self.running = False
        self.monitor.stop_monitoring()
        self.wait()

class LineChart(FigureCanvas):
    def __init__(self, parent=None):
        fig = Figure(figsize=(8, 4), dpi=100)
        self.ax = fig.add_subplot(111)
        super().__init__(fig)
        self.setParent(parent)
        self.traffic_data = []
        self.line, = self.ax.plot([], [], color='red', label='Tráfico')
        style.use('dark_background')
        self.ax.set_facecolor('#2E2E2E')
        self.ax.spines['bottom'].set_color('white')
        self.ax.spines['top'].set_color('white')
        self.ax.spines['right'].set_color('white')
        self.ax.spines['left'].set_color('white')
        self.ax.yaxis.label.set_color('white')
        self.ax.xaxis.label.set_color('white')
        self.ax.tick_params(axis='both', colors='white')
        self.ax.set_ylabel('Tráfico (bytes/s)')
        self.ax.set_title('Uso de Internet en Tiempo Real')
        self.ax.legend()
        self.ax.grid(True, linestyle='--', alpha=0.5, color='grey')

    def update_chart(self, traffic):
        self.traffic_data.append(traffic)

        # Limitar el número de puntos en el gráfico
        if len(self.traffic_data) > 100:
            self.traffic_data.pop(0)

        x = list(range(len(self.traffic_data)))  # Eje X
        self.line.set_data(x, self.traffic_data)
        self.ax.relim()  # Ajustar los límites del eje
        self.ax.autoscale_view()  # Recalcular el rango de los ejes

        self.draw()

class StatsWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout()

        self.label_max_traffic = QLabel("Max Traffic: 0 bytes/s", self)
        self.label_avg_traffic = QLabel("Average Traffic: 0 bytes/s", self)
        self.label_alerts = QLabel("Alerts: None", self)
        self.label_result = QLabel("Current Usage: 0 bytes/s", self)
        self.arp_results = QTextEdit(self)
        self.arp_results.setReadOnly(True)
        self.arp_results.setStyleSheet("background-color: #1E1E1E; color: white;")

        # Estilo para las etiquetas
        self.label_max_traffic.setStyleSheet("color: white;")
        self.label_avg_traffic.setStyleSheet("color: white;")
        self.label_alerts.setStyleSheet("color: white;")
        self.label_result.setStyleSheet("color: white;")

        # Añadir widgets al layout
        layout.addWidget(self.label_result)
        layout.addWidget(self.label_max_traffic)
        layout.addWidget(self.label_avg_traffic)
        layout.addWidget(self.label_alerts)
        layout.addWidget(self.arp_results)

        self.setLayout(layout)
        self.setStyleSheet("background-color: #2E2E2E; color: white;")

    def update_stats(self, result, max_traffic, avg_traffic, alert_msg, arp_scan_results):
        self.label_result.setText(f"Current Usage: {result}")
        self.label_max_traffic.setText(f"Max Traffic: {max_traffic:.2f} bytes/s")
        self.label_avg_traffic.setText(f"Average Traffic: {avg_traffic:.2f} bytes/s")
        self.label_alerts.setText(f"Alerts: {alert_msg}")
        self.arp_results.setPlainText(arp_scan_results)  # Mostrar los resultados del escaneo ARP

class CSVViewer(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.text_edit = QTextEdit(self)
        self.text_edit.setReadOnly(True)
        self.text_edit.setStyleSheet("background-color: #1E1E1E; color: white;")
        layout = QVBoxLayout()
        layout.addWidget(self.text_edit)
        self.setLayout(layout)
        self.setStyleSheet("background-color: #2E2E2E;")
        self.update_csv()

    def update_csv(self):
        try:
            with open('redlocal.csv', 'r') as file:
                reader = csv.reader(file)
                content = "\n".join([", ".join(row) for row in reader])
                self.text_edit.setPlainText(content)
        except FileNotFoundError:
            self.text_edit.setPlainText("No se encontró el archivo redlocal.csv")

class AlertsViewer(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.text_edit = QTextEdit(self)
        self.text_edit.setReadOnly(True)
        self.text_edit.setStyleSheet("background-color: #1E1E1E; color: white;")
        layout = QVBoxLayout()
        layout.addWidget(self.text_edit)
        self.setLayout(layout)
        self.setStyleSheet("background-color: #2E2E2E;")
        self.update_alerts()

    def update_alerts(self):
        try:
            with open('alertas.csv', 'r') as file:
                reader = csv.reader(file)
                content = "\n".join([", ".join(row) for row in reader])
                self.text_edit.setPlainText(content)
        except FileNotFoundError:
            self.text_edit.setPlainText("No se encontró el archivo alertas.csv")

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.initUI()
        
        self.monitor_thread = MonitorThread()
        self.monitor_thread.update_signal.connect(self.update_traffic)
        self.monitor_thread.start()

    def initUI(self):
        self.setWindowTitle("Monitoreo de Red")
        self.resize(800, 800)
        self.setStyleSheet("background-color: #2E2E2E; color: white;")

        self.tab_widget = QTabWidget()
        self.tab_widget.setStyleSheet("QTabBar::tab { color: #D3D3D3; background: #2E2E2E; padding: 5px; }"
                                      "QTabBar::tab:selected { background: #4F4F4F; }"
                                      "QTabWidget::pane { border: 1px solid #444; }")

        # Primer pestaña: Gráfico Lineal y Caja CSV
        chart_tab = QWidget()
        chart_layout = QHBoxLayout()

        # Crear y agregar gráfico
        self.line_chart = LineChart(self)
        chart_layout.addWidget(self.line_chart)

        # Crear y agregar caja para mostrar CSV
        self.csv_viewer = CSVViewer(self)
        chart_layout.addWidget(self.csv_viewer)

        chart_tab.setLayout(chart_layout)
        self.tab_widget.addTab(chart_tab, "Gráfico de Tráfico y CSV")

        # Segunda pestaña: Estadísticas
        self.stats_widget = StatsWidget(self)
        stats_tab = QWidget()
        stats_layout = QVBoxLayout()
        stats_layout.addWidget(self.stats_widget)
        stats_tab.setLayout(stats_layout)
        self.tab_widget.addTab(stats_tab, "Estadísticas")

        # Tercera pestaña: Alertas
        self.alerts_viewer = AlertsViewer(self)
        alerts_tab = QWidget()
        alerts_layout = QVBoxLayout()
        alerts_layout.addWidget(self.alerts_viewer)
        alerts_tab.setLayout(alerts_layout)
        self.tab_widget.addTab(alerts_tab, "Alertas")

        self.setCentralWidget(self.tab_widget)

    def update_traffic(self, result, threshold_msg, alert_msg, max_traffic, avg_traffic, security_score, arp_scan_results):
        self.line_chart.update_chart(avg_traffic)  # Usar avg_traffic en el gráfico o el dato relevante.
        self.csv_viewer.update_csv()
        self.stats_widget.update_stats(result, max_traffic, avg_traffic, alert_msg, arp_scan_results)
        self.alerts_viewer.update_alerts()

    def closeEvent(self, event):
        self.monitor_thread.stop()
        event.accept()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
