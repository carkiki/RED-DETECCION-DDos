import psutil
import time
import csv
import subprocess
from datetime import datetime

# Parámetros de monitoreo
INITIAL_THRESHOLD = 1024 * 1024  # Umbral inicial de tráfico en bytes por segundo (1 MB/s)
MONITOR_INTERVAL = 1  # Intervalo de monitoreo en segundos
WINDOW_SIZE = 10  # Tamaño de la ventana para la media móvil
HISTORY_FILE = 'redlocal.csv'  # Archivo para guardar el historial
ALERTS_FILE = 'alertas.csv'  # Archivo para guardar las alertas

def log_traffic_to_file(timestamp, recv_per_sec, sent_per_sec):
    with open(HISTORY_FILE, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([timestamp, recv_per_sec, sent_per_sec])

def log_alert_to_file(timestamp, reason, recv_per_sec, sent_per_sec):
    with open(ALERTS_FILE, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([timestamp, reason, recv_per_sec, sent_per_sec])

def perform_arp_scan():
    """Ejecuta un escaneo ARP y retorna los resultados."""
    try:
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return f"Error realizando ARP scan: {str(e)}"

def calculate_security_score():
    """Calcula una puntuación de seguridad basada en el resultado del escaneo ARP."""
    arp_results = perform_arp_scan()
    num_devices = arp_results.count('\n')  # Contar número de dispositivos en el escaneo ARP

    # Calcular la puntuación de seguridad (esto es un ejemplo y puede ser modificado)
    if num_devices > 10:
        return 1.0  # Puntuación baja
    elif num_devices > 5:
        return 2.0  # Puntuación media
    else:
        return 3.0  # Puntuación alta


class BandwidthMonitor:
    def __init__(self):
        self.prev_recv = psutil.net_io_counters().bytes_recv
        self.prev_sent = psutil.net_io_counters().bytes_sent
        self.traffic_history = []
        self.max_traffic = 0
        self.running = True

    def monitor_bandwidth(self, initial_threshold, interval, window_size):
        while self.running:
            time.sleep(interval)
            curr_recv = psutil.net_io_counters().bytes_recv
            curr_sent = psutil.net_io_counters().bytes_sent

            recv_per_sec = (curr_recv - self.prev_recv) / interval
            sent_per_sec = (curr_sent - self.prev_sent) / interval

            total_traffic = recv_per_sec + sent_per_sec
            self.traffic_history.append(total_traffic)
            if len(self.traffic_history) > window_size:
                self.traffic_history.pop(0)

            avg_traffic = sum(self.traffic_history) / len(self.traffic_history) if self.traffic_history else 0
            dynamic_threshold = initial_threshold + avg_traffic * 0.5

            result = f"Recibido: {recv_per_sec / 1024:.2f} KB/s, Enviado: {sent_per_sec / 1024:.2f} KB/s"
            threshold_msg = f"Umbral dinámico: {dynamic_threshold / 1024 / 1024:.2f} MB/s"
            alert_msg = ""
            if recv_per_sec > dynamic_threshold or sent_per_sec > dynamic_threshold:
                alert_msg = f"Alerta: Tráfico anormal detectado. Recibido: {recv_per_sec / 1024 / 1024:.2f} MB/s, Enviado: {sent_per_sec / 1024 / 1024:.2f} MB/s"
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                log_alert_to_file(timestamp, "Tráfico anormal detectado", recv_per_sec, sent_per_sec)

            self.max_traffic = max(self.max_traffic, total_traffic)
            arp_scan_results = perform_arp_scan()
            security_score = calculate_security_score()

            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_traffic_to_file(timestamp, recv_per_sec, sent_per_sec)

            self.prev_recv = curr_recv
            self.prev_sent = curr_sent

            yield result, threshold_msg, alert_msg, self.max_traffic, avg_traffic, security_score, arp_scan_results

    def get_max_traffic(self):
        return self.max_traffic

    def get_average_traffic(self):
        return sum(self.traffic_history) / len(self.traffic_history) if self.traffic_history else 0

    def stop_monitoring(self):
        self.running = False
