import subprocess
import time

def generate_network_traffic():
    # Simula tráfico de red usando ping
    print("Iniciando simulación de tráfico de red...")
    try:
        subprocess.Popen(['ping', '8.8.8.8', '-t'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(10)  # Genera tráfico durante 10 segundos
    except Exception as e:
        print(f"Error al generar tráfico: {e}")

if __name__ == "__main__":
    generate_network_traffic()
