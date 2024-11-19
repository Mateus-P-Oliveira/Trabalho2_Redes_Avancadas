import threading
from scapy.all import sniff
import time
import sys
import json
import logging

# Configure logging
logging.basicConfig(
    filename='/tmp/probe_log.txt',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Estruturas das tabelas RMON
etherStatsTable = {}
etherHistoryTable = []
historyControlTable = []
alarmTable = []
eventTable = []

# Arquivos para salvar as tabelas
ether_stats_file = "etherStatsTable.json"
ether_history_file = "etherHistoryTable.json"

# Lock para acessar dados compartilhados entre threads
data_lock = threading.Lock()

# Variáveis compartilhadas
packet_count = 0

# Função para capturar pacotes
def capture_packets(interface):
    logging.info(f"Iniciando captura de pacotes na interface {interface}...")
    sniff(iface=interface, prn=process_packet, store=False, promisc=True)

# Função para processar pacotes
def process_packet(packet):
    global packet_count
    with data_lock:
        packet_count += 1
        src_mac = packet.src if hasattr(packet, 'src') else "unknown"
        packet_size = len(packet)

        if src_mac not in etherStatsTable:
            etherStatsTable[src_mac] = {
                'total_packets': 0,
                'total_bytes': 0,
                'unicast_packets': 0,
                'multicast_packets': 0,
                'broadcast_packets': 0,
                'average_packet_size': 0
            }
        stats = etherStatsTable[src_mac]
        stats['total_packets'] += 1
        stats['total_bytes'] += packet_size
        stats['average_packet_size'] = stats['total_bytes'] / stats['total_packets']

        # Identifica tipo de pacote
        if hasattr(packet, 'dst') and packet.dst == "ff:ff:ff:ff:ff:ff":
            stats['broadcast_packets'] += 1
        elif hasattr(packet, 'type') and packet.type == 0x0800:  # IPv4
            stats['unicast_packets'] += 1
        else:
            stats['multicast_packets'] += 1

        # Salva estatísticas periodicamente
        save_table_to_file(etherStatsTable, ether_stats_file)

# Função para salvar tabelas em arquivos JSON
def save_table_to_file(data, filename):
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)

# Função para lidar com requisições SNMP (pass persist)
def handle_snmp_requests():
    logging.info("Iniciando loop pass persist para SNMP...")
    while True:
        try:
            line = sys.stdin.readline().strip()
            if not line:
                continue

            if line == "PING":
                print("PONG")
            elif line.startswith("get"):
                oid = sys.stdin.readline().strip()
                with data_lock:
                    if oid == ".1.3.6.1.2.1.16.1.1.1.1.1":  # Exemplo de OID
                        print(".1.3.6.1.2.1.16.1.1.1.1.1")
                        print("integer")
                        print(packet_count)
                    else:
                        print("NONE")
            elif line.startswith("set"):
                sys.stdin.readline()  # Ignora OID
                sys.stdin.readline()  # Ignora valor
                print("NONE")
            else:
                print("NONE")
            sys.stdout.flush()
        except Exception as e:
            logging.error(f"Erro no loop SNMP: {e}")

# Função para coletar dados históricos
def update_history_data():
    while True:
        with data_lock:
            timestamped_data = {
                'timestamp': time.time(),
                'data': etherStatsTable.copy()
            }
            etherHistoryTable.append(timestamped_data)
            save_table_to_file(etherHistoryTable, ether_history_file)
        time.sleep(30)

# Função principal
def main():
    if len(sys.argv) < 2:
        print("Uso: python probe.py <interface>")
        sys.exit(1)

    interface = sys.argv[1]
    logging.info(f"Interface selecionada: {interface}")

    # Inicia threads de captura e histórico
    sniffer_thread = threading.Thread(target=capture_packets, args=(interface,))
    sniffer_thread.daemon = True
    sniffer_thread.start()

    history_thread = threading.Thread(target=update_history_data)
    history_thread.daemon = True
    history_thread.start()

    # Inicia loop de requisições SNMP
    handle_snmp_requests()

if __name__ == "__main__":
    main()
