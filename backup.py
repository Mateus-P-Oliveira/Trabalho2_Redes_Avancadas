import sys
import time
import json
import logging
import threading
from scapy.all import sniff
from pysnmp.smi import rfc1902

# Configurações para o arquivo de log
log_file = "probe_log.txt"
logging.basicConfig(filename=log_file, level=logging.INFO, format='%(asctime)s - %(message)s')

# Estruturas das tabelas RMON
etherStatsTable = {}
etherHistoryTable = []
alarmTable = []
eventTable = []

# Arquivos para salvar os dados
ether_stats_file = "etherStatsTable.json"
ether_history_file = "etherHistoryTable.json"
alarm_file = "alarmTable.json"
event_file = "eventTable.json"

# Mapeamento de OIDs para tabelas RMON
oid_mapping = {
    ".1.3.6.1.2.1.16.1.1.1.6": lambda idx: etherStatsTable.get(idx, {}).get('total_packets', 0),
    ".1.3.6.1.2.1.16.1.1.1.9": lambda idx: etherStatsTable.get(idx, {}).get('total_bytes', 0),
    ".1.3.6.1.2.1.16.1.1.1.10": lambda idx: etherStatsTable.get(idx, {}).get('errors', 0),
}

# Função para capturar pacotes
def capture_packets(interface):
    logging.info(f"Iniciando captura de pacotes na interface {interface}...")
    sniff(iface=interface, prn=process_packet, store=False)

# Função para processar pacotes capturados
def process_packet(packet):
    src_mac = packet[0].src
    packet_size = len(packet)
    if src_mac not in etherStatsTable:
        etherStatsTable[src_mac] = {
            'total_packets': 0,
            'total_bytes': 0,
            'errors': 0,
        }
    etherStatsTable[src_mac]['total_packets'] += 1
    etherStatsTable[src_mac]['total_bytes'] += packet_size
    save_table_to_file(etherStatsTable, ether_stats_file)

# Função para salvar tabelas
def save_table_to_file(data, filename):
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)

# Função para gerar histórico
def update_history_data():
    while True:
        snapshot = {'timestamp': time.time(), 'data': etherStatsTable.copy()}
        etherHistoryTable.append(snapshot)
        save_table_to_file(etherHistoryTable, ether_history_file)
        time.sleep(30)

# Função para verificar alarmes
def check_alarms():
    threshold_packets = 100
    while True:
        for mac, stats in etherStatsTable.items():
            if stats['total_packets'] > threshold_packets:
                alarm = {
                    'time': time.time(),
                    'mac': mac,
                    'type': 'packet_threshold',
                    'message': f"MAC {mac} excedeu {threshold_packets} pacotes",
                }
                alarmTable.append(alarm)
                save_table_to_file(alarmTable, alarm_file)
                add_event(alarm['message'])
        time.sleep(10)

# Função para registrar eventos
def add_event(event_description):
    event = {'time': time.time(), 'description': event_description}
    eventTable.append(event)
    save_table_to_file(eventTable, event_file)

# Modelo pass persist para SNMP
def snmp_pass_persist():
    print("PASS-PERSIST-START")
    sys.stdout.flush()

    while True:
        try:
            line = sys.stdin.readline().strip()
            if line.startswith("get"):
                oid = line.split(" ")[1]
                value = handle_oid_request(oid)
                if value is not None:
                    print(f"SNMPv2-SMI::mib-2.16.1.1.1.6.1 = Counter32: {value}")
                else:
                    print("NONE")
            sys.stdout.flush()
        except Exception as e:
            logging.error(f"Erro no pass persist: {e}")

# Lida com requisições SNMP baseadas em OIDs
def handle_oid_request(oid):
    logging.info(f"Requisição OID recebida: {oid}")
    oid_parts = oid.split(".")
    base_oid = ".".join(oid_parts[:-1])
    idx = oid_parts[-1]
    if base_oid in oid_mapping:
        value = oid_mapping[base_oid](idx)
        logging.info(f"Valor retornado para {oid}: {value}")
        return value
    logging.warning(f"OID não encontrado: {oid}")
    return None


# Função principal
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python probe.py <interface>")
        sys.exit(1)

    interface = sys.argv[1]

    # Inicializa threads de monitoramento
    threading.Thread(target=capture_packets, args=(interface,), daemon=True).start()
    threading.Thread(target=update_history_data, daemon=True).start()
    threading.Thread(target=check_alarms, daemon=True).start()

    # Inicia o modelo pass persist
    snmp_pass_persist()
