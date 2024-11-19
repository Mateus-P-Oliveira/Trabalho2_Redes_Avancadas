import threading
import time
import sys
import json
import logging
from scapy.all import sniff

# Configuração do log
logging.basicConfig(
    filename='/tmp/probe_log.txt',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Estruturas de dados para os grupos RMON
etherStatsTable = {}  # Estatísticas Ethernet
etherHistoryTable = []  # Histórico Ethernet
alarmTable = []  # Alarmes
eventTable = []  # Eventos

# Lock para acesso seguro a dados compartilhados
data_lock = threading.Lock()

# Função para processar pacotes capturados
def process_packet(packet):
    global etherStatsTable
    with data_lock:
        src_mac = packet.src
        packet_size = len(packet)

        if src_mac not in etherStatsTable:
            etherStatsTable[src_mac] = {
                'total_packets': 0, 'total_bytes': 0,
                'unicast_packets': 0, 'multicast_packets': 0,
                'broadcast_packets': 0, 'errors': 0
            }
        etherStatsTable[src_mac]['total_packets'] += 1
        etherStatsTable[src_mac]['total_bytes'] += packet_size

        if packet.haslayer('IP'):
            etherStatsTable[src_mac]['unicast_packets'] += 1
        elif packet.dst == "ff:ff:ff:ff:ff:ff":
            etherStatsTable[src_mac]['broadcast_packets'] += 1
        else:
            etherStatsTable[src_mac]['multicast_packets'] += 1

# Função para capturar pacotes na interface especificada
def packet_sniffer(interface):
    logging.info(f"Capturando pacotes na interface: {interface}")
    sniff(prn=process_packet, iface=interface, store=False, promisc=True)

# Função para atualizar o histórico de pacotes
def update_history():
    global etherHistoryTable
    while True:
        with data_lock:
            snapshot = {
                'timestamp': time.time(),
                'data': etherStatsTable.copy()
            }
            etherHistoryTable.append(snapshot)
        time.sleep(30)  # Intervalo para capturar histórico

# Função para verificar alarmes
def check_alarms():
    global alarmTable, eventTable
    threshold_packets = 100
    while True:
        with data_lock:
            for mac, stats in etherStatsTable.items():
                if stats['total_packets'] > threshold_packets:
                    alarm = {
                        'time': time.time(),
                        'mac': mac,
                        'type': 'packet_threshold',
                        'message': f'Alarme: {mac} excedeu {threshold_packets} pacotes.'
                    }
                    alarmTable.append(alarm)
                    logging.warning(alarm['message'])

                    # Adiciona evento relacionado ao alarme
                    eventTable.append({
                        'time': time.time(),
                        'event_type': 'alarm_triggered',
                        'description': alarm['message']
                    })
        time.sleep(10)

# Função para responder a comandos do método pass_persist
def pass_persist_handler():
    while True:
        try:
            line = sys.stdin.readline().strip()
            if not line:
                continue 

            if line == "PING":
                print("PONG")
                sys.stdout.flush()
            elif line == "get":
                oid = sys.stdin.readline().strip()
                with data_lock:
                    # etherStatsTable
                    if oid.startswith(".1.3.6.1.2.1.16.1.1.1.1"):  # etherStatsIndex
                        mac_list = list(etherStatsTable.keys())
                        instance_id = oid.split(".")[-1]
                        if instance_id.isdigit() and int(instance_id) < len(mac_list):
                            print(oid)
                            print("integer")
                            print(instance_id)
                        else:
                            print("NONE")
                    elif oid.startswith(".1.3.6.1.2.1.16.1.1.1.5"):  # etherStatsPkts
                        mac_list = list(etherStatsTable.keys())
                        instance_id = oid.split(".")[-1]
                        if instance_id.isdigit() and int(instance_id) < len(mac_list):
                            mac = mac_list[int(instance_id)]
                            print(oid)
                            print("integer")
                            print(etherStatsTable[mac]['total_packets'])
                        else:
                            print("NONE")
                    # etherHistoryTable
                    elif oid.startswith(".1.3.6.1.2.1.16.2.2.1.2"):  # History Table
                        instance_id = oid.split(".")[-1]
                        if instance_id.isdigit() and int(instance_id) < len(etherHistoryTable):
                            history = etherHistoryTable[int(instance_id)]
                            print(oid)
                            print("string")
                            print(json.dumps(history))
                        else:
                            print("NONE")
                    # alarmTable
                    elif oid.startswith(".1.3.6.1.2.1.16.3.1.1"):  # Alarm Table
                        instance_id = oid.split(".")[-1]
                        if instance_id.isdigit() and int(instance_id) < len(alarmTable):
                            alarm = alarmTable[int(instance_id)]
                            print(oid)
                            print("string")
                            print(json.dumps(alarm))
                        else:
                            print("NONE")
                    # eventTable
                    elif oid.startswith(".1.3.6.1.2.1.16.9.1.1"):  # Event Table
                        instance_id = oid.split(".")[-1]
                        if instance_id.isdigit() and int(instance_id) < len(eventTable):
                            event = eventTable[int(instance_id)]
                            print(oid)
                            print("string")
                            print(json.dumps(event))
                        else:
                            print("NONE")
                    else:
                        print("NONE")
                sys.stdout.flush()
            elif line == "set":
                oid = sys.stdin.readline().strip()
                value = sys.stdin.readline().strip()
                logging.info(f"SET recebido para OID {oid} com valor {value}")
                print("DONE")
                sys.stdout.flush()
            else:
                print("NONE")
                sys.stdout.flush()
        except Exception as e:
            logging.error(f"Erro no pass_persist: {e}")
            break

# Função principal
def main():
    if len(sys.argv) < 2:
        logging.error("Uso: python probe.py <interface>")
        sys.exit(1)

    interface = sys.argv[1]

    # Inicia threads para as funções
    threading.Thread(target=packet_sniffer, args=(interface,), daemon=True).start()
    threading.Thread(target=update_history, daemon=True).start()
    threading.Thread(target=check_alarms, daemon=True).start()

    # Inicia o loop do pass_persist
    pass_persist_handler()

if __name__ == "__main__":
    main()