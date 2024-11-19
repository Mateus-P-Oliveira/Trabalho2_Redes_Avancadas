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

# Lock para acesso seguro a dados compartilhados
data_lock = threading.Lock()

# Base OID para os grupos SNMP simulados
BASE_OID = ".1.3.6.1.2.1.16"

# Mapear sub-OIDs para colunas simuladas
etherStatsColumns = {
    "1": "total_packets",
    "2": "total_bytes",
    "3": "unicast_packets",
    "4": "multicast_packets",
    "5": "broadcast_packets"
}

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

# Função para manipular requisições SNMP
def handle_snmp_request(command, oid):
    with data_lock:
        if oid.startswith(BASE_OID + ".1.1.1"):  # etherStatsTable
            mac_list = list(etherStatsTable.keys())
            parts = oid.split(".")
            if len(parts) > len(BASE_OID.split(".")) + 2:  # Verifica índice e coluna
                column = parts[-2]
                index = int(parts[-1]) - 1  # O índice SNMP começa em 1
                if column in etherStatsColumns and 0 <= index < len(mac_list):
                    mac = mac_list[index]
                    if command == "GET":
                        return "integer", etherStatsTable[mac][etherStatsColumns[column]]
                    elif command == "GET-NEXT":
                        next_index = index + 1
                        if next_index < len(mac_list):
                            next_oid = f"{BASE_OID}.1.1.1.{column}.{next_index + 1}"
                            next_mac = mac_list[next_index]
                            return next_oid, "integer", etherStatsTable[next_mac][etherStatsColumns[column]]
                        else:
                            return None
                elif command == "GET-NEXT" and 0 <= index < len(mac_list):
                    next_column = str(int(column) + 1)
                    if next_column in etherStatsColumns:
                        next_oid = f"{BASE_OID}.1.1.1.{next_column}.1"
                        return next_oid, "integer", etherStatsTable[mac_list[0]][etherStatsColumns[next_column]]
            elif command == "GET-NEXT":  # Se não for um OID completo, retorna o primeiro
                first_oid = f"{BASE_OID}.1.1.1.1.1"
                first_mac = mac_list[0]
                return first_oid, "integer", etherStatsTable[first_mac][etherStatsColumns["1"]]
        return None

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
            elif line in {"get", "getnext"}:
                oid = sys.stdin.readline().strip()
                if line == "get":
                    result = handle_snmp_request("GET", oid)
                else:
                    result = handle_snmp_request("GET-NEXT", oid)
                
                if result:
                    if line == "get":
                        print(oid)
                        print(result[0])
                        print(result[1])
                    else:  # GET-NEXT
                        print(result[0])  # Próximo OID
                        print(result[1])  # Tipo
                        print(result[2])  # Valor
                else:
                    print("NONE")
                sys.stdout.flush()
            elif line == "set":
                oid = sys.stdin.readline().strip()
                value = sys.stdin.readline().strip()
                with data_lock:
                    # Lógica de SET pode ser personalizada
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

    # Inicia o loop do pass_persist
    pass_persist_handler()

if __name__ == "__main__":
    main()