import threading
from scapy.all import sniff
import time
import sys
import datetime
import socket
import os
import logging

# Configure logging
logging.basicConfig(
    filename='/tmp/log.txt',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Shared variable to store the packet count
packet_count = 0
# Lock for thread-safe access to shared variable
count_lock = threading.Lock()

# Function to handle each sniffed packet
def packet_handler(packet):
    global packet_count
    with count_lock:
        packet_count += 1
        # logging.info(f"Packet received. Total count: {packet_count}")

# Sniffer thread function
def packet_sniffer(interface):
    logging.info(f"Starting packet sniffer on interface: {interface}")
    try:
        sniff(prn=packet_handler, iface=interface, store=False, promisc=True)
    except Exception as e:
        logging.error(f"Error in packet sniffer: {e}")

def main():
    logging.info("Program started")
    interface = sys.argv[1]
    logging.info(f"Interface provided: {interface}")

    # Create and start the sniffer thread
    sniffer_thread = threading.Thread(target=packet_sniffer, args=(interface,))
    sniffer_thread.daemon = True  # This makes the thread exit when the main program exits
    sniffer_thread.start()
    logging.info("Sniffer thread started")

    while True:
        try:
            line = sys.stdin.readline()
            if not line:
                raise EOFError()
            line = line.strip()
            
            if 'PING' in line:
                logging.info("Received PING command")
                print("PONG")
            elif not line: # if line is empty then continue
                continue
            elif 'get' in line:
                logging.info("Received get command")
                oid = sys.stdin.readline()
                oid = oid.strip()
                logging.info(f"OID received: {oid}")
                if oid.startswith(".1.3.6.1.2.1.16.1.1.1.1"): # etherStatsIndex
                    logging.info("Valid OID received")
                    instanceid = oid.split('.')[-1]
                    print(oid)
                    print("integer")
                    print(instanceid)
                elif oid.startswith(".1.3.6.1.2.1.16.1.1.1.5"): # etherStatsPkts
                    logging.info("Valid OID received")
                    print(oid)
                    print("integer")
                    with count_lock:
                        print(f"{packet_count}")
                        logging.info(f"Packet count returned: {packet_count}")
                elif oid.startswith(".1.3.6.1.2.1.16.1.1.1.21"): # etherStatsStatus
                    logging.info("Valid OID received")
                    print(oid)
                    print("integer")
                    print("1") # valid
                else:
                    logging.warning("Invalid OID received")
                    print("NONE")
            elif 'set' in line:
                logging.info("Received set command")
                oid = sys.stdin.readline()
                oid = oid.strip()
                value = sys.stdin.readline()
                value = value.strip()
                logging.info(f"OID received: {oid}")
                logging.info(f"Value received: {value}")
                print("DONE")
            else:
                logging.warning("Unknown command received")
                print("NONE")
            sys.stdout.flush()
        except EOFError:
            logging.info("EOFError encountered, exiting main loop")
            break
        except Exception as e:
            logging.error(f"Error in main loop: {e}")

if __name__ == "__main__":
    main()