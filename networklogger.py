import socket
import threading
from scapy.all import sniff, ARP
import datetime
import dns.message
import dns.query
import dns.resolver

LOG_FILE = "network_monitor.txt"
FORWARD_DNS = "8.8.8.8"  
DNS_PORT = 53


def save_log(text):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {text}\n")
    print(text)

def handle_arp(pkt):
    if ARP in pkt and pkt[ARP].op == 1:  
        ip = pkt[ARP].psrc
        mac = pkt[ARP].hwsrc
        save_log(f"[DEVICE] IP={ip}, MAC={mac}")

def arp_sniffer():
    sniff(filter="arp", prn=handle_arp, store=0)

def dns_udp_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", DNS_PORT))
    save_log("[DNS UDP SERVER] Listening on UDP port 53")

    while True:
        try:
            data, addr = sock.recvfrom(512)

            request = dns.message.from_wire(data)
            qname = str(request.question[0].name)
            save_log(f"[DNS UDP] {addr[0]} → {qname}")

            response = dns.query.udp(request, FORWARD_DNS, timeout=3)
            sock.sendto(response.to_wire(), addr)

        except Exception as e:
            save_log(f"[DNS UDP ERROR] {e}")


def dns_tcp_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", DNS_PORT))
    sock.listen(5)
    save_log("[DNS TCP SERVER] Listening on TCP port 53")

    while True:
        conn, addr = sock.accept()
        threading.Thread(target=handle_tcp_client, args=(conn, addr), daemon=True).start()

def handle_tcp_client(conn, addr):
    try:
        length_bytes = conn.recv(2)
        if not length_bytes:
            conn.close()
            return
        length = int.from_bytes(length_bytes, 'big')
        data = conn.recv(length)
        request = dns.message.from_wire(data)
        qname = str(request.question[0].name)
        save_log(f"[DNS TCP] {addr[0]} → {qname}")


        response = dns.query.tcp(request, FORWARD_DNS, timeout=3)
        resp_data = response.to_wire()
        conn.send(len(resp_data).to_bytes(2, 'big') + resp_data)
    except Exception as e:
        save_log(f"[DNS TCP ERROR] {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    save_log("Python Network + DNS Logger Started...")

    threading.Thread(target=arp_sniffer, daemon=True).start()

    threading.Thread(target=dns_udp_server, daemon=True).start()

    threading.Thread(target=dns_tcp_server, daemon=True).start()

    while True:
        pass
