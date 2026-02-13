from scapy.all import sniff, ARP, DNS, DNSQR
import datetime
import threading


LOG_FILE = "network_monitor.txt"

#===================
# Save Log Files
# ==================

def save_log(text): 
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {text}\n")
        
        
def handle_arp(pkt):
    if ARP in pkt  and pkt[ARP].op == 1: 
        ip = pkt[ARP].psrc  
        mac = pkt[ARP].hwsrc 
        msg = f"[DEVICE]  IP={ip}, MAC = {mac}"
        print(msg)
        save_log(msg)
        
        
def handle_dns(pkt):
    try: 
        if pkt.haslayer(DNSQR):
            ip = pkt[IP].src if pkt.haslayer(IP) else "UNKNOWN IP"
            domain = pkt[DNSQR].qname.decode(errors="ignore")
            msg = f"[Query] {ip} → {domain}"
            print(msg)
            save_log(msg)
    except Exception as e:
        print("DNS Handler Error:", e)
        
        
    
def packet_handler(pkt):
    if ARP in pkt:
        handle_arp(pkt)
    elif pkt.haslayer(DNSQR):
        handle_dns(pkt)
        
        
def start_sniffer():
    print("Start Network Sniffer....")
    sniff(filter = "arp or port 53", prn=packet_handler, store=0)
    

        
        
if __name__ == "__main__":
    print("Python Network Logger Started....")
    print("Listening for IP, MAC and DNS Queries....")
    
    sniffer_thread = threading.Thread(target=start_sniffer, daemon=True)
    sniffer_thread.start()
    
    
    while True:
        pass