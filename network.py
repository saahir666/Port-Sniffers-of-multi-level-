from scapy.all import sniff, TCP, UDP
from datetime import datetime 

log_file = open("network_traffic_log.txt", "a")

def packet_callback(packet):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    
    if packet.haslayer(TCP):
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport 
    elif packet.haslayer(UDP):
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    else: 
        return
    
    
    if packet.haslayer('IP'):
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst
        
        
        log_entry = f"[{timestamp}] {protocol}: {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
        log_file.write(log_entry)
        log_file.flush()
        
        
        print(f"Logged: {log_entry.strip()}")
        
        
interface_name = "Ethernet"
        

try: 
    print(f"Starting packet capture on interface: {interface_name}")
    sniff(iface=interface_name, prn=packet_callback, store=0)
except ValueError as e:
    print(f"Interface error: {e}")
    print("Please run the interface code first to find correct interface name")
except KeyboardInterrupt:
    print("\nStopping Capture....")
finally:
    log_file.close()