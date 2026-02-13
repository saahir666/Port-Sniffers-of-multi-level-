import psutil
import platform
from scapy.all import sniff, IP, TCP, UDP, Ether
import time

def diagnose_interfaces():
    """Diagnose available interfaces and their status"""
    print("=== Network Interface Diagnosis ===")
    print(f"Platform: {platform.system()}")
    print("\nAvailable interfaces:")
    
    
    interfaces = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    
    active_interfaces = []
    
    for interface_name, addresses in interfaces.items():
        print(f"\nInterface: {interface_name}")
        
        
        if interface_name in stats:
            is_up = stats[interface_name].isup
            speed = stats[interface_name].speed
            print(f"  Status: {'UP' if is_up else 'DOWN'}")
            print(f"  Speed: {speed} Mbps")
        else:
            is_up = False
            print("  Status: Unknown")
        
        for addr in addresses:
            if addr.family == psutil.AF_LINK:
                print(f"  MAC: {addr.address}")
            elif addr.family == 2:  
                print(f"  IP: {addr.address}")
                print(f"  Netmask: {addr.netmask}")
        
        if is_up and not interface_name.startswith('lo'):
            if any(addr.family == 2 for addr in addresses):  
                active_interfaces.append(interface_name)
    
    return active_interfaces

def simple_packet_test(interface_name, duration=10):
    """Simple packet capture test"""
    print(f"\n=== Testing Packet Capture on {interface_name} ===")
    print(f"Duration: {duration} seconds")
    print("Generating network traffic now would help (browse web, ping, etc.)")
    
    captured_packets = []
    
    def packet_callback(packet):
        captured_packets.append(packet)
        if len(captured_packets) <= 5:  
            print(f"  Packet #{len(captured_packets)}: ", end="")
            if IP in packet:
                print(f"{packet[IP].src} -> {packet[IP].dst}", end="")
                if TCP in packet:
                    print(f" [TCP {packet[TCP].sport} -> {packet[TCP].dport}]")
                elif UDP in packet:
                    print(f" [UDP {packet[UDP].sport} -> {packet[UDP].dport}]")
                else:
                    print(f" [IP Protocol {packet[IP].proto}]")
            else:
                print("Non-IP packet")
    
    try:
        print("Starting capture...")
        sniff(
            iface=interface_name,
            prn=packet_callback,
            timeout=duration,
            store=0
        )
        print(f"Capture finished. Total packets seen: {len(captured_packets)}")
        return len(captured_packets) > 0
        
    except PermissionError:
        print("PERMISSION ERROR: Need administrator/root privileges")
        return False
    except Exception as e:
        print(f"ERROR: {e}")
        return False

def test_all_interfaces():
    """Test packet capture on all available interfaces"""
    interfaces = diagnose_interfaces()
    
    if not interfaces:
        print("\nNo active interfaces found!")
        return
    
    print(f"\n=== Testing Packet Capture ===")
    print("Will test each interface for 5 seconds...")
    
    working_interfaces = []
    
    for interface in interfaces[:3]:  
        print(f"\n--- Testing {interface} ---")
        success = simple_packet_test(interface, duration=5)
        if success:
            working_interfaces.append(interface)
            print(f"✅ {interface} works for packet capture")
        else:
            print(f"❌ {interface} failed")
    
    if working_interfaces:
        print(f"\nWorking interfaces for capture: {working_interfaces}")
        return working_interfaces[0]  
    else:
        print("\nNo interfaces working for packet capture!")
        print("\nCommon fixes:")
        print("1. Run as Administrator (Windows) or with sudo (Linux/Mac)")
        print("2. Install Npcap (Windows) or tcpdump/libpcap (Linux/Mac)")
        print("3. Check if firewall/antivirus is blocking packet capture")
        return None

def full_capture_with_working_interface(interface_name):
    """Full capture using a proven working interface"""
    print(f"\n=== Starting Full Capture on {interface_name} ===")
    
    packets = []
    start_time = time.time()
    duration = 30  
    
    def packet_handler(packet):
        packet_info = {}
        if IP in packet:
            packet_info['src'] = packet[IP].src
            packet_info['dst'] = packet[IP].dst
            packet_info['proto'] = packet[IP].proto
            
            if TCP in packet:
                packet_info['sport'] = packet[TCP].sport
                packet_info['dport'] = packet[TCP].dport
                packet_info['type'] = 'TCP'
            elif UDP in packet:
                packet_info['sport'] = packet[UDP].sport
                packet_info['dport'] = packet[UDP].dport
                packet_info['type'] = 'UDP'
            else:
                packet_info['type'] = 'IP'
                
            packets.append(packet_info)
            
            elapsed = time.time() - start_time
            if len(packets) <= 10 or len(packets) % 20 == 0:
                print(f"[{elapsed:.1f}s] {packet_info['src']}:{packet_info.get('sport', '')} -> "
                      f"{packet_info['dst']}:{packet_info.get('dport', '')} [{packet_info['type']}]")
    
    try:
        print("Capture started - Generate some network traffic (browse web, ping google.com)...")
        sniff(
            iface=interface_name,
            prn=packet_handler,
            timeout=duration
        )
        
        print(f"\n✨ Capture complete! Collected {len(packets)} packets in {duration} seconds")
        return packets
        
    except Exception as e:
        print(f"Error during capture: {e}")
        return []


if __name__ == "__main__":
    print("Network Packet Capture Diagnostic Tool")
    print("=====================================")
    

    working_interface = test_all_interfaces()
    
    if working_interface:
        print(f"\n🎉 Found working interface: {working_interface}")
        print("\nNow performing full capture...")
        packets = full_capture_with_working_interface(working_interface)
        
        if packets:
            print(f"\nSuccessfully captured {len(packets)} packets!")
            print("Sample of captured data:")
            for i, packet in enumerate(packets[:5]):
                print(f"  {i+1}. {packet}")
        else:
            print("No packets captured. Try generating more network traffic during capture.")
    else:
        print("\n❌ Cannot proceed with packet capture due to interface issues.")
        print("Please check the diagnostic output above for troubleshooting steps.")