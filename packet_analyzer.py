from scapy.all import Ether, IP, TCP, UDP, ICMP, DNS, Raw
from datetime import datetime

def analyze_packet(packet):
    """
    Takes a raw scapy packet and extracts readable information into a dictionary.
    This demonstrates understanding of the OSI model layers: 
    Layer 2 (Ethernet), Layer 3 (IP), Layer 4 (TCP/UDP), Layer 7 (Application - HTTP/DNS).
    
    Args:
        packet: A scapy packet object.
        
    Returns:
        dict: A dictionary containing parsed and readable packet information.
    """
    # Initialize basic info that all packets will have
    pkt_info = {
        "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "length": len(packet),
        "protocol": "UNKNOWN",
        "src_mac": None,
        "dst_mac": None,
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "payload": "",
        "hex_data": [],
        "packet_details": [],
    }

    # =========================================================
    # 1. DATA LINK LAYER (Layer 2) - Ethernet
    # Moves packets between physically connected devices via MAC addresses.
    # =========================================================
    if packet.haslayer(Ether):
        pkt_info["src_mac"] = packet[Ether].src
        pkt_info["dst_mac"] = packet[Ether].dst

    # =========================================================
    # 2. NETWORK LAYER (Layer 3) - IP (Internet Protocol)
    # Routes packets across networks via IP addresses.
    # =========================================================
    if packet.haslayer(IP):
        pkt_info["src_ip"] = packet[IP].src
        pkt_info["dst_ip"] = packet[IP].dst
        
        # =========================================================
        # 3. TRANSPORT LAYER (Layer 4) - TCP / UDP / ICMP
        # Handles application-to-application communication using Ports.
        # =========================================================
        
        if packet.haslayer(TCP):
            pkt_info["src_port"] = packet[TCP].sport
            pkt_info["dst_port"] = packet[TCP].dport
            pkt_info["protocol"] = "TCP"
            
            # Detect Common Application Protocols (Layer 7) based on ports
            if pkt_info["src_port"] == 80 or pkt_info["dst_port"] == 80:
                pkt_info["protocol"] = "HTTP"
            elif pkt_info["src_port"] == 443 or pkt_info["dst_port"] == 443:
                pkt_info["protocol"] = "HTTPS"
                
        elif packet.haslayer(UDP):
            pkt_info["src_port"] = packet[UDP].sport
            pkt_info["dst_port"] = packet[UDP].dport
            pkt_info["protocol"] = "UDP"
            
            # Detect DNS (Domain Name System)
            if packet.haslayer(DNS) or pkt_info["src_port"] == 53 or pkt_info["dst_port"] == 53:
                pkt_info["protocol"] = "DNS"
                
        elif packet.haslayer(ICMP):
            pkt_info["protocol"] = "ICMP"
            
    # =========================================================
    # 4. APPLICATION LAYER (Layer 7) / PAYLOAD EXTRACTION
    # The actual data the applications are sending (e.g. HTML text).
    # =========================================================
    
    # We look for raw data in the packet
    if packet.haslayer(Raw):
        raw_data = packet[Raw].load
        try:
            # Try to decode as utf-8 (works for HTTP headers or plain text)
            decoded_payload = raw_data.decode('utf-8', errors='ignore')
            
            # Clean up newlines for safe single-line terminal printing
            clean_payload = decoded_payload.replace('\n', ' ').replace('\r', '')
            pkt_info["payload"] = clean_payload

        except Exception:
            # If it fails, it's likely pure binary (like an image, video stream, or encrypted HTTPS)
            pkt_info["payload"] = f"<Binary Data: {len(raw_data)} bytes>"
            
    # Add detailed packet breakdown
    try:
        details = []
        for line in packet.show(dump=True).split('\n'):
            if line.strip():
                details.append(line)
        pkt_info["packet_details"] = details
    except Exception:
        pkt_info["packet_details"] = ["Details unavailable"]
        
    # Generate Hex Dump
    hex_lines = []
    raw_bytes = bytes(packet)
    for i in range(0, len(raw_bytes), 16):
        chunk = raw_bytes[i:i+16]
        hex_str = ' '.join(f'{b:02x}' for b in chunk)
        ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        hex_lines.append(f"{i:04x}  {hex_str:<47}  {ascii_str}")
    pkt_info["hex_data"] = hex_lines
    
    return pkt_info
