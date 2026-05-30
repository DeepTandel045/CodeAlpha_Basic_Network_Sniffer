import argparse
import sys
import threading

# Suppress scapy warnings before importing
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import sniff
from colorama import Fore, Style, init

from utils import print_banner
from packet_analyzer import analyze_packet
from filters import build_bpf_filter
from logger import PacketLogger
from statistics import PacketStatistics

# Initialize colorama for terminal colors (vital for Windows compatibility)
init(autoreset=True)

class NetworkSniffer:
    """
    Main Network Sniffer class. Coordinates packet capture, processing,
    display, logging, and statistics.
    """
    def __init__(self, interface=None, bpf_filter="", packet_count=0, log_format=None):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.packet_count = packet_count
        
        self.stats = PacketStatistics()
        # Initialize logger only if a format was requested
        self.logger = PacketLogger(log_format) if log_format else None
        
        self.is_running = True
        
    def process_packet(self, packet):
        """
        Callback function executed by scapy for *every* captured packet.
        """
        try:
            # Step 1: Analyze the raw packet and extract info
            pkt_info = analyze_packet(packet)
            
            # Step 2: Update real-time statistics
            self.stats.update(pkt_info)
            
            # Step 3: Log to file if logger is active
            if self.logger:
                self.logger.log_packet(pkt_info)
                
            # Step 4: Display nicely formatted data to the terminal
            self.display_packet(pkt_info)
            
        except Exception as e:
            # Catch unexpected errors to prevent the sniffer from crashing on weird packets
            print(f"{Fore.RED}Error processing packet: {e}{Style.RESET_ALL}")

    def display_packet(self, pkt_info):
        """
        Formats and prints the packet dictionary nicely to the terminal.
        """
        proto = pkt_info["protocol"]
        
        # Color code based on protocol for readability
        if proto == "TCP": proto_color = Fore.BLUE
        elif proto == "UDP": proto_color = Fore.CYAN
        elif proto == "ICMP": proto_color = Fore.YELLOW
        elif proto == "DNS": proto_color = Fore.MAGENTA
        elif proto == "HTTP": proto_color = Fore.GREEN
        elif proto == "HTTPS": proto_color = Fore.GREEN + Style.BRIGHT
        else: proto_color = Fore.WHITE
        
        time_str = f"[{pkt_info['timestamp']}]"
        proto_str = f"{proto_color}[{proto:^5}]{Style.RESET_ALL}"
        
        # Build addressing string (e.g., 192.168.1.5:443 -> 8.8.8.8:53)
        if pkt_info["src_ip"] and pkt_info["dst_ip"]:
            src = f"{pkt_info['src_ip']}:{pkt_info['src_port']}" if pkt_info['src_port'] else pkt_info['src_ip']
            dst = f"{pkt_info['dst_ip']}:{pkt_info['dst_port']}" if pkt_info['dst_port'] else pkt_info['dst_ip']
            addr_str = f"{src: <21} -> {dst: <21}"
        else:
            # Fallback for non-IP packets (like ARP on Layer 2)
            src_mac = pkt_info.get("src_mac", "Unknown MAC")
            dst_mac = pkt_info.get("dst_mac", "Unknown MAC")
            addr_str = f"{src_mac: <21} -> {dst_mac: <21}"
            
        len_str = f"Len: {pkt_info['length']} bytes"
        
        # Print main packet line
        print(f"{time_str} {proto_str} {addr_str} | {len_str}")
        
        # Extract and print a snippet of the payload if it contains readable text
        payload = pkt_info.get("payload")
        if payload and not payload.startswith("<Binary"):
            # Truncate long payloads to keep terminal clean (max 80 chars)
            snippet = payload[:80] + "..." if len(payload) > 80 else payload
            # Ensure the string can be printed in the current terminal's encoding
            encoding = sys.stdout.encoding or 'utf-8'
            snippet = snippet.encode(encoding, errors='replace').decode(encoding)
            print(f"   {Fore.LIGHTBLACK_EX}\\__ Payload: {snippet}{Style.RESET_ALL}")

    def start(self):
        """
        Configures and starts the packet sniffing process.
        """
        print_banner()
        print(f"{Fore.GREEN}[*] Starting Network Sniffer...{Style.RESET_ALL}")
        
        if self.bpf_filter:
            print(f"{Fore.CYAN}[*] Active Filter: {self.bpf_filter}{Style.RESET_ALL}")
        if self.interface:
            print(f"{Fore.CYAN}[*] Interface: {self.interface}{Style.RESET_ALL}")
        if self.logger:
            print(f"{Fore.CYAN}[*] Logging to: {self.logger.filepath}{Style.RESET_ALL}")
            
        print(f"{Fore.YELLOW}[*] Press Ctrl+C to stop sniffing.{Style.RESET_ALL}\n")
        
        # Start a background thread to print statistics every 15 seconds
        stats_thread = threading.Thread(target=self.stats.display_loop, args=(15,), daemon=True)
        stats_thread.start()
        
        try:
            # Scapy's sniff function is a blocking call that loops indefinitely (or until count is reached)
            # - iface: network interface to listen on
            # - prn: callback function executed for each packet
            # - filter: BPF filter string for kernel-level filtering
            # - store: False saves RAM (we process and discard immediately)
            # - count: number of packets to capture (0 = infinite)
            sniff(
                iface=self.interface,
                prn=self.process_packet,
                filter=self.bpf_filter,
                store=False, 
                count=self.packet_count
            )
        except KeyboardInterrupt:
            # Handled gracefully via user pressing Ctrl+C
            pass
        except PermissionError:
            print(f"\n{Fore.RED}[!] Permission Denied! Packet sniffing requires Administrator / Root privileges.")
            print(f"    Windows: Run command prompt or PowerShell as Administrator.")
            print(f"    Linux: Run script with 'sudo'.{Style.RESET_ALL}")
        except Exception as e:
            print(f"\n{Fore.RED}[!] Sniffing error: {e}{Style.RESET_ALL}")
        finally:
            self.stop()
            
    def stop(self):
        """
        Cleanly stops the sniffer, closes log files, and shows final statistics.
        """
        if not self.is_running:
            return
        self.is_running = False
        print(f"\n\n{Fore.YELLOW}[*] Stopping Sniffer...{Style.RESET_ALL}")
        
        if self.logger:
            self.logger.close()
            print(f"{Fore.GREEN}[*] Logs successfully saved to {self.logger.filepath}{Style.RESET_ALL}")
            
        # Display final statistics table
        print(self.stats.get_stats())
        sys.exit(0)


def main():
    """
    Parses command line arguments and initializes the sniffer.
    """
    parser = argparse.ArgumentParser(description="Python Network Sniffer - Educational packet capture tool")
    
    # Setup optional arguments
    parser.add_argument("-i", "--interface", help="Network interface to sniff on (e.g., 'eth0', 'Wi-Fi')")
    parser.add_argument("-p", "--protocol", help="Filter by protocol (tcp, udp, icmp, dns, http)")
    parser.add_argument("--ip", help="Filter by specific IP address (source or destination)")
    parser.add_argument("--port", type=int, help="Filter by specific port number")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (default: 0 = infinite)")
    parser.add_argument("-l", "--log", choices=["csv", "json", "txt"], help="Format to save captured packets")
    
    args = parser.parse_args()
    
    # Construct BPF filter string based on provided arguments
    bpf_filter = build_bpf_filter(args.protocol, args.ip, args.port)
    
    sniffer = NetworkSniffer(
        interface=args.interface,
        bpf_filter=bpf_filter,
        packet_count=args.count,
        log_format=args.log
    )
    
    sniffer.start()

if __name__ == "__main__":
    main()
