from collections import Counter
import threading
import time
from colorama import Fore, Style
from tabulate import tabulate

class PacketStatistics:
    """
    Tracks and calculates statistics about captured network traffic.
    Uses threading locks to ensure accurate counting when multiple packets arrive simultaneously.
    """
    def __init__(self):
        self.total_packets = 0
        self.protocols = Counter()
        self.src_ips = Counter()
        self.dst_ips = Counter()
        self.start_time = time.time()
        
        # Threading lock to prevent race conditions during updates
        self.lock = threading.Lock()
        
    def update(self, pkt_info):
        """
        Thread-safe update of statistics based on a single packet's information.
        """
        with self.lock:
            self.total_packets += 1
            
            # Count protocols
            protocol = pkt_info.get("protocol", "UNKNOWN")
            self.protocols[protocol] += 1
            
            # Count source and destination IP occurrences
            src_ip = pkt_info.get("src_ip")
            if src_ip:
                self.src_ips[src_ip] += 1
                
            dst_ip = pkt_info.get("dst_ip")
            if dst_ip:
                self.dst_ips[dst_ip] += 1
                
    def top_source_ips(self, n=5):
        with self.lock:
            return self.src_ips.most_common(n)

    def top_dest_ips(self, n=5):
        with self.lock:
            return self.dst_ips.most_common(n)

    def get_stats(self):
        """
        Calculates and formats the current statistics into a readable table.
        """
        with self.lock:
            duration = time.time() - self.start_time
            
            # Find the most common source and destination IPs safely
            top_src = self.src_ips.most_common(1)
            top_dst = self.dst_ips.most_common(1)
            
            top_src_str = f"{top_src[0][0]} ({top_src[0][1]} pkts)" if top_src else "None"
            top_dst_str = f"{top_dst[0][0]} ({top_dst[0][1]} pkts)" if top_dst else "None"
            
            # Prepare data for tabulation
            stats_data = [
                ["Total Packets", self.total_packets],
                ["Capture Duration (s)", round(duration, 2)],
                ["TCP Packets", self.protocols.get("TCP", 0)],
                ["UDP Packets", self.protocols.get("UDP", 0)],
                ["ICMP Packets", self.protocols.get("ICMP", 0)],
                ["DNS Packets", self.protocols.get("DNS", 0)],
                ["HTTP(S) Packets", self.protocols.get("HTTP", 0) + self.protocols.get("HTTPS", 0)],
                ["Most Active Src IP", top_src_str],
                ["Most Active Dst IP", top_dst_str]
            ]
            
            # Format output using tabulate and colorama
            title = f"\n{Fore.YELLOW}--- Live Packet Statistics ---{Style.RESET_ALL}\n"
            table = tabulate(stats_data, headers=["Metric", "Value"], tablefmt="grid")
            return title + table
            
    def display_loop(self, interval=15):
        """
        A blocking loop that runs in a background thread to print stats periodically.
        """
        while True:
            time.sleep(interval)
            print(self.get_stats())
