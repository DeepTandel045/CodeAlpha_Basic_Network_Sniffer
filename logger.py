import csv
import json
import os
from datetime import datetime

class PacketLogger:
    """
    Handles logging of captured packets into different file formats (TXT, CSV, JSON).
    Files are automatically created with a timestamp in the specified directory.
    """
    def __init__(self, log_format="csv", log_dir="captures"):
        self.log_format = log_format.lower()
        self.log_dir = log_dir
        
        # Create logging directory if it doesn't exist
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
            
        # Generate a unique filename based on the current time
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.filepath = os.path.join(self.log_dir, f"capture_{timestamp}.{self.log_format}")
        
        # Initialize the file structure based on format
        self._initialize_file()

    def _initialize_file(self):
        """Sets up headers or initial structures for the log files."""
        try:
            if self.log_format == "csv":
                with open(self.filepath, mode='w', newline='', encoding='utf-8') as file:
                    writer = csv.writer(file)
                    writer.writerow(["Timestamp", "Protocol", "Src IP", "Dst IP", "Src Port", "Dst Port", "Length", "Payload Summary"])
            elif self.log_format == "json":
                with open(self.filepath, mode='w', encoding='utf-8') as file:
                    file.write("[\n") # Start JSON array
            elif self.log_format == "txt":
                with open(self.filepath, mode='w', encoding='utf-8') as file:
                    file.write("=== Network Sniffer Packet Capture Log ===\n")
        except Exception as e:
            print(f"Failed to initialize log file: {e}")

    def log_packet(self, pkt_info):
        """
        Appends a single packet's information to the log file.
        """
        try:
            if self.log_format == "csv":
                with open(self.filepath, mode='a', newline='', encoding='utf-8') as file:
                    writer = csv.writer(file)
                    # Extract up to 100 characters of payload for the summary
                    payload_summary = str(pkt_info.get("payload", ""))[:100]
                    writer.writerow([
                        pkt_info.get("timestamp", ""),
                        pkt_info.get("protocol", ""),
                        pkt_info.get("src_ip", ""),
                        pkt_info.get("dst_ip", ""),
                        pkt_info.get("src_port", ""),
                        pkt_info.get("dst_port", ""),
                        pkt_info.get("length", ""),
                        payload_summary
                    ])
            elif self.log_format == "json":
                with open(self.filepath, mode='a', encoding='utf-8') as file:
                    # Note: We just append stringified JSON. The array formatting is finalized in close()
                    json_str = json.dumps(pkt_info)
                    file.write("  " + json_str + ",\n")
            elif self.log_format == "txt":
                with open(self.filepath, mode='a', encoding='utf-8') as file:
                    file.write(f"[{pkt_info.get('timestamp')}] {pkt_info.get('protocol')} "
                               f"{pkt_info.get('src_ip')}:{pkt_info.get('src_port')} -> "
                               f"{pkt_info.get('dst_ip')}:{pkt_info.get('dst_port')} | "
                               f"Len: {pkt_info.get('length')} bytes\n")
        except Exception as e:
            print(f"Logging error: {e}")
                           
    def close(self):
        """
        Finalizes the log file. Crucial for completing JSON formatting.
        """
        if self.log_format == "json":
            try:
                # Read the file to remove the trailing comma and close the array properly
                with open(self.filepath, mode='r', encoding='utf-8') as file:
                    content = file.read()
                
                # Simple string replacement for the last comma
                if content.endswith(",\n"):
                    content = content[:-2] + "\n"
                    
                with open(self.filepath, mode='w', encoding='utf-8') as file:
                    file.write(content + "]") # Close the JSON array
            except Exception as e:
                print(f"Error finalizing JSON file: {e}")
