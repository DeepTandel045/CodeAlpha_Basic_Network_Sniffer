def build_bpf_filter(protocol=None, ip=None, port=None):
    """
    Builds a Berkeley Packet Filter (BPF) syntax string based on user inputs.
    BPF allows the capture engine (like scapy/tcpdump) to filter packets at the kernel level,
    which is much more efficient than capturing everything and filtering in Python later.
    
    Args:
        protocol (str): Protocol to filter (e.g., 'tcp', 'udp', 'icmp', 'dns', 'http').
        ip (str): Specific IP address to monitor.
        port (int): Specific Port to monitor.
        
    Returns:
        str: The formatted BPF string or an empty string if no filters are applied.
    """
    filters = []
    
    # 1. Protocol Filter
    if protocol:
        protocol = protocol.lower()
        if protocol in ['tcp', 'udp', 'icmp']:
            filters.append(protocol)
        elif protocol == 'dns':
            # DNS typically uses port 53 (UDP mostly, but sometimes TCP)
            filters.append("port 53")
        elif protocol == 'http':
            # HTTP typically uses port 80 or 8080
            filters.append("(port 80 or port 8080)")
        elif protocol == 'https':
            filters.append("port 443")
            
    # 2. IP Address Filter
    if ip:
        filters.append(f"host {ip}")
        
    # 3. Port Filter
    if port:
        filters.append(f"port {port}")
        
    # Combine all filters with 'and' to ensure all conditions are met
    bpf_string = " and ".join(filters)
    return bpf_string
