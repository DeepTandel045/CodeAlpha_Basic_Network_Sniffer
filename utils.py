import os
from colorama import init, Fore, Style

# Initialize colorama to automatically reset styles after each print
init(autoreset=True)

def print_banner():
    """
    Prints a professional, clean banner for the terminal UI.
    """
    banner = f"""
{Fore.CYAN}==================================================
{Fore.GREEN}         PYTHON NETWORK SNIFFER
{Fore.CYAN}=================================================={Style.RESET_ALL}
    """
    print(banner)
