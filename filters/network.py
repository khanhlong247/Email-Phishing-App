import dns.resolver
from config.settings import RBL_SERVERS
import logging

logging.basicConfig(level=logging.INFO, filename='data/logs/network.log')

def check_network_filters(ip: str) -> bool:
    """
    Check if IP is in any RBL (Real-time Blackhole List).
    Returns True if clean, False if blacklisted.
    """
    reverse_ip = '.'.join(reversed(ip.split('.')))
    for rbl in RBL_SERVERS:
        try:
            dns.resolver.resolve(f"{reverse_ip}.{rbl}", 'A')
            logging.warning(f"IP {ip} blacklisted by {rbl}")
            return False
        except dns.resolver.NXDOMAIN:
            continue
        except Exception as e:
            logging.error(f"Error checking RBL {rbl}: {e}")
    # Add SPF/DKIM checks here if needed
    return True