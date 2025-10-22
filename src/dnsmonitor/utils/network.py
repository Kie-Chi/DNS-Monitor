"""
Network utility functions for DNS Monitor
"""
import socket
import ipaddress
from typing import Optional, Dict, Any
import logging

logger = logging.getLogger(__name__)


def get_iface(cidr: str) -> Optional[str]:
    """
        Get Interface Name by CIDR
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        interfaces = _get_ifaces()
        
        for interface_name, interface_info in interfaces.items():
            for addr_info in interface_info.get('addresses', []):
                if addr_info.get('family') == 'inet':  # IPv4
                    try:
                        ip = addr_info.get('addr')
                        netmask = addr_info.get('netmask')
                        if ip and netmask:
                            interface_ip = ipaddress.ip_address(ip)
                            interface_network = ipaddress.ip_network(f"{ip}/{netmask}", strict=False)
                            if interface_ip in network or network.overlaps(interface_network):
                                logger.info(f"Found interface {interface_name} for CIDR {cidr}")
                                return interface_name
                    except (ipaddress.AddressValueError, ValueError) as e:
                        logger.debug(f"Error processing interface {interface_name}: {e}")
                        continue
        
        logger.warning(f"No interface found for CIDR {cidr}")
        return None
        
    except (ipaddress.AddressValueError, ValueError) as e:
        logger.error(f"Invalid CIDR format '{cidr}': {e}")
        return None


def _get_ifaces() -> Dict[str, Dict[str, Any]]:
    """
    
    """
    try:
        import psutil
        interfaces = {}
        net_if_addrs = psutil.net_if_addrs()
        net_if_stats = psutil.net_if_stats()
        
        for interface_name, addresses in net_if_addrs.items():
            is_up = False
            if interface_name in net_if_stats:
                stats = net_if_stats[interface_name]
                is_up = stats.isup if hasattr(stats, 'isup') else False
            interface_info = {
                'addresses': [],
                'is_up': is_up
            }
            for addr in addresses:
                addr_info = {
                    'family': 'inet' if addr.family == socket.AF_INET else 'inet6' if addr.family == socket.AF_INET6 else 'other',
                    'addr': addr.address,
                    'netmask': addr.netmask,
                    'broadcast': getattr(addr, 'broadcast', None)
                }
                interface_info['addresses'].append(addr_info)
            
            interfaces[interface_name] = interface_info
        
        return interfaces
        
    except ImportError:
        logger.error("psutil is required for network interface detection")
        return {}


def validate_cidr(cidr: str) -> bool:
    """
    Validate CIDR format
    """
    try:
        if '/' not in cidr:
            return False
        ipaddress.ip_network(cidr, strict=False)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False