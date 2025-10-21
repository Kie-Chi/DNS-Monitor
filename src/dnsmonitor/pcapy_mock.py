"""
Mock implementation of pcapy for development/testing purposes
This allows the code to run without the actual pcapy dependency
"""

import time
import threading
from typing import Optional, Callable, Any

class MockPcapyReader:
    """Mock pcapy reader for testing"""
    
    def __init__(self, device: str, snaplen: int = 65536, promisc: bool = True, timeout: int = 100):
        self.device = device
        self.snaplen = snaplen
        self.promisc = promisc
        self.timeout = timeout
        self.running = False
        self._callback = None
        
    def setfilter(self, filter_str: str):
        """Set BPF filter (mock implementation)"""
        print(f"[MOCK] Setting filter: {filter_str}")
        
    def loop(self, count: int, callback: Callable):
        """Start packet capture loop (mock implementation)"""
        print(f"[MOCK] Starting capture loop on {self.device}")
        self.running = True
        self._callback = callback
        
        # Mock packet capture - just sleep to simulate
        while self.running and count != 0:
            time.sleep(1)
            if count > 0:
                count -= 1
                
    def breakloop(self):
        """Break the capture loop"""
        print("[MOCK] Breaking capture loop")
        self.running = False
        
    def next(self):
        """Get next packet (mock implementation)"""
        # Return mock packet data
        timestamp = time.time()
        packet_data = b'\x00' * 64  # Mock packet data
        return (timestamp, packet_data)

def open_live(device: str, snaplen: int = 65536, promisc: bool = True, timeout: int = 100):
    """Mock pcapy.open_live function"""
    print(f"[MOCK] Opening live capture on device: {device}")
    return MockPcapyReader(device, snaplen, promisc, timeout)

def findalldevs():
    """Mock pcapy.findalldevs function"""
    # Return mock network interfaces
    mock_devices = [
        "eth0",
        "lo", 
        "wlan0",
        "any"
    ]
    print(f"[MOCK] Found devices: {mock_devices}")
    return mock_devices

def lookupdev():
    """Mock pcapy.lookupdev function"""
    device = "eth0"
    print(f"[MOCK] Default device: {device}")
    return device

# Mock exceptions
class PcapError(Exception):
    """Mock pcapy error"""
    pass

# Export the same interface as pcapy
__all__ = [
    'open_live',
    'findalldevs', 
    'lookupdev',
    'PcapError'
]