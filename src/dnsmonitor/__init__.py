"""
DNS Monitor - A comprehensive DNS monitoring tool

This package provides monitoring capabilities for:
- DNS traffic analysis using high-performance packet capture
- DNS resolution path tracing with BPF filtering
- DNS cache monitoring for recursive resolvers (BIND, Unbound)
"""

__version__ = "0.1.0"
__author__ = "DNS Monitor Team"

from .monitor import DNSMonitor
from .traffic import OptimizedTrafficMonitor as TrafficMonitor
from .resolver import ResolverMonitor
from .cache import CacheMonitor

__all__ = [
    "DNSMonitor",
    "TrafficMonitor", 
    "ResolverMonitor",
    "CacheMonitor",
]