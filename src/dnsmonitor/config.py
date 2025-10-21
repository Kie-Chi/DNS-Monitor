"""
Configuration management for DNS Monitor
"""

import os
import yaml
from typing import Optional
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class TrafficConfig:
    """Traffic monitoring configuration"""
    interface: str = "any"
    pcap_dir: str = "/tmp/dnsmonitor/pcap"
    pcap_rotation_size: int = 100  # MB
    pcap_rotation_time: int = 300  # seconds
    bpf_filter: str = "port 53"
    buffer_size: int = 65536


@dataclass
class ResolverConfig:
    """Resolver path monitoring configuration"""
    client_ip: Optional[str] = None
    resolver_ip: Optional[str] = None
    timeout: int = 30
    bpf_filter: str = "port 53"
    trace_queries: bool = True


@dataclass
class CacheConfig:
    """Cache monitoring configuration"""
    software: str = "unbound"  # unbound, bind
    host: str = "localhost"
    port: int = 12345
    control_config: Optional[str] = None
    dump_file: Optional[str] = None


@dataclass
class MonitorConfig:
    """Main monitoring configuration"""
    traffic: TrafficConfig = field(default_factory=TrafficConfig)
    resolver: ResolverConfig = field(default_factory=ResolverConfig)
    cache: CacheConfig = field(default_factory=CacheConfig)
    log_level: str = "INFO"
    output_dir: str = "/tmp/dnsmonitor/output"


class ConfigManager:
    """Configuration manager for DNS Monitor"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file
        self.config = MonitorConfig()
        
        if config_file and Path(config_file).exists():
            self.load_from_file(config_file)
        
        # Override with environment variables
        self.load_from_env()
    
    def load_from_file(self, config_file: str) -> None:
        """Load configuration from YAML file"""
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            
            if 'traffic' in data:
                self.config.traffic = TrafficConfig(**data['traffic'])
            if 'resolver' in data:
                self.config.resolver = ResolverConfig(**data['resolver'])
            if 'cache' in data:
                self.config.cache = CacheConfig(**data['cache'])
            if 'log_level' in data:
                self.config.log_level = data['log_level']
            if 'output_dir' in data:
                self.config.output_dir = data['output_dir']
                
        except Exception as e:
            raise ValueError(f"Failed to load config from {config_file}: {e}")
    
    def load_from_env(self) -> None:
        """Load configuration from environment variables"""
        # Traffic config
        if os.getenv("DNS_MONITOR_INTERFACE"):
            self.config.traffic.interface = os.getenv("DNS_MONITOR_INTERFACE")
        if os.getenv("DNS_MONITOR_PCAP_DIR"):
            self.config.traffic.pcap_dir = os.getenv("DNS_MONITOR_PCAP_DIR")
        
        # Resolver config
        if os.getenv("CLIENT_IP"):
            self.config.resolver.client_ip = os.getenv("CLIENT_IP")
        if os.getenv("RESOLVER_IP"):
            self.config.resolver.resolver_ip = os.getenv("RESOLVER_IP")
        
        # Cache config
        if os.getenv("DNS_SOFTWARE"):
            self.config.cache.software = os.getenv("DNS_SOFTWARE")
        if os.getenv("CACHE_HOST"):
            self.config.cache.host = os.getenv("CACHE_HOST")
        if os.getenv("CACHE_PORT"):
            self.config.cache.port = int(os.getenv("CACHE_PORT"))
        
        # General config
        if os.getenv("LOG_LEVEL"):
            self.config.log_level = os.getenv("LOG_LEVEL")
        if os.getenv("OUTPUT_DIR"):
            self.config.output_dir = os.getenv("OUTPUT_DIR")
    
    def save_to_file(self, config_file: str) -> None:
        """Save current configuration to YAML file"""
        config_dict = {
            'traffic': {
                'interface': self.config.traffic.interface,
                'pcap_dir': self.config.traffic.pcap_dir,
                'pcap_rotation_size': self.config.traffic.pcap_rotation_size,
                'pcap_rotation_time': self.config.traffic.pcap_rotation_time,
                'bpf_filter': self.config.traffic.bpf_filter,
                'buffer_size': self.config.traffic.buffer_size,
            },
            'resolver': {
                'client_ip': self.config.resolver.client_ip,
                'resolver_ip': self.config.resolver.resolver_ip,
                'timeout': self.config.resolver.timeout,
                'bpf_filter': self.config.resolver.bpf_filter,
                'trace_queries': self.config.resolver.trace_queries,
            },
            'cache': {
                'software': self.config.cache.software,
                'host': self.config.cache.host,
                'port': self.config.cache.port,
                'control_config': self.config.cache.control_config,
                'dump_file': self.config.cache.dump_file,
            },
            'log_level': self.config.log_level,
            'output_dir': self.config.output_dir,
        }
        
        with open(config_file, 'w', encoding='utf-8') as f:
            yaml.dump(config_dict, f, default_flow_style=False, allow_unicode=True)
    
    def get_config(self) -> MonitorConfig:
        """Get the current configuration"""
        return self.config