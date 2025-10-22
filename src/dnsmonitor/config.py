"""
Configuration management for DNS Monitor
"""

import os
import yaml
from typing import Optional
from dataclasses import dataclass, field
from pathlib import Path

from .constants import DEFAULT_CACHE_INTERVAL, DEFAULT_ANALYSIS_PORT, DEFAULT_RESOLVE_PORT


@dataclass
class TrafficConfig:
    """DNS Traffic Monitoring Configuration"""
    interface: str = "any"
    pcap_dir: str = "./pcap"
    pcap_rotation_size: int = 100  # MB
    pcap_rotation_time: int = 3600  # seconds
    bpf_filter: str = "port 53"
    buffer_size: int = 65536
    snaplen: int = 65535
    dns_port: int = 53
    
    # optimization
    enable_lazy_loading: bool = True
    enable_object_pool: bool = False
    max_packet_cache: int = 1000
    
    # performance tuning
    capture_timeout_ms: int = 100
    enable_promiscuous: bool = True
    
    @classmethod
    def for_pcap_only(cls, interface: str, pcap_dir: str = "./pcap", **kwargs) -> 'TrafficConfig':
        """Create PCAP-only configuration"""
        return cls(
            interface=interface,
            pcap_dir=pcap_dir,
            enable_lazy_loading=False,
            **kwargs
        )
    
    @classmethod
    def for_display_only(cls, interface: str, **kwargs) -> 'TrafficConfig':
        """Create display-only configuration""" 
        return cls(
            interface=interface,
            pcap_dir="",
            enable_lazy_loading=True,
            **kwargs
        )
    
    @classmethod
    def for_resolver(cls, interface: str, **kwargs) -> 'TrafficConfig':
        """Create resolver-specific configuration"""
        return cls(
            interface=interface,
            pcap_dir="",
            enable_lazy_loading=True,
            max_packet_cache=5000,
            **kwargs
        )


@dataclass
class ResolverConfig:
    """Resolver path monitoring configuration"""
    interface: str = "any"
    client_ip: Optional[str] = None
    resolver_ip: Optional[str] = None
    timeout: int = 3
    trace_queries: bool = True
    output_path: str = "./resolve"

    enable_server: bool = False
    analysis_port: int = DEFAULT_RESOLVE_PORT


# -------------------------
# Cache configuration Common + Bind + Unbound
# -------------------------

@dataclass
class CacheCommonConfig:
    """Common fields for cache monitoring"""
    interval: int = DEFAULT_CACHE_INTERVAL
    enable_analysis_server: bool = False
    analysis_port: int = DEFAULT_ANALYSIS_PORT
    save_changes: bool = False


@dataclass
class BindCacheConfig:
    """BIND-specific cache configuration"""
    rndc_key_file: Optional[str] = None  # e.g., "/etc/bind/rndc.key"
    dump_file: Optional[str] = None      # e.g., "/var/cache/bind/named_dump.db"


@dataclass
class UnboundCacheConfig:
    """Unbound-specific cache configuration"""
    control_config: Optional[str] = None  # Optional path to unbound-control config


@dataclass
class CacheConfig:
    """Cache monitoring configuration with server type and nested configs"""
    server_type: str = "bind"  # "bind" or "unbound"
    common: CacheCommonConfig = field(default_factory=CacheCommonConfig)
    bind: BindCacheConfig = field(default_factory=BindCacheConfig)
    unbound: UnboundCacheConfig = field(default_factory=UnboundCacheConfig)


@dataclass
class MonitorConfig:
    """Main monitoring configuration"""
    traffic: TrafficConfig = field(default_factory=TrafficConfig)
    resolver: ResolverConfig = field(default_factory=ResolverConfig)
    cache: CacheConfig = field(default_factory=CacheConfig)
    log_level: str = "INFO"
    output_dir: str = "/tmp/dnsmonitor/output"
    log_file: Optional[str] = None


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
                data = yaml.safe_load(f) or {}
            
            if 'traffic' in data:
                self.config.traffic = TrafficConfig(**data['traffic'])
            if 'resolver' in data:
                self.config.resolver = ResolverConfig(**data['resolver'])
            if 'cache' in data:
                cache_data = data['cache']
                
                # Handle server_type
                if 'server_type' in cache_data:
                    self.config.cache.server_type = cache_data['server_type']
                
                # Handle common fields
                common_fields = {}
                for field in CacheCommonConfig.__dataclass_fields__:
                    if field in cache_data:
                        common_fields[field] = cache_data[field]
                if common_fields:
                    self.config.cache.common = CacheCommonConfig(**common_fields)
                
                # Handle BIND specific fields
                bind_fields = {}
                for field in BindCacheConfig.__dataclass_fields__:
                    if field in cache_data:
                        bind_fields[field] = cache_data[field]
                    # Legacy field names compatibility
                    elif field == 'rndc_key_file' and 'bind_rndc_key' in cache_data:
                        bind_fields[field] = cache_data['bind_rndc_key']
                    elif field == 'dump_file' and 'bind_dump_file' in cache_data:
                        bind_fields[field] = cache_data['bind_dump_file']
                if bind_fields:
                    self.config.cache.bind = BindCacheConfig(**bind_fields)
                
                # Handle Unbound specific fields
                unbound_fields = {}
                for field in UnboundCacheConfig.__dataclass_fields__:
                    if field in cache_data:
                        unbound_fields[field] = cache_data[field]
                if unbound_fields:
                    self.config.cache.unbound = UnboundCacheConfig(**unbound_fields)
            
            if 'log_level' in data:
                self.config.log_level = data['log_level']
            if 'output_dir' in data:
                self.config.output_dir = data['output_dir']
            if 'log_file' in data:
                self.config.log_file = data['log_file']
                
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
        
        # Cache config - server type
        if os.getenv("DNS_SOFTWARE"):
            self.config.cache.server_type = os.getenv("DNS_SOFTWARE")
        
        # Cache config - common fields
        if os.getenv("CACHE_INTERVAL"):
            self.config.cache.common.interval = int(os.getenv("CACHE_INTERVAL"))
        if os.getenv("ENABLE_ANALYSIS_SERVER"):
            self.config.cache.common.enable_analysis_server = os.getenv("ENABLE_ANALYSIS_SERVER").lower() in ('true', 'yes', '1')
        if os.getenv("ANALYSIS_PORT"):
            self.config.cache.common.analysis_port = int(os.getenv("ANALYSIS_PORT"))
        if os.getenv("SAVE_CHANGES"):
            self.config.cache.common.save_changes = os.getenv("SAVE_CHANGES").lower() in ('true', 'yes', '1')
        
        # Cache config - BIND specific
        if os.getenv("BIND_RNDC_KEY"):
            self.config.cache.bind.rndc_key_file = os.getenv("BIND_RNDC_KEY")
        if os.getenv("BIND_DUMP_FILE"):
            self.config.cache.bind.dump_file = os.getenv("BIND_DUMP_FILE")
        
        # Cache config - Unbound specific
        if os.getenv("UNBOUND_CONTROL_CONFIG"):
            self.config.cache.unbound.control_config = os.getenv("UNBOUND_CONTROL_CONFIG")
        
        # General config
        if os.getenv("LOG_LEVEL"):
            self.config.log_level = os.getenv("LOG_LEVEL")
        if os.getenv("OUTPUT_DIR"):
            self.config.output_dir = os.getenv("OUTPUT_DIR")
        if os.getenv("LOG_FILE"):
            self.config.log_file = os.getenv("LOG_FILE")
    
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
                'server_type': self.config.cache.server_type,
                # Common fields
                'interval': self.config.cache.common.interval,
                'enable_analysis_server': self.config.cache.common.enable_analysis_server,
                'analysis_port': self.config.cache.common.analysis_port,
                'save_changes': self.config.cache.common.save_changes,
                # BIND specific fields
                'rndc_key_file': self.config.cache.bind.rndc_key_file,
                'dump_file': self.config.cache.bind.dump_file,
                # Unbound specific fields
                'control_config': self.config.cache.unbound.control_config,
            },
            'log_level': self.config.log_level,
            'output_dir': self.config.output_dir,
            'log_file': self.config.log_file,
        }
        
        with open(config_file, 'w', encoding='utf-8') as f:
            yaml.dump(config_dict, f, default_flow_style=False, allow_unicode=True)
    
    def get_config(self) -> MonitorConfig:
        """Get the current configuration"""
        return self.config