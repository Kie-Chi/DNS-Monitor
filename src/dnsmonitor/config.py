"""
Configuration management for DNS Monitor
"""

import os
from token import OP
import yaml
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field, asdict
from pathlib import Path

from .utils.common import get_iface
from .constants import DEFAULT_CACHE_INTERVAL, DEFAULT_ANALYSIS_PORT, DEFAULT_RESOLVE_PORT


@dataclass
class TrafficConfig:
    """DNS Traffic Monitoring Configuration"""
    interface: Optional[str] = None
    pcap_dir: str = "pcap"
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
    interface: Optional[str] = None
    client_ip: Optional[str] = None
    resolver_ip: Optional[str] = None
    timeout: int = 3
    output_path: str = "resolve"

    enable_server: bool = False
    analysis_port: int = DEFAULT_RESOLVE_PORT


# -------------------------
# Cache configuration Common + Bind + Unbound
# -------------------------

@dataclass
class CacheCommonConfig:
    """Common fields for cache monitoring"""
    interface: Optional[str] = None
    resolver_ip: Optional[str] = None
    cooldown_period: float = .5
    timeout: float = 2.0
    enable_analysis_server: bool = False
    analysis_address: str = "0.0.0.0"
    analysis_port: int = DEFAULT_ANALYSIS_PORT
    save_changes: bool = True
    output_path: str = "cache"


@dataclass
class BindCacheConfig:
    """BIND-specific cache configuration"""
    rndc_key_file: str = "/usr/local/var/bind/rndc.key"
    dump_file: str = "/usr/local/var/bind/named_dump.db"


@dataclass
class UnboundCacheConfig:
    """Unbound-specific cache configuration"""
    control_config: str = "/usr/local/var/unbound/control.conf"


@dataclass
class CacheConfig:
    """Cache monitoring configuration with server type and nested configs"""
    server_type: str = "bind"  # "bind" or "unbound"
    common: CacheCommonConfig = field(default_factory=CacheCommonConfig)
    bind: BindCacheConfig = field(default_factory=BindCacheConfig)
    unbound: UnboundCacheConfig = field(default_factory=UnboundCacheConfig)


@dataclass
class MonitorConfig:
    """Main monitoring configuration using dictionaries for named instances."""
    traffic: TrafficConfig = field(default_factory=TrafficConfig)
    resolvers: Dict[str, ResolverConfig] = field(default_factory=dict)
    caches: Dict[str, CacheConfig] = field(default_factory=dict)
    log_level: str = "INFO"
    output_dir: str = "/tmp/dnsmonitor/output"
    log_file: Optional[str] = None
    cidr: str = "10.0.0.0/24"


class ConfigManager:
    """Configuration manager for DNS Monitor"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file
        self.config = MonitorConfig()
        
        if config_file and Path(config_file).exists():
            self.load_from_file(config_file)

    def _parse_cache_config(self, cache_data: Dict[str, Any]) -> CacheConfig:
        """Helper to parse a single cache config dictionary."""
        server_type = cache_data.get('server_type', 'bind')

        # Handle common fields
        common_fields = {f: cache_data[f] for f in CacheCommonConfig.__dataclass_fields__ if f in cache_data}
        common_config = CacheCommonConfig(**common_fields)

        # Handle BIND specific fields
        bind_fields = {}
        for f in BindCacheConfig.__dataclass_fields__:
            if f in cache_data: bind_fields[f] = cache_data[f]
        # Legacy compatibility
        if 'bind_rndc_key' in cache_data: bind_fields['rndc_key_file'] = cache_data['bind_rndc_key']
        if 'bind_dump_file' in cache_data: bind_fields['dump_file'] = cache_data['bind_dump_file']
        bind_config = BindCacheConfig(**bind_fields)

        # Handle Unbound specific fields
        unbound_fields = {f: cache_data[f] for f in UnboundCacheConfig.__dataclass_fields__ if f in cache_data}
        unbound_config = UnboundCacheConfig(**unbound_fields)

        return CacheConfig(
            server_type=server_type,
            common=common_config,
            bind=bind_config,
            unbound=unbound_config
        )

    def load_from_file(self, config_file: str) -> None:
        """Load configuration from YAML file (now expecting dictionaries)."""
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f) or {}
            
            if 'cidr' in data:
                self.config.cidr = data['cidr']
            else:
                raise ValueError("CIDR must be specified in the configuration file.")

            _iface = get_iface(self.config.cidr)
            if not _iface:
                raise ValueError(f"Could not find interface for CIDR {self.config.cidr}")

            if 'traffic' in data:
                self.config.traffic = TrafficConfig(**data['traffic'])
                if self.config.traffic.interface is None:
                    self.config.traffic.interface = _iface

            if 'resolvers' in data and isinstance(data['resolvers'], dict):
                self.config.resolvers = {
                    name: ResolverConfig(**conf) for name, conf in data['resolvers'].items()
                }
                for resolver in self.config.resolvers.values():
                    if resolver.interface is None:
                        resolver.interface = _iface

            if 'caches' in data and isinstance(data['caches'], dict):
                self.config.caches = {
                    name: self._parse_cache_config(conf) for name, conf in data['caches'].items()
                }
                for cache in self.config.caches.values():
                    if cache.common.interface is None:
                        cache.common.interface = _iface
            if 'log_level' in data: self.config.log_level = data['log_level']
            if 'output_dir' in data: self.config.output_dir = data['output_dir']
            if 'log_file' in data: self.config.log_file = data['log_file']
                
        except Exception as e:
            raise ValueError(f"Failed to load config from {config_file}: {e}")
    
    def save_to_file(self, config_file: str) -> None:
        """Save current configuration to YAML file with dictionary format."""
        
        # Helper to convert nested dataclasses for cache
        def cache_to_dict(c: CacheConfig) -> dict:
            data = asdict(c.common)
            data['server_type'] = c.server_type
            if c.server_type == 'bind':
                data.update(asdict(c.bind))
            elif c.server_type == 'unbound':
                data.update(asdict(c.unbound))
            return data

        config_dict = {
            'traffic': asdict(self.config.traffic),
            'resolvers': {name: asdict(conf) for name, conf in self.config.resolvers.items()},
            'caches': {name: cache_to_dict(conf) for name, conf in self.config.caches.items()},
            'log_level': self.config.log_level,
            'output_dir': self.config.output_dir,
            'log_file': self.config.log_file,
        }
        
        with open(config_file, 'w', encoding='utf-8') as f:
            yaml.dump(config_dict, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
    
    def get_config(self) -> MonitorConfig:
        """Get the current configuration"""
        return self.config