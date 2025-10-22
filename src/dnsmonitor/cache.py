"""DNS Cache Monitor - Monitors DNS server cache changes for BIND and Unbound
"""

from concurrent.futures import thread
import time
import threading
import subprocess
import json
import socket
import re
import sys
import queue
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, NamedTuple, Set, Tuple, override
from dataclasses import dataclass, asdict, field
from pathlib import Path
import socketserver

from .traffic import create_resolver_monitor
from .packet import DNSPacket
from .config import CacheConfig, TrafficConfig
from .utils.logger import get_logger
from .utils import Colors, colorize
from .utils.common import get_timestamp, save_json

class PendingQuery(NamedTuple):
    query: DNSPacket
    timestamp: float

@dataclass(slots=True)
class DNSCacheRecord:
    """Represents a DNS cache record"""
    name: str
    rtype: str
    rdata: str
    ttl: int
    timestamp: float = field(default_factory=time.time)
    original_ttl: int = field(init=False)

    def __post_init__(self):
        self.original_ttl = self.ttl
    
    def __eq__(self, other):
        if not isinstance(other, DNSCacheRecord):
            return False
        return (self.name == other.name and 
                self.rtype == other.rtype and 
                self.rdata == other.rdata)
    
    def __hash__(self):
        return hash((self.name, self.rdata, self.rtype))
    
    def __str__(self):
        return f"{self.name} {self.ttl} IN {self.rtype} {self.rdata}"
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    def is_expired(self) -> bool:
        return time.time() - self.timestamp > self.original_ttl


class CacheSnapshot:
    """Represents a DNS cache snapshot"""
    
    def __init__(self, timestamp: float = None, trigger: Optional[DNSPacket] = None):
        self.timestamp = timestamp or time.time()
        self.trigger = trigger
        self.records: Dict[Tuple[str, str, str], DNSCacheRecord] = {}
    
    def add_record(self, record: DNSCacheRecord) -> None:
        key = (record.name, record.rtype, record.rdata)
        self.records[key] = record
    
    def record_cnts(self) -> int:
        return len(self.records)
    
    def record_grps(self) -> Dict[str, int]:
        type_counts = {}
        for record in self.records.values():
            type_counts[record.rtype] = type_counts.get(record.rtype, 0) + 1
        return type_counts
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp,
            'trigger': self.trigger.to_dict() if self.trigger else None,
            'record_cnts': self.record_cnts(),
            'record_grps': self.record_grps(),
            'records': [record.to_dict() for record in self.records.values()]
        }


class CacheDiff:
    """Represents differences between two cache snapshots"""
    
    def __init__(self, old_snapshot: CacheSnapshot, new_snapshot: CacheSnapshot):
        self.old_snapshot = old_snapshot
        self.new_snapshot = new_snapshot
        self.timestamp = time.time()
        
        self.added_records: List[DNSCacheRecord] = []
        self.removed_records: List[DNSCacheRecord] = []
        self.modified_records: List[Dict[str, Any]] = []
        
        self._calculate_diff()
    
    def _calculate_diff(self) -> None:
        old_records_set = set(self.old_snapshot.records.values())
        new_records_set = set(self.new_snapshot.records.values())
        
        self.added_records = list(new_records_set - old_records_set)
        self.removed_records = list(old_records_set - new_records_set)
        
        old_map = {hash(r): r for r in old_records_set}
        new_map = {hash(r): r for r in new_records_set}

        common_keys = set(old_map.keys()) & set(new_map.keys())
        added_pkts = []
        removed_pkts = []
        for key in common_keys:
            old_rec = old_map[key]
            new_rec = new_map[key]
            # If TTL has decreased, it's a modification
            if new_rec.ttl < old_rec.ttl:
                self.modified_records.append({
                    'old': old_rec.to_dict(),
                    'new': new_rec.to_dict(),
                })
                added_pkts.append(new_rec.trigger)
                removed_pkts.append(old_rec.trigger)
        if added_pkts:
            self.added_records = [rec for rec in self.added_records if rec.trigger not in added_pkts]
        if removed_pkts:
            self.removed_records = [rec for rec in self.removed_records if rec.trigger not in removed_pkts]

    def has_changes(self) -> bool:
        return bool(self.added_records or self.removed_records or self.modified_records)
    
    def get_summary(self) -> Dict[str, int]:
        return {
            'added': len(self.added_records),
            'removed': len(self.removed_records),
            'modified': len(self.modified_records)
        }
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp,
            'old_snap_time': self.old_snapshot.timestamp,
            'new_snap_time': self.new_snapshot.timestamp,
            'trigger': self.new_snapshot.trigger.to_dict() if self.new_snapshot.trigger else None,
            'summary': self.get_summary(),
            'added': [r.to_dict() for r in self.added_records],
            'removed': [r.to_dict() for r in self.removed_records],
            'modified': self.modified_records
        }


class AbstractCacheMonitor(ABC):
    def __init__(self, config: CacheConfig):
        self.config = config
        self.logger = get_logger(__name__)

    @abstractmethod
    def dump_cache(self) -> str: pass

    @abstractmethod
    def parse_cache(self, cache_content: str, trigger: Optional[DNSPacket]) -> CacheSnapshot: pass

class BindCacheMonitor(AbstractCacheMonitor):
    def __init__(self, config: CacheConfig):
        super().__init__(config)
        self.rndc_key_file = config.bind.rndc_key_file or "/usr/local/etc/bind/rndc.key"
        self.dump_file = config.bind.dump_file or "/usr/local/var/cache/bind/named_dump.db"
    
    def dump_cache(self) -> str:
        # Simplified dump logic for brevity, original logic is also fine
        try:
            cmd = ["rndc", "-k", self.rndc_key_file, "dumpdb", "-cache"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                self.logger.error(f"rndc dump failed: {result.stderr}")
                return ""
            
            time.sleep(0.1)
            with open(self.dump_file, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception as e:
            self.logger.error(f"Failed to dump BIND cache: {e}")
            return ""

    def parse_cache(self, cache_data: str, trigger: Optional[DNSPacket]) -> CacheSnapshot:
        snapshot = CacheSnapshot(trigger=trigger)
        cache_pattern = r'^([^\s;]+)\s+(\d+)\s+(?:IN)\s+([A-Z0-9]+)\s+(.+)$'
        for line in cache_data.split('\n'):
            line = line.strip()
            if not line or line.startswith(';'):
                continue
            
            match = re.match(cache_pattern, line)
            if match:
                name, ttl, rtype, rdata = match.groups()
                record = DNSCacheRecord(name, rtype, rdata.strip(), int(ttl))
                snapshot.add_record(record)
        return snapshot

class UnboundCacheMonitor(AbstractCacheMonitor):
    def dump_cache(self) -> str:
        try:
            cmd = ["unbound-control", "dump_cache"]
            if self.config.unbound.control_config:
                cmd = ["unbound-control", "-c", self.config.unbound.control_config, "dump_cache"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                self.logger.error(f"unbound-control dump failed: {result.stderr}")
                return ""
            return result.stdout
        except Exception as e:
            self.logger.error(f"Failed to dump Unbound cache: {e}")
            return ""
    
    def parse_cache(self, cache_data: str, trigger: Optional[DNSPacket]) -> CacheSnapshot:
        snapshot = CacheSnapshot(trigger=trigger)
        for line in cache_data.strip().split('\n'):
            if line.startswith("msg") or "validation" in line or not line:
                continue
            parts = line.split()
            if len(parts) >= 5 and parts[3].isdigit():
                name, rtype, _, ttl, *rdata_parts = parts
                rdata = ' '.join(rdata_parts)
                record = DNSCacheRecord(name, rtype, rdata, int(ttl))
                snapshot.add_record(record)
        return snapshot

# REFACTORED: CacheAnalysisServer now retrieves latest data instead of triggering analysis
class CacheAnalysisServer(socketserver.ThreadingTCPServer):
    def __init__(self, server_address, RequestHandlerClass, monitor: 'CacheMonitor') -> None:
        super().__init__(server_address, RequestHandlerClass)
        self.monitor = monitor

class CacheRequestHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        try:
            with self.server.monitor.lock:
                latest_diff = self.server.monitor.last_diff
                latest_snapshot = self.server.monitor.current_snapshot
            
            if latest_diff:
                response = {
                    "status": "success",
                    "message": "Cache diff available.",
                    "diff": latest_diff.to_dict()
                }
            elif latest_snapshot:
                response = {
                    "status": "success",
                    "message": "No changes since last trigger.",
                    "snapshot": latest_snapshot.to_dict()
                }
            else:
                response = {
                    "status": "error",
                    "message": "No snapshot available yet."
                }

            self.request.sendall(json.dumps(response, indent=2).encode('utf-8'))
        except Exception as e:
            self.server.monitor.logger.error(f"Error handling client request: {e}")
        finally:
            self.request.close()


class CacheMonitor:
    def __init__(self, config: CacheConfig):
        resolver_ip = config.common.resolver_ip
        if not resolver_ip:
            raise ValueError("resolver_ip must be set for transaction-aware monitoring.")

        self.config = config
        self.logger = get_logger(__name__)
        self.running = threading.Event()
        self.lock = threading.Lock()
        
        # Data storage, protected by the lock
        self.current_snapshot: Optional[CacheSnapshot] = None
        self.last_diff: Optional[CacheDiff] = None
        
        self.pd_query: Dict[Tuple[str, int, int], PendingQuery] = {}
        self.trans_lock = threading.Lock()
        self.TRANSACTION_TIMEOUT = config.common.timeout # 2 seconds

        # Traffic monitoring setup
        self.packet_queue = queue.Queue(maxsize=10000)
        self.trigger_queue = queue.Queue(maxsize=100)
        bpf_filter = f"host {resolver_ip} and udp port 53"
        traffic_cfg = TrafficConfig(interface=config.common.interface, bpf_filter=bpf_filter)
        self.traffic_monitor = create_resolver_monitor(traffic_cfg, self._enqueue_packet)
        self.process_thread: Optional[threading.Thread] = None
        self.monitor_thread: Optional[threading.Thread] = None
        self.cleanup_thread: Optional[threading.Thread] = None
        
        # Analysis server
        self.analysis_server = self._setup_server()

    # Initialization and thread management methods
    def _setup_server(self):
        if self.config.common.enable_analysis_server:
            addr = (self.config.common.analysis_address, self.config.common.analysis_port)
            return CacheAnalysisServer(addr, CacheRequestHandler, self)
        return None

    def start(self):
        self.logger.info(f"Starting {self.config.server_type} cache monitoring...")
        self.running.set()

        self.logger.info("Taking initial cache snapshot...")
        self.current_snapshot = self._take_snapshot(None)

        self.process_thread = threading.Thread(target=self._process_worker, daemon=True)
        self.process_thread.start()

        self.monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitor_thread.start()

        self.cleanup_thread = threading.Thread(target=self._cleanup_pd_query, daemon=True)
        self.cleanup_thread.start()

        if self.analysis_server:
            threading.Thread(target=self.analysis_server.serve_forever, daemon=True).start()

        self.logger.info(f"Listening for DNS traffic involving {self.config.common.resolver_ip}...")
        self.traffic_monitor.start()

    def stop(self):
        self.logger.info("Stopping cache monitoring...")
        self.running.clear()
        self.traffic_monitor.stop()

        if self.analysis_server:
            self.analysis_server.shutdown()
        
        self.trigger_queue.put(None) # Sentinel for monitor_thread
        if self.process_thread and self.process_thread.is_alive(): 
            self.process_thread.join(timeout=2)
        if self.monitor_thread and self.monitor_thread.is_alive(): 
            self.monitor_thread.join(timeout=2)
        if self.cleanup_thread and self.cleanup_thread.is_alive(): 
            self.cleanup_thread.join(timeout=2)
        
        self.logger.info("Cache monitoring stopped.")
    
    def _enqueue_packet(self, packet: DNSPacket):
        """Keep it fast."""
        try:
            self.packet_queue.put_nowait(packet)
        except queue.Full:
            self.logger.warning("Packet queue is full, dropped.")

    def _process_worker(self):
        """Continuously processes packets from the packet_queue."""
        self.logger.debug("Packet processing worker started.")
        while self.running.is_set():
            try:
                packet = self.packet_queue.get(timeout=1.0)
                if packet is None: # Sentinel
                    break
                self._process_packet(packet)
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Error in packet processing worker: {e}", exc_info=True)
        self.logger.debug("Packet processing worker stopped.")

    def _process_packet(self, packet: DNSPacket):
        resolver_ip = self.config.common.resolver_ip
        
        with self.trans_lock:
            if not packet.is_response and packet.dst_ip == resolver_ip:
                key = (packet.src_ip, packet.src_port, packet.query_id)
                self.pd_query[key] = PendingQuery(query=packet, timestamp=time.time())
                self.logger.debug(f"Tracking new query: {packet.qname} from {packet.src_ip}:{packet.src_port}")

            elif packet.is_response and packet.src_ip == resolver_ip:
                key = (packet.dst_ip, packet.dst_port, packet.query_id)
                if key in self.pd_query:
                    pending = self.pd_query.pop(key)
                    self.logger.debug(f"Matched response for: {pending.query.qname}")
                    try:
                        self.trigger_queue.put_nowait(packet)
                    except queue.Full:
                        self.logger.warning("Trigger queue full, dropping transaction completion trigger.")

    def _cleanup_pd_query(self):
        while self.running.is_set():
            time.sleep(self.TRANSACTION_TIMEOUT)
            with self.trans_lock:
                now = time.time()
                expired_keys = [
                    key for key, trans in self.pd_query.items()
                    if now - trans.timestamp > self.TRANSACTION_TIMEOUT
                ]
                for key in expired_keys:
                    trans = self.pd_query.pop(key)
                    self.logger.debug(f"Timing out tracked query for {trans.query.qname}")

    def _monitoring_loop(self):
        last_dump_time = 0.0
        while self.running.is_set():
            try:
                trigger_packet = self.trigger_queue.get(timeout=1.0)
                if trigger_packet is None: 
                    break

                if time.time() - last_dump_time < self.config.common.cooldown_period:
                    continue

                self.logger.info(f"Transaction for '{trigger_packet.qname}' completed. Triggering cache dump.")
                
                new_snapshot = self._take_snapshot(trigger_packet)
                last_dump_time = time.time()
                
                with self.lock:
                    if new_snapshot and self.current_snapshot:
                        diff = CacheDiff(self.current_snapshot, new_snapshot)
                        if diff.has_changes():
                            self.last_diff = diff
                            self.print(diff)
                    self.current_snapshot = new_snapshot

            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}", exc_info=True)

    def _take_snapshot(self, trigger: Optional[DNSPacket]) -> Optional[CacheSnapshot]:
        try:
            cache_data = self.cache_impl.dump_cache()
            if cache_data:
                return self.cache_impl.parse_cache(cache_data, trigger)
            return None
        except Exception as e:
            self.logger.error(f"Failed to take cache snapshot: {e}")
            return None

    def print(self, diff: CacheDiff):
        summary = diff.get_summary()
        self.logger.info(
            f"{colorize('CACHE CHANGES DETECTED', Colors.CYAN)}: "
            f"+{summary['added']} added, -{summary['removed']} removed, ~{summary['modified']} modified TTL"
        )
        for record in diff.added_records[:5]:
            self.logger.info(f"  {colorize('+', Colors.GREEN)} {record}")
        
        if self.config.common.save_changes:
            self._save_cache_changes(diff)

    def _save_cache_changes(self, diff: CacheDiff):
        try:
            timestamp = get_timestamp()
            path = Path(self.config.common.cache_changes_dir)
            path.mkdir(parents=True, exist_ok=True)
            filename = path / f"cache_diff_{timestamp}.json"
            save_json(diff.to_dict(), str(filename))
            self.logger.debug(f"Cache changes saved to: {filename}")
        except Exception as e:
            self.logger.error(f"Failed to save cache changes: {e}")