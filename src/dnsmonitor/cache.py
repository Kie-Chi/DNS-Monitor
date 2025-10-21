"""DNS Cache Monitor - Monitors DNS server cache changes for BIND and Unbound
"""

import time
import threading
import subprocess
import json
import socket
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from pathlib import Path

from config import CacheConfig
from utils.logger import get_logger
from utils import Colors, colorize


class DNSCacheRecord:
    """Represents a DNS cache record"""
    
    def __init__(self, name: str, rtype: str, rdata: str, ttl: int, timestamp: float = None):
        self.name = name
        self.rtype = rtype
        self.rdata = rdata
        self.ttl = ttl
        self.timestamp = timestamp or time.time()
        self.original_ttl = ttl
    
    def __eq__(self, other):
        if not isinstance(other, DNSCacheRecord):
            return False
        return (self.name == other.name and 
                self.rtype == other.rtype and 
                self.rdata == other.rdata)
    
    def __hash__(self):
        return hash((self.name, self.rtype, self.rdata))
    
    def __str__(self):
        return f"{self.name} {self.ttl} IN {self.rtype} {self.rdata}"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert record to dictionary"""
        return {
            'name': self.name,
            'type': self.rtype,
            'data': self.rdata,
            'ttl': self.ttl,
            'original_ttl': self.original_ttl,
            'timestamp': self.timestamp
        }
    
    def is_expired(self) -> bool:
        """Check if record is expired"""
        return time.time() - self.timestamp > self.original_ttl


class CacheSnapshot:
    """Represents a DNS cache snapshot"""
    
    def __init__(self, timestamp: float = None):
        self.timestamp = timestamp or time.time()
        self.records: Dict[Tuple[str, str], DNSCacheRecord] = {}
    
    def add_record(self, record: DNSCacheRecord) -> None:
        """Add record to snapshot"""
        key = (record.name, record.rtype)
        self.records[key] = record
    
    def get_record_count(self) -> int:
        """Get total number of records"""
        return len(self.records)
    
    def get_records_by_type(self) -> Dict[str, int]:
        """Get record count by type"""
        type_counts = {}
        for record in self.records.values():
            type_counts[record.rtype] = type_counts.get(record.rtype, 0) + 1
        return type_counts
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert snapshot to dictionary"""
        return {
            'timestamp': self.timestamp,
            'record_count': self.get_record_count(),
            'records_by_type': self.get_records_by_type(),
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
        self.modified_records: List[Tuple[DNSCacheRecord, DNSCacheRecord]] = []
        
        self._calculate_diff()
    
    def _calculate_diff(self) -> None:
        """Calculate differences between snapshots"""
        old_keys = set(self.old_snapshot.records.keys())
        new_keys = set(self.new_snapshot.records.keys())
        
        # Find added records
        for key in new_keys - old_keys:
            self.added_records.append(self.new_snapshot.records[key])
        
        # Find removed records
        for key in old_keys - new_keys:
            self.removed_records.append(self.old_snapshot.records[key])
        
        # Find modified records
        for key in old_keys & new_keys:
            old_record = self.old_snapshot.records[key]
            new_record = self.new_snapshot.records[key]
            
            if (old_record.rdata != new_record.rdata or 
                abs(old_record.ttl - new_record.ttl) > 1):  # Allow 1 second TTL difference
                self.modified_records.append((old_record, new_record))
    
    def has_changes(self) -> bool:
        """Check if there are any changes"""
        return bool(self.added_records or self.removed_records or self.modified_records)
    
    def get_summary(self) -> Dict[str, int]:
        """Get summary of changes"""
        return {
            'added': len(self.added_records),
            'removed': len(self.removed_records),
            'modified': len(self.modified_records)
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert diff to dictionary"""
        return {
            'timestamp': self.timestamp,
            'old_snapshot_time': self.old_snapshot.timestamp,
            'new_snapshot_time': self.new_snapshot.timestamp,
            'summary': self.get_summary(),
            'added_records': [record.to_dict() for record in self.added_records],
            'removed_records': [record.to_dict() for record in self.removed_records],
            'modified_records': [
                {
                    'old': old.to_dict(),
                    'new': new.to_dict()
                }
                for old, new in self.modified_records
            ]
        }


class BindCacheMonitor:
    """BIND DNS cache monitor using rndc"""
    
    def __init__(self, config: CacheConfig):
        self.config = config
        self.logger = get_logger(__name__)
        self.rndc_key_file = config.bind_rndc_key or "/etc/bind/rndc.key"
        self.dump_file = config.bind_dump_file or "/var/cache/bind/named_dump.db"
    
    def dump_cache(self) -> bool:
        """Dump BIND cache using rndc"""
        try:
            cmd = ["rndc", "-k", self.rndc_key_file, "dumpdb", "-cache"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                self.logger.error(f"rndc dump failed: {result.stderr}")
                return False
            
            # Wait for dump file to be created/updated
            time.sleep(1)
            return os.path.exists(self.dump_file)
            
        except subprocess.TimeoutExpired:
            self.logger.error("rndc dump timed out")
            return False
        except Exception as e:
            self.logger.error(f"Failed to dump BIND cache: {e}")
            return False
    
    def parse_cache(self) -> CacheSnapshot:
        """Parse BIND cache dump file"""
        snapshot = CacheSnapshot()
        
        try:
            with open(self.dump_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Parse cache entries using regex
            # BIND cache format: name ttl class type rdata
            cache_pattern = r'^([^\s]+)\s+(\d+)\s+IN\s+([A-Z]+)\s+(.+)$'
            
            for line in content.split('\n'):
                line = line.strip()
                if not line or line.startswith(';'):
                    continue
                
                match = re.match(cache_pattern, line)
                if match:
                    name, ttl, rtype, rdata = match.groups()
                    record = DNSCacheRecord(name, rtype, rdata.strip(), int(ttl))
                    snapshot.add_record(record)
            
            self.logger.debug(f"Parsed {snapshot.get_record_count()} BIND cache records")
            return snapshot
            
        except Exception as e:
            self.logger.error(f"Failed to parse BIND cache: {e}")
            return snapshot


class UnboundCacheMonitor:
    """Unbound DNS cache monitor using unbound-control"""
    
    def __init__(self, config: CacheConfig):
        self.config = config
        self.logger = get_logger(__name__)
    
    def dump_cache(self) -> str:
        """Dump Unbound cache using unbound-control"""
        try:
            cmd = ["unbound-control", "dump_cache"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                self.logger.error(f"unbound-control dump failed: {result.stderr}")
                return ""
            
            return result.stdout
            
        except subprocess.TimeoutExpired:
            self.logger.error("unbound-control dump timed out")
            return ""
        except Exception as e:
            self.logger.error(f"Failed to dump Unbound cache: {e}")
            return ""
    
    def parse_cache(self, cache_data: str) -> CacheSnapshot:
        """Parse Unbound cache data"""
        snapshot = CacheSnapshot()
        
        try:
            lines = cache_data.strip().split('\n')
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                # Unbound cache format: name type class ttl rdata
                parts = line.split()
                if len(parts) >= 5:
                    name = parts[0]
                    rtype = parts[1]
                    ttl = int(parts[3])
                    rdata = ' '.join(parts[4:])
                    
                    record = DNSCacheRecord(name, rtype, rdata, ttl)
                    snapshot.add_record(record)
            
            self.logger.debug(f"Parsed {snapshot.get_record_count()} Unbound cache records")
            return snapshot
            
        except Exception as e:
            self.logger.error(f"Failed to parse Unbound cache: {e}")
            return snapshot


class CacheAnalysisServer:
    """TCP server for cache analysis requests (similar to unbound.py)"""
    
    def __init__(self, cache_monitor, port: int = 9999):
        self.cache_monitor = cache_monitor
        self.port = port
        self.server_socket = None
        self.running = False
        self.logger = cache_monitor.logger
    
    def start(self) -> None:
        """Start the analysis server"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('localhost', self.port))
            self.server_socket.listen(5)
            
            self.running = True
            self.logger.info(f"Cache analysis server started on port {self.port}")
            
            while self.running:
                try:
                    client_socket, address = self.server_socket.accept()
                    self.logger.debug(f"Client connected from {address}")
                    
                    # Handle client in separate thread
                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket,),
                        daemon=True
                    )
                    client_thread.start()
                    
                except Exception as e:
                    if self.running:
                        self.logger.error(f"Server error: {e}")
                        
        except Exception as e:
            self.logger.error(f"Failed to start analysis server: {e}")
        finally:
            self.stop()
    
    def stop(self) -> None:
        """Stop the analysis server"""
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
        self.logger.info("Cache analysis server stopped")
    
    def _handle_client(self, client_socket: socket.socket) -> None:
        """Handle client request"""
        try:
            # Trigger cache analysis
            diff = self.cache_monitor.analyze_cache_changes()
            
            if diff and diff.has_changes():
                response = json.dumps(diff.to_dict(), indent=2)
            else:
                response = json.dumps({"message": "No cache changes detected"})
            
            client_socket.send(response.encode('utf-8'))
            
        except Exception as e:
            self.logger.error(f"Error handling client: {e}")
            error_response = json.dumps({"error": str(e)})
            try:
                client_socket.send(error_response.encode('utf-8'))
            except Exception:
                pass
        finally:
            try:
                client_socket.close()
            except Exception:
                pass


class CacheMonitor:
    """Main DNS cache monitor supporting multiple DNS servers"""
    
    def __init__(self, config: CacheConfig):
        self.config = config
        self.logger = get_logger(__name__)
        self.running = False
        
        # Initialize appropriate cache monitor
        if config.server_type.lower() == 'bind':
            self.cache_impl = BindCacheMonitor(config)
        elif config.server_type.lower() == 'unbound':
            self.cache_impl = UnboundCacheMonitor(config)
        else:
            raise ValueError(f"Unsupported DNS server type: {config.server_type}")
        
        # Cache snapshots
        self.previous_snapshot: Optional[CacheSnapshot] = None
        self.current_snapshot: Optional[CacheSnapshot] = None
        
        # Analysis server
        self.analysis_server = None
        if config.enable_analysis_server:
            self.analysis_server = CacheAnalysisServer(self, config.analysis_port)
        
        # Statistics
        self.stats = {
            'total_snapshots': 0,
            'total_changes': 0,
            'records_added': 0,
            'records_removed': 0,
            'records_modified': 0,
        }
    
    def start(self) -> None:
        """Start cache monitoring"""
        self.logger.info(f"Starting {self.config.server_type} cache monitoring...")
        self.running = True
        
        try:
            # Start analysis server if enabled
            if self.analysis_server:
                server_thread = threading.Thread(target=self.analysis_server.start, daemon=True)
                server_thread.start()
            
            # Take initial snapshot
            self.current_snapshot = self._take_snapshot()
            if self.current_snapshot:
                self.logger.info(f"Initial snapshot: {self.current_snapshot.get_record_count()} records")
                self._print_cache_summary(self.current_snapshot)
            
            # Start monitoring loop
            self._monitoring_loop()
            
        except KeyboardInterrupt:
            self.logger.info("Monitoring interrupted by user")
        except Exception as e:
            self.logger.error(f"Cache monitoring failed: {e}")
        finally:
            self.stop()
    
    def stop(self) -> None:
        """Stop cache monitoring"""
        self.logger.info("Stopping cache monitoring...")
        self.running = False
        
        if self.analysis_server:
            self.analysis_server.stop()
        
        # Save final statistics
        self._save_statistics()
        
        self.logger.info("Cache monitoring stopped")
    
    def _monitoring_loop(self) -> None:
        """Main monitoring loop"""
        last_report_time = time.time()
        
        while self.running:
            try:
                # Take new snapshot
                new_snapshot = self._take_snapshot()
                if not new_snapshot:
                    time.sleep(self.config.interval)
                    continue
                
                # Compare with previous snapshot
                if self.current_snapshot:
                    diff = CacheDiff(self.current_snapshot, new_snapshot)
                    
                    if diff.has_changes():
                        self._process_cache_changes(diff)
                        self.stats['total_changes'] += 1
                        self.stats['records_added'] += len(diff.added_records)
                        self.stats['records_removed'] += len(diff.removed_records)
                        self.stats['records_modified'] += len(diff.modified_records)
                
                # Update snapshots
                self.previous_snapshot = self.current_snapshot
                self.current_snapshot = new_snapshot
                self.stats['total_snapshots'] += 1
                
                # Print periodic status
                current_time = time.time()
                if current_time - last_report_time >= 60:  # Every minute
                    self._print_status()
                    last_report_time = current_time
                
                time.sleep(self.config.interval)
                
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(self.config.interval)
    
    def _take_snapshot(self) -> Optional[CacheSnapshot]:
        """Take a cache snapshot"""
        try:
            if isinstance(self.cache_impl, BindCacheMonitor):
                if self.cache_impl.dump_cache():
                    return self.cache_impl.parse_cache()
            elif isinstance(self.cache_impl, UnboundCacheMonitor):
                cache_data = self.cache_impl.dump_cache()
                if cache_data:
                    return self.cache_impl.parse_cache(cache_data)
            
            return None
            
        except Exception as e:
            self.logger.error(f"Failed to take cache snapshot: {e}")
            return None
    
    def _process_cache_changes(self, diff: CacheDiff) -> None:
        """Process and log cache changes"""
        summary = diff.get_summary()
        
        self.logger.info(
            f"{colorize('CACHE CHANGES', Colors.CYAN)}: "
            f"+{summary['added']} -{summary['removed']} ~{summary['modified']}"
        )
        
        # Log added records
        for record in diff.added_records[:5]:  # Limit to first 5
            self.logger.info(f"  {colorize('ADDED', Colors.GREEN)}: {record}")
        
        if len(diff.added_records) > 5:
            self.logger.info(f"  ... and {len(diff.added_records) - 5} more added records")
        
        # Log removed records
        for record in diff.removed_records[:5]:  # Limit to first 5
            self.logger.info(f"  {colorize('REMOVED', Colors.RED)}: {record}")
        
        if len(diff.removed_records) > 5:
            self.logger.info(f"  ... and {len(diff.removed_records) - 5} more removed records")
        
        # Log modified records
        for old_record, new_record in diff.modified_records[:3]:  # Limit to first 3
            self.logger.info(f"  {colorize('MODIFIED', Colors.YELLOW)}: {old_record.name}")
            self.logger.info(f"    Old: {old_record.rdata} (TTL: {old_record.ttl})")
            self.logger.info(f"    New: {new_record.rdata} (TTL: {new_record.ttl})")
        
        if len(diff.modified_records) > 3:
            self.logger.info(f"  ... and {len(diff.modified_records) - 3} more modified records")
        
        # Save detailed changes if configured
        if self.config.save_changes:
            self._save_cache_changes(diff)
    
    def _print_cache_summary(self, snapshot: CacheSnapshot) -> None:
        """Print cache summary"""
        print(f"\n{Colors.BOLD}{Colors.CYAN}Cache Summary{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*40}{Colors.RESET}")
        print(f"Total records: {colorize(str(snapshot.get_record_count()), Colors.GREEN)}")
        
        records_by_type = snapshot.get_records_by_type()
        for rtype, count in sorted(records_by_type.items()):
            print(f"  {rtype}: {colorize(str(count), Colors.YELLOW)}")
        
        print(f"{Colors.CYAN}{'='*40}{Colors.RESET}\n")
    
    def _print_status(self) -> None:
        """Print monitoring status"""
        print(f"\n{Colors.BOLD}Cache Monitor Status{Colors.RESET}")
        print(f"Snapshots taken: {colorize(str(self.stats['total_snapshots']), Colors.CYAN)}")
        print(f"Changes detected: {colorize(str(self.stats['total_changes']), Colors.YELLOW)}")
        print(f"Records added: {colorize(str(self.stats['records_added']), Colors.GREEN)}")
        print(f"Records removed: {colorize(str(self.stats['records_removed']), Colors.RED)}")
        print(f"Records modified: {colorize(str(self.stats['records_modified']), Colors.MAGENTA)}")
        
        if self.current_snapshot:
            print(f"Current cache size: {colorize(str(self.current_snapshot.get_record_count()), Colors.CYAN)}")
    
    def _save_cache_changes(self, diff: CacheDiff) -> None:
        """Save cache changes to file"""
        try:
            timestamp = get_timestamp()
            changes_file = f"cache_changes_{timestamp}.json"
            save_json(diff.to_dict(), changes_file)
            
            self.logger.debug(f"Cache changes saved to: {changes_file}")
            
        except Exception as e:
            self.logger.error(f"Failed to save cache changes: {e}")
    
    def _save_statistics(self) -> None:
        """Save monitoring statistics"""
        try:
            stats_data = {
                'config': {
                    'server_type': self.config.server_type,
                    'interval': self.config.interval,
                },
                'statistics': self.stats,
                'final_snapshot': self.current_snapshot.to_dict() if self.current_snapshot else None,
            }
            
            timestamp = get_timestamp()
            stats_file = f"cache_monitor_stats_{timestamp}.json"
            save_json(stats_data, stats_file)
            
            self.logger.info(f"Statistics saved to: {stats_file}")
            
        except Exception as e:
            self.logger.error(f"Failed to save statistics: {e}")
    
    def analyze_cache_changes(self) -> Optional[CacheDiff]:
        """Analyze current cache changes (for analysis server)"""
        try:
            new_snapshot = self._take_snapshot()
            if not new_snapshot or not self.current_snapshot:
                return None
            
            diff = CacheDiff(self.current_snapshot, new_snapshot)
            
            # Update current snapshot
            self.current_snapshot = new_snapshot
            
            return diff if diff.has_changes() else None
            
        except Exception as e:
            self.logger.error(f"Failed to analyze cache changes: {e}")
            return None