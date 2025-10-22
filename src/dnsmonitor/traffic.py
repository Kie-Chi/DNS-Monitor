"""
Optimized Traffic Monitor with scenario-specific implementations
"""

import time
import threading
import os
import signal
import queue
from pathlib import Path
from typing import Optional, Callable, Any, List
from enum import Enum
from concurrent.futures import ThreadPoolExecutor

from dpkt.dns import DNS

try:
    import pcapy
    PCAPY_AVAILABLE = True
except ImportError:
    print("Warning: pcapy not available, using mock implementation")
    PCAPY_AVAILABLE = False

from .config import TrafficConfig
from .packet import OptimizedDNSAnalyzer, DNSPacket
from .utils.logger import get_logger
from .utils.common import ensure_directory


class MonitorMode(Enum):
    """monitor modes"""
    PCAP_ONLY = "pcap_only"          # only write pcap files
    DISPLAY_ONLY = "display_only"    # only display tcpdump-style output
    RESOLVER_ONLY = "resolver_only"  # only provide to resolver analysis
    MIXED = "mixed"                  # mixed mode

    def __str__(self):
        return self.value.lower()


class OptimizedTrafficMonitor:
    """optimized traffic monitor"""
    
    def __init__(self, config: TrafficConfig, mode: MonitorMode = MonitorMode.MIXED):
        self.config = config
        self.mode = mode
        self.logger = get_logger(__name__)
        
        # Core components
        self.analyzer = OptimizedDNSAnalyzer()
        self.pcap_handle = None
        self.pcap_dumper = None
        
        # Threading components
        self.running = False
        self.capture_thread = None
        self.worker_executor = None
        self.packet_queue = queue.Queue(maxsize=config.buffer_size // 1024)  # Reasonable queue size
        
        # Performance tracking
        self.packet_count = 0
        self.dns_packet_count = 0
        self.start_time = None
        self.dropped_packets = 0
        
        # Callbacks
        self.packet_callback = None
        self.display_callback = None
        
        # PCAP rotation
        self.current_pcap_file = None
        self.pcap_file_size = 0
        self.pcap_file_count = 0
        self.pcap_start_time = None
        
        # Worker thread configuration
        self.num_workers = min(4, (os.cpu_count() or 1) + 1)  # Optimal worker count
        
        if self.mode in [MonitorMode.PCAP_ONLY, MonitorMode.MIXED]:
            ensure_directory(self.config.pcap_dir)
        
        # Signal handling
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def set_packet_callback(self, callback: Callable[[DNSPacket], None]) -> None:
        """set packet callback function (for resolver scenario)"""
        self.packet_callback = callback
    
    def set_display_callback(self, callback: Callable[[str], None]) -> None:
        """set display callback function (for custom output)"""
        self.display_callback = callback
    
    def start(self) -> None:
        """Start traffic monitoring with multi-threading architecture"""
        self.logger.info(f"Starting DNS traffic monitoring in {self.mode.value} mode...")
        self.running = True
        self.start_time = time.time()
        
        try:
            self._init_capture()
            if self.mode in [MonitorMode.PCAP_ONLY, MonitorMode.MIXED]:
                self._init_pcap_writer()
            
            # Start worker thread pool for packet processing
            self.worker_executor = ThreadPoolExecutor(
                max_workers=self.num_workers,
                thread_name_prefix="dns_worker"
            )
            
            # Start capture thread (producer)
            self.capture_thread = threading.Thread(target=self._capture_worker, daemon=True)
            self.capture_thread.start()
            
            self.logger.info(f"Traffic monitoring started with {self.num_workers} worker threads")
            
            # Main monitoring loop
            while self.running:
                time.sleep(1)
                if self.mode in [MonitorMode.PCAP_ONLY, MonitorMode.MIXED]:
                    self._check_pcap_rotation()
                    
        except Exception as e:
            self.logger.error(f"Failed to start traffic monitoring: {e}")
            self.stop()

    def stop(self) -> None:
        """Stop traffic monitoring and cleanup resources"""
        self.logger.info("Stopping DNS traffic monitoring...")
        self.running = False
        
        # Wait for capture thread to finish
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=5)
        
        # Shutdown worker thread pool
        if self.worker_executor:
            self.worker_executor.shutdown(wait=True)
            self.worker_executor = None
        
        # Close pcap resources
        try:
            if self.pcap_dumper:
                if hasattr(self.pcap_dumper, 'close'):
                    self.pcap_dumper.close()
                self.pcap_dumper = None
                
            if self.pcap_handle:
                if hasattr(self.pcap_handle, 'close'):
                    self.pcap_handle.close()
                self.pcap_handle = None
                
        except Exception as e:
            self.logger.debug(f"Error closing pcap resources: {e}")
        
        # Log final statistics
        if self.start_time:
            duration = time.time() - self.start_time
            pps = self.packet_count / duration if duration > 0 else 0
            dns_pps = self.dns_packet_count / duration if duration > 0 else 0
            self.logger.info(f"Monitoring stopped. Processed {self.packet_count} packets "
                           f"({self.dns_packet_count} DNS) in {duration:.2f}s. "
                           f"Rate: {pps:.0f} pps ({dns_pps:.0f} DNS pps). "
                           f"Dropped: {self.dropped_packets}")
        
        self.logger.info("DNS traffic monitoring stopped")

    def _signal_handler(self, signum, frame):
        """signal handler"""
        self.logger.info(f"Received signal {signum}, stopping...")
        self.stop()

    def _init_capture(self) -> None:
        """init pcap handle"""  
        if not PCAPY_AVAILABLE:
            raise RuntimeError("pcapy is not available")
            
        try:
            # open pcap handle
            self.pcap_handle = pcapy.open_live(
                self.config.interface,
                self.config.snaplen,
                self.config.enable_promiscuous,  # promiscuous mode
                self.config.capture_timeout_ms
            )
            
            # filter dns traffic
            dns_filter = f"port {self.config.dns_port}"
            self.pcap_handle.setfilter(dns_filter)
            
            self.logger.info(f"Initialized capture on {self.config.interface} with filter: {dns_filter}")
            
        except Exception as e:
            raise RuntimeError(f"Failed to initialize packet capture: {e}")

    def _init_pcap_writer(self) -> None:
        """init pcap writer"""
        try:
            # init pcap filename
            timestamp = int(time.time())
            filename = f"dns_traffic_{timestamp}.pcap"
            self.current_pcap_file = os.path.join(self.config.pcap_dir, filename)
            
            # init pcap dumper
            if self.pcap_handle:
                self.pcap_dumper = self.pcap_handle.dump_open(self.current_pcap_file)
                self.pcap_start_time = time.time()
                
                self.logger.info(f"Started PCAP writing to: {self.current_pcap_file}")
            else:
                raise RuntimeError("PCAP handle not initialized")
                
        except Exception as e:
            raise RuntimeError(f"Failed to initialize PCAP writer: {e}")
    
    def _capture_worker(self) -> None:
        """Producer thread: capture packets and put them into queue"""
        self.logger.info("Started packet capture worker (producer)")
        
        try:
            while self.running:
                try:
                    # Get next packet from pcap handle
                    header, packet_data = self.pcap_handle.next()
                    if header is None:
                        continue
                    
                    self.packet_count += 1
                    
                    # Get timestamp
                    try:
                        ts = header.getts()
                        timestamp = ts[0] + ts[1] * 1e-6
                    except Exception:
                        timestamp = time.time()
                    
                    # Create packet info tuple
                    packet_info = (header, packet_data, timestamp)
                    
                    # Try to put packet in queue (non-blocking)
                    try:
                        self.packet_queue.put_nowait(packet_info)
                        
                        # Submit processing task to worker pool
                        if self.worker_executor and not self.worker_executor._shutdown:
                            self.worker_executor.submit(self._process_packet, packet_info)
                            
                    except queue.Full:
                        # Queue is full, drop packet and increment counter
                        self.dropped_packets += 1
                        if self.dropped_packets % 1000 == 0:
                            self.logger.warning(f"Dropped {self.dropped_packets} packets due to queue overflow")
                    
                except Exception as e:
                    if self.running:
                        self.logger.debug(f"Capture error: {e}")
                        
        except Exception as e:
            self.logger.error(f"Capture worker failed: {e}")
        finally:
            self.logger.info("Capture worker stopped")

    def _process_packet(self, packet_info: tuple) -> None:
        """Consumer worker: process individual packets"""
        try:
            header, packet_data, timestamp = packet_info
            
            # PCAP writing (if needed)
            if self.mode in [MonitorMode.PCAP_ONLY, MonitorMode.MIXED] and self.pcap_dumper:
                try:
                    self.pcap_dumper.dump(header, packet_data)
                    self.pcap_file_size += len(packet_data)
                except Exception as e:
                    self.logger.debug(f"PCAP write error: {e}")
            
            # Skip DNS parsing for PCAP_ONLY mode
            if self.mode == MonitorMode.PCAP_ONLY:
                return
            
            # DNS packet parsing and handling
            dns_packet = self.analyzer.analyze_packet(timestamp, packet_data)
            if dns_packet:
                self.dns_packet_count += 1
                self._handle_dns_packet(dns_packet)
                
        except Exception as e:
            self.logger.debug(f"Packet processing error: {e}")
    
    def _handle_dns_packet(self, packet: DNSPacket) -> None:
        """Handle DNS packet with thread-safe callbacks"""
        try:
            # Display mode handling
            if self.mode in [MonitorMode.DISPLAY_ONLY, MonitorMode.MIXED]:
                if self.display_callback:
                    self.display_callback(str(packet))
                else:
                    # Default to console output (thread-safe)
                    print(packet)
            
            # Resolver mode handling
            if self.mode in [MonitorMode.RESOLVER_ONLY, MonitorMode.MIXED]:
                if self.packet_callback:
                    self.packet_callback(packet)
                    
        except Exception as e:
            self.logger.debug(f"Packet handling error: {e}")
    
    def _check_pcap_rotation(self) -> None:
        """check pcap file rotation"""
        if not self.current_pcap_file or not self.pcap_start_time:
            return
        
        current_time = time.time()
        need_rotation = False
        
        # time rotation check
        if current_time - self.pcap_start_time >= self.config.pcap_rotation_time:
            self.logger.info("PCAP rotation triggered by time limit")
            need_rotation = True
        
        # size rotation check
        try:
            if os.path.exists(self.current_pcap_file):
                file_size = os.path.getsize(self.current_pcap_file)
                if file_size >= self.config.pcap_rotation_size * 1024 * 1024:  # MB to bytes
                    self.logger.info("PCAP rotation triggered by size limit")
                    need_rotation = True
        except Exception:
            pass
        
        if need_rotation:
            self._rotate_pcap_file()
    
    def _rotate_pcap_file(self) -> None:
        """rotate pcap file"""
        try:
            # close current dumper
            if self.pcap_dumper:
                if hasattr(self.pcap_dumper, 'close'):
                    self.pcap_dumper.close()
                self.pcap_dumper = None
            
            # new pcap file
            self._init_pcap_writer()
            
        except Exception as e:
            self.logger.error(f"PCAP rotation failed: {e}")
    
    def get_stats(self) -> dict:
        """Get comprehensive monitoring statistics"""
        if not self.start_time:
            return {}
        
        duration = time.time() - self.start_time
        pps = self.packet_count / duration if duration > 0 else 0
        dns_pps = self.dns_packet_count / duration if duration > 0 else 0
        
        # Queue statistics
        queue_size = self.packet_queue.qsize() if self.packet_queue else 0
        queue_utilization = (queue_size / self.packet_queue.maxsize * 100) if self.packet_queue else 0
        
        # Worker thread statistics
        active_workers = 0
        if self.worker_executor and hasattr(self.worker_executor, '_threads'):
            active_workers = len(self.worker_executor._threads)
        
        return {
            'duration': duration,
            'total_packets': self.packet_count,
            'dns_packets': self.dns_packet_count,
            'packets_per_second': pps,
            'dns_packets_per_second': dns_pps,
            'dropped_packets': self.dropped_packets,
            'drop_rate': (self.dropped_packets / max(1, self.packet_count)) * 100,
            'queue_size': queue_size,
            'queue_utilization': queue_utilization,
            'active_workers': active_workers,
            'max_workers': self.num_workers,
            'mode': self.mode.value,
            'pcap_file_size': getattr(self, 'pcap_file_size', 0),
            'pcap_file_count': getattr(self, 'pcap_file_count', 0)
        }


# factory function

def create_pcap_monitor(config: TrafficConfig) -> OptimizedTrafficMonitor:
    """pcap-write monitor"""
    return OptimizedTrafficMonitor(config, MonitorMode.PCAP_ONLY)


def create_display_monitor(config: TrafficConfig, 
                         display_callback: Optional[Callable[[str], None]] = None) -> OptimizedTrafficMonitor:
    """display monitor"""
    monitor = OptimizedTrafficMonitor(config, MonitorMode.DISPLAY_ONLY)
    if display_callback:
        monitor.set_display_callback(display_callback)
    return monitor


def create_resolver_monitor(config: TrafficConfig, 
                          packet_callback: Callable[[DNSPacket], None]) -> OptimizedTrafficMonitor:
    """resolver monitor"""
    monitor = OptimizedTrafficMonitor(config, MonitorMode.RESOLVER_ONLY)
    monitor.set_packet_callback(packet_callback)
    return monitor


def create_mixed_monitor(config: TrafficConfig,
                        packet_callback: Optional[Callable[[DNSPacket], None]] = None,
                        display_callback: Optional[Callable[[str], None]] = None) -> OptimizedTrafficMonitor:
    """mixed monitor"""
    monitor = OptimizedTrafficMonitor(config, MonitorMode.MIXED)
    if packet_callback:
        monitor.set_packet_callback(packet_callback)
    if display_callback:
        monitor.set_display_callback(display_callback)
    return monitor