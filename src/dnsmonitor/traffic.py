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
    PCAP_ONLY = "pcap_only"
    DISPLAY_ONLY = "display_only"
    RESOLVER_ONLY = "resolver_only"
    MIXED = "mixed"

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
        self.running = threading.Event()
        self.capture_thread = None
        self.pcap_writer_thread = None
        self.worker_executor = None
        
        # Queues for decoupling threads
        self.packet_queue = queue.Queue(maxsize=config.buffer_size // 1024)
        self.pcap_write_queue = queue.Queue(maxsize=config.buffer_size // 1024)
        
        # Thread-safe statistics
        self.stats_lock = threading.Lock()
        self.packet_count = 0
        self.dns_packet_count = 0
        self.start_time = None
        self.dropped_packets = 0
        
        # Callbacks
        self.packet_callback = None
        self.display_callback = None
        
        # PCAP rotation (managed by writer thread)
        self.current_pcap_file = None
        self.pcap_file_size = 0
        self.pcap_file_count = 0
        self.pcap_start_time = None
        
        # Worker thread configuration
        self.num_workers = min(4, (os.cpu_count() or 1) + 1)
        
        if self.mode in [MonitorMode.PCAP_ONLY, MonitorMode.MIXED]:
            ensure_directory(self.config.pcap_dir)
        
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def set_packet_callback(self, callback: Callable[[DNSPacket], None]) -> None:
        self.packet_callback = callback
    
    def set_display_callback(self, callback: Callable[[str], None]) -> None:
        self.display_callback = callback
    
    def start(self) -> None:
        self.logger.info(f"Starting DNS traffic monitoring in {self.mode.value} mode...")
        if self.running.is_set():
            self.logger.warning("Monitor is already running.")
            return

        self.running.set()
        self.start_time = time.time()
        
        try:
            self._init_capture()
            
            # Start dedicated PCAP writer thread if needed
            if self.mode in [MonitorMode.PCAP_ONLY, MonitorMode.MIXED]:
                self._init_pcap_writer()
                self.pcap_writer_thread = threading.Thread(target=self._pcap_writer_worker, daemon=True)
                self.pcap_writer_thread.start()
            
            # Start worker thread pool for packet processing
            self.worker_executor = ThreadPoolExecutor(
                max_workers=self.num_workers,
                thread_name_prefix="dns_worker"
            )
            for _ in range(self.num_workers):
                self.worker_executor.submit(self._processing_worker)
            
            # Start capture thread (producer)
            self.capture_thread = threading.Thread(target=self._capture_worker, daemon=True)
            self.capture_thread.start()
            
            self.logger.info(f"Traffic monitoring started with {self.num_workers} worker threads")
            
        except Exception as e:
            self.logger.error(f"Failed to start traffic monitoring: {e}")
            self.stop()

    def stop(self) -> None:
        if not self.running.is_set():
            return
            
        self.logger.info("Stopping DNS traffic monitoring...")
        self.running.clear()
        
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=2)
        
        # Signal processing workers to stop by putting None in the queue
        if self.worker_executor:
            for _ in range(self.num_workers):
                try:
                    self.packet_queue.put_nowait(None)
                except queue.Full:
                    pass
            self.worker_executor.shutdown(wait=True)
            self.worker_executor = None

        # Signal pcap writer to stop
        if self.pcap_writer_thread and self.pcap_writer_thread.is_alive():
            try:
                self.pcap_write_queue.put_nowait(None)
            except queue.Full:
                pass
            self.pcap_writer_thread.join(timeout=2)
        
        self._close_pcap_resources()
        
        if self.start_time:
            duration = time.time() - self.start_time
            pps = self.packet_count / duration if duration > 0 else 0
            dns_pps = self.dns_packet_count / duration if duration > 0 else 0
            self.logger.info(f"Monitoring stopped. Processed {self.packet_count} packets "
                           f"({self.dns_packet_count} DNS) in {duration:.2f}s. "
                           f"Rate: {pps:.0f} pps ({dns_pps:.0f} DNS pps). "
                           f"Dropped: {self.dropped_packets}")
        
        self.logger.info("DNS traffic monitoring stopped")

    def _close_pcap_resources(self):
        """Safely close pcap dumper and handle."""
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

    def _signal_handler(self, signum, frame):
        self.logger.info(f"Received signal {signum}, stopping...")
        self.stop()

    def _init_capture(self) -> None:
        if not PCAPY_AVAILABLE:
            raise RuntimeError("pcapy is not available")
        try:
            self.pcap_handle = pcapy.open_live(
                self.config.interface, self.config.snaplen,
                self.config.enable_promiscuous, self.config.capture_timeout_ms
            )
            dns_filter = f"port {self.config.dns_port}"
            self.pcap_handle.setfilter(dns_filter)
            self.logger.info(f"Initialized capture on {self.config.interface} with filter: {dns_filter}")
        except Exception as e:
            raise RuntimeError(f"Failed to initialize packet capture: {e}")

    def _init_pcap_writer(self) -> None:
        try:
            timestamp = int(time.time())
            filename = f"dns_traffic_{timestamp}_{self.pcap_file_count}.pcap"
            self.current_pcap_file = os.path.join(self.config.pcap_dir, filename)
            
            if self.pcap_handle:
                self.pcap_dumper = self.pcap_handle.dump_open(self.current_pcap_file)
                self.pcap_start_time = time.time()
                self.pcap_file_size = 0
                self.pcap_file_count += 1
                self.logger.info(f"Started PCAP writing to: {self.current_pcap_file}")
            else:
                raise RuntimeError("PCAP handle not initialized")
        except Exception as e:
            raise RuntimeError(f"Failed to initialize PCAP writer: {e}")
    
    def _capture_worker(self) -> None:
        """Producer thread: captures packets and puts them into the processing queue."""
        self.logger.info("Started packet capture worker (producer)")
        while self.running.is_set():
            try:
                header, packet_data = self.pcap_handle.next()
                if header is None:
                    continue
                with self.stats_lock:
                    self.packet_count += 1
                try:
                    ts = header.getts()
                    timestamp = ts[0] + ts[1] * 1e-6
                except Exception:
                    timestamp = time.time()
                
                packet_info = (header, packet_data, timestamp)
                try:
                    self.packet_queue.put(packet_info, timeout=0.1)
                except queue.Full:
                    with self.stats_lock:
                        self.dropped_packets += 1
                    if self.dropped_packets % 1000 == 0:
                        self.logger.warning(f"Dropped {self.dropped_packets} packets due to queue overflow")
            
            except pcapy.PcapError as e:
                # This can happen on timeout in open_live, which is normal
                if "timed out" not in str(e):
                    self.logger.debug(f"Capture error: {e}")
            except Exception as e:
                if self.running.is_set():
                    self.logger.error(f"Capture worker failed: {e}")
                    self.running.clear() # Stop everything on critical error
        self.logger.info("Capture worker stopped")

    def _processing_worker(self) -> None:
        """Consumer worker: pulls packets from queue and processes them."""
        while self.running.is_set():
            try:
                packet_info = self.packet_queue.get(timeout=1)
                if packet_info is None: # Sentinel value to stop
                    break
                
                self._parse_packet(packet_info)

            except queue.Empty:
                continue # Normal timeout, check running flag and loop again
            except Exception as e:
                self.logger.error(f"Processing worker error: {e}")
                
    def _parse_packet(self, packet_info: tuple) -> None:
        """The actual packet processing logic"""
        try:
            header, packet_data, timestamp = packet_info
            if self.mode in [MonitorMode.PCAP_ONLY, MonitorMode.MIXED]:
                try:
                    self.pcap_write_queue.put_nowait((header, packet_data))
                except queue.Full:
                    pass
            if self.mode == MonitorMode.PCAP_ONLY:
                return
            
            dns_packet = self.analyzer.analyze_packet(timestamp, packet_data)
            if dns_packet:
                with self.stats_lock:
                    self.dns_packet_count += 1
                self._handle_dns_packet(dns_packet)
                
        except Exception as e:
            self.logger.debug(f"Packet processing error: {e}")
    
    def _pcap_writer_worker(self) -> None:
        """Dedicated thread to write packets to a PCAP file."""
        self.logger.info("Started PCAP writer worker")
        while self.running.is_set():
            try:
                packet_to_write = self.pcap_write_queue.get(timeout=1)
                if packet_to_write is None: # Sentinel to stop
                    break
                header, packet_data = packet_to_write
                if self.pcap_dumper:
                    self.pcap_dumper.dump(header, packet_data)
                    self.pcap_file_size += len(packet_data)
                    self._check_pcap_rotation()

            except queue.Empty:
                self._check_pcap_rotation()
                continue
            except Exception as e:
                self.logger.error(f"PCAP writer error: {e}")
        self.logger.info("PCAP writer worker stopped")

    def _handle_dns_packet(self, packet: DNSPacket) -> None:
        """Handle DNS packet with thread-safe callbacks."""
        try:
            if self.mode in [MonitorMode.DISPLAY_ONLY, MonitorMode.MIXED]:
                if self.display_callback:
                    self.display_callback(str(packet))
                else:
                    print(packet)
            
            if self.mode in [MonitorMode.RESOLVER_ONLY, MonitorMode.MIXED]:
                if self.packet_callback:
                    self.packet_callback(packet)
                    
        except Exception as e:
            self.logger.debug(f"Packet handling error: {e}")
    
    def _check_pcap_rotation(self) -> None:
        """Check and perform PCAP file rotation."""
        if not self.pcap_start_time:
            return
        
        time_expired = (time.time() - self.pcap_start_time) >= self.config.pcap_rotation_time
        size_exceeded = self.pcap_file_size >= self.config.pcap_rotation_size * 1024 * 1024

        if time_expired or size_exceeded:
            if time_expired: self.logger.info("PCAP rotation triggered by time limit")
            if size_exceeded: self.logger.info("PCAP rotation triggered by size limit")
            self._rotate_pcap_file()
    
    def _rotate_pcap_file(self) -> None:
        """Rotate pcap file. Called ONLY by the writer thread."""
        try:
            if self.pcap_dumper:
                if hasattr(self.pcap_dumper, 'close'):
                    self.pcap_dumper.close()
                self.pcap_dumper = None
            
            self._init_pcap_writer()
            
        except Exception as e:
            self.logger.error(f"PCAP rotation failed: {e}")
    
    def get_stats(self) -> dict:
        """Get comprehensive monitoring statistics in a thread-safe way."""
        if not self.start_time:
            return {}
        
        with self.stats_lock:
            packet_count = self.packet_count
            dns_packet_count = self.dns_packet_count
            dropped_packets = self.dropped_packets
        
        duration = time.time() - self.start_time
        pps = packet_count / duration if duration > 0 else 0
        dns_pps = dns_packet_count / duration if duration > 0 else 0
        
        queue_size = self.packet_queue.qsize()
        queue_utilization = (queue_size / self.packet_queue.maxsize * 100) if self.packet_queue.maxsize > 0 else 0
        
        return {
            'duration': duration, 'total_packets': packet_count, 'dns_packets': dns_packet_count,
            'packets_per_second': pps, 'dns_packets_per_second': dns_pps,
            'dropped_packets': dropped_packets, 'drop_rate': (dropped_packets / max(1, packet_count)) * 100,
            'queue_size': queue_size, 'queue_utilization': queue_utilization,
            'active_workers': self.num_workers, 'max_workers': self.num_workers, 'mode': self.mode.value,
            'pcap_file_size': self.pcap_file_size, 'pcap_file_count': self.pcap_file_count
        }

# (Factory functions remain unchanged)

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