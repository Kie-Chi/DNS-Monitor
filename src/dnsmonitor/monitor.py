"""
Main DNS Monitor - Integrates traffic, resolver path, and cache monitoring
"""

import time
import threading
import multiprocessing # Use multiprocessing
import signal
import json
import socket
import socketserver
from typing import Optional, Dict, Any, List
from datetime import datetime

from .config import MonitorConfig
from .traffic import OptimizedTrafficMonitor as TrafficMonitor
from .resolver import ResolverMonitor
from .cache import CacheMonitor
from .utils.logger import setup_logger, get_logger, log_system_info
from .utils import Colors, colorize

# Helper function to run a monitor instance in a new process
def _process_worker(monitor_class, config):
    """
    Initializes and starts a monitor instance.
    """
    monitor = monitor_class(config)
    monitor.start()

class DNSMonitorServer(socketserver.ThreadingTCPServer):
    """Main aggregator server for DNSMonitor."""
    def __init__(self, server_address, RequestHandlerClass, monitor: 'DNSMonitor'):
        super().__init__(server_address, RequestHandlerClass)
        self.monitor = monitor
        self.allow_reuse_address = True

class DNSMonitorRequestHandler(socketserver.BaseRequestHandler):
    """Handles requests for aggregated data from child monitors."""
    def _query_child(self, address: str, port: int, command: str = "") -> Dict[str, Any]:
        """Helper to query a child monitor's analysis server."""
        try:
            with socket.create_connection((address, port), timeout=2) as s:
                if command:
                    s.sendall(command.encode('utf-8'))

                response_data = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    response_data += chunk
                return json.loads(response_data)
        except (socket.timeout, ConnectionRefusedError, json.JSONDecodeError) as e:
            return {"status": "error", "message": f"Failed to query child at {address}:{port}: {str(e)}"}
        except Exception as e:
            return {"status": "error", "message": f"An unexpected error occurred: {str(e)}"}

    def handle(self) -> None:
        monitor = self.server.monitor
        response = {}
        for name, config in monitor.cache_configs.items():
            if config.common.enable_analysis_server:
                addr = config.common.analysis_address
                port = config.common.analysis_port
                response[name] = self._query_child(addr, port)
        for name, config in monitor.resolver_configs.items():
            if config.enable_server:
                addr = config.analysis_address
                port = config.analysis_port
                response[name] = self._query_child(addr, port, command="-1")
        
        self.request.sendall(json.dumps(response, indent=2).encode('utf-8'))


class DNSMonitor:
    """Main DNS monitoring system integrating all monitoring components via processes."""
    
    def __init__(self, config: MonitorConfig):
        self.config = config
        
        setup_logger(
            debug=(config.log_level.upper() == 'DEBUG'),
            log_file=getattr(config, 'log_file', None)
        )
        self.logger = get_logger(__name__)
        
        log_system_info(self.logger)
        
        # Store configs and process objects
        self.traffic_monitor: Optional[TrafficMonitor] = None
        self.resolver_configs: Dict[str, Any] = {}
        self.cache_configs: Dict[str, Any] = {}
        self.monitor_processes: Dict[str, multiprocessing.Process] = {}
        # Aggregator Server
        self.server: Optional[DNSMonitorServer] = None
        self.running = False
        self.stats = {
            'start_time': None,
            'uptime': 0,
            'components_active': [],
            'total_errors': 0,
        }
        
        self._initialize_components()
        
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _initialize_components(self) -> None:
        """Initialize monitoring components based on configuration"""
        try:
            if self.config.traffic:
                self.traffic_monitor = TrafficMonitor(self.config.traffic)
                self.stats['components_active'].append('traffic')
                self.logger.info("Traffic monitoring component configured")
            
            for name, resolver_config in self.config.resolvers.items():
                self.resolver_configs[name] = resolver_config
                self.stats['components_active'].append(name)
                self.logger.info(f"Resolver monitor '{name}' for {resolver_config.client_ip} -> {resolver_config.resolver_ip} configured")
            
            for name, cache_config in self.config.caches.items():
                self.cache_configs[name] = cache_config
                self.stats['components_active'].append(name)
                self.logger.info(f"Cache monitor '{name}' for {cache_config.common.resolver_ip} configured")

            if not self.stats['components_active']:
                self.logger.warning("No monitoring components are configured or enabled.")
                
        except Exception as e:
            self.logger.error(f"Failed to initialize monitoring components: {e}")
            raise
    
    def start(self) -> None:
        if not self.stats['components_active']:
            self.logger.error("Cannot start: no monitoring components were initialized.")
            return
        if self.running:
            self.logger.warning("DNS monitoring system is already running.")
            return
        self.logger.info("Starting DNS monitoring system...")
        self.running = True
        self.start_time = time.time()
        self.stats['start_time'] = self.start_time
        
        try:
            self._startup()
            if self.traffic_monitor:
                thread = threading.Thread(
                    target=self.traffic_monitor.start,
                    name="TrafficMonitor",
                    daemon=True
                )
                thread.start()
                self.logger.info("Traffic monitoring thread started")

            # Start resolver monitors in separate processes
            for name, config in self.resolver_configs.items():
                process = multiprocessing.Process(
                    target=_process_worker,
                    args=(ResolverMonitor, config),
                    name=f"ResolverMonitor-{name}",
                    daemon=True
                )
                process.start()
                self.monitor_processes[name] = process
                self.logger.info(f"Resolver monitoring process '{name}' started (PID: {process.pid})")
            
            for name, config in self.cache_configs.items():
                process = multiprocessing.Process(
                    target=_process_worker,
                    args=(CacheMonitor, config),
                    name=f"CacheMonitor-{name}",
                    daemon=True
                )
                process.start()
                self.monitor_processes[name] = process
                self.logger.info(f"Cache monitoring process '{name}' started (PID: {process.pid})")
            
            if self.config.server.enable:
                addr = (self.config.server.address, self.config.server.port)
                self.server = DNSMonitorServer(addr, DNSMonitorRequestHandler, self)
                server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
                server_thread.start()
                self.logger.info(f"Main aggregator server started on {addr[0]}:{addr[1]}")

            self.logger.info("All monitoring components started successfully")
            
            self._main_loop()
            
        except KeyboardInterrupt:
            self.logger.info("Monitoring interrupted by user")
        except Exception as e:
            self.logger.error(f"Monitoring system failed: {e}")
            self.stats['total_errors'] += 1
        finally:
            self.stop()
    
    def stop(self) -> None:
        if not self.running:
            return
        self.logger.info("Stopping DNS monitoring system...")
        self.running = False
        
        if self.traffic_monitor:
            self.traffic_monitor.stop()
        
        if self.server:
            self.server.shutdown()
        
        # Terminate child processes
        for name, process in self.monitor_processes.items():
            if process.is_alive():
                self.logger.info(f"Terminating process '{name}' (PID: {process.pid})")
                process.terminate()
                process.join(timeout=3)
        
        if self.start_time:
            self.stats['uptime'] = time.time() - self.start_time
        
        self._final()
        self.logger.info("DNS monitoring system stopped")
    
    def _signal_handler(self, signum, frame):
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.stop()
    
    def _main_loop(self) -> None:
        """Main monitoring loop for health checks of child processes."""
        while self.running:
            time.sleep(3) # Check every 3 seconds
            for name, process in self.monitor_processes.items():
                if not process.is_alive():
                    self.logger.error(f"Process '{name}' (PID: {process.pid}) has stopped unexpectedly. Shutting down system.")
                    self.stop()
                    return
    
    def _startup(self) -> None:
        """Print startup banner with configuration info"""
        print(f"\n{Colors.BOLD}{Colors.CYAN}DNS Monitor v1.0{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"Start time: {colorize(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), Colors.GREEN)}")
        
        print(f"\n{Colors.BOLD}Active Components:{Colors.RESET}")
        if self.traffic_monitor:
            print(f"  {colorize('✓', Colors.GREEN)} Traffic Monitor: on interface {self.config.traffic.interface}")

        for name, monitor_config in self.resolver_configs.items():
            print(f"  {colorize('✓', Colors.GREEN)} [{name}] Resolver Monitor: Client {monitor_config.client_ip} -> Resolver {monitor_config.resolver_ip}")

        for name, monitor_config in self.cache_configs.items():
            print(f"  {colorize('✓', Colors.GREEN)} [{name}] Cache Monitor: Type {monitor_config.server_type.upper()} on Resolver {monitor_config.common.resolver_ip}")
        
        if self.config.server.enable:
            addr = f"{self.config.server.address}:{self.config.server.port}"
            print(f"  {colorize('✓', Colors.GREEN)} Aggregator Server listening on {addr}")

        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}\n")

    def _final(self):
        print(f"\n{Colors.BOLD}{Colors.CYAN}Final Statistics{Colors.RESET}")
        if self.start_time:
            uptime_str = self._format_duration(self.stats.get('uptime', 0))
            print(f"Total uptime: {colorize(uptime_str, Colors.GREEN)}")
    
    def _format_duration(self, seconds: float) -> str:
        """Format duration in human-readable format"""
        if seconds < 60: return f"{seconds:.1f}s"
        if seconds < 3600: return f"{seconds/60:.1f}m"
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours}h {minutes}m"