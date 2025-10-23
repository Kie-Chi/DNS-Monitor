"""
Main DNS Monitor - Integrates traffic, resolver path, and cache monitoring
"""

import time
import threading
import signal
from typing import Optional, Dict, Any, List
from datetime import datetime

from .config import MonitorConfig
from .traffic import OptimizedTrafficMonitor as TrafficMonitor
from .resolver import ResolverMonitor
from .cache import CacheMonitor
from .utils.logger import setup_logger, get_logger, log_system_info, PerformanceLogger
from .utils import Colors, colorize


class DNSMonitor:
    """Main DNS monitoring system integrating all monitoring components"""
    
    def __init__(self, config: MonitorConfig):
        self.config = config
        
        # Setup logging first
        setup_logger(
            debug=(config.log_level.upper() == 'DEBUG'),
            log_file=getattr(config, 'log_file', None)
        )
        self.logger = get_logger(__name__)
        
        # Log system information
        log_system_info(self.logger)
        
        # Monitoring components
        self.traffic_monitor: Optional[TrafficMonitor] = None
        self.resolver_monitors: List[ResolverMonitor] = []
        self.cache_monitors: List[CacheMonitor] = []
        
        # Control flags
        self.running = False
        self.monitor_threads = []
        
        # Statistics
        self.start_time = None
        self.stats = {
            'start_time': None,
            'uptime': 0,
            'components_active': [],
            'total_errors': 0,
        }
        
        # Initialize monitoring components based on configuration
        self._initialize_components()
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _initialize_components(self) -> None:
        """Initialize monitoring components based on configuration"""
        try:
            # Initialize traffic monitor (singular)
            if self.config.traffic:
                self.traffic_monitor = TrafficMonitor(self.config.traffic)
                self.stats['components_active'].append('traffic')
                self.logger.info("Traffic monitoring component initialized")
            
            # Initialize resolver monitors (multiple)
            for i, resolver_config in enumerate(self.config.resolvers):
                monitor_instance = ResolverMonitor(resolver_config)
                self.resolver_monitors.append(monitor_instance)
                self.stats['components_active'].append(f'resolver-{i}')
                self.logger.info(f"Resolver path monitor instance {i} for {resolver_config.resolver_ip} initialized")
            
            # Initialize cache monitors (multiple)
            for i, cache_config in enumerate(self.config.caches):
                monitor_instance = CacheMonitor(cache_config)
                self.cache_monitors.append(monitor_instance)
                self.stats['components_active'].append(f'cache-{i}')
                self.logger.info(f"Cache monitor instance {i} for {cache_config.common.resolver_ip} initialized")

            if not self.stats['components_active']:
                self.logger.warning("No monitoring components are configured or enabled.")
                
        except Exception as e:
            self.logger.error(f"Failed to initialize monitoring components: {e}")
            raise
    
    def start(self) -> None:
        """Start all monitoring components"""
        if not self.stats['components_active']:
            self.logger.error("Cannot start: no monitoring components were initialized.")
            return

        self.logger.info("Starting DNS monitoring system...")
        self.running = True
        self.start_time = time.time()
        self.stats['start_time'] = self.start_time
        
        try:
            self._print_startup_banner()
            
            # Start traffic monitoring
            if self.traffic_monitor:
                thread = threading.Thread(
                    target=self.traffic_monitor.start,
                    name="TrafficMonitor",
                    daemon=True
                )
                thread.start()
                self.monitor_threads.append(thread)
                self.logger.info("Traffic monitoring thread started")
            
            # Start resolver monitoring instances
            for i, monitor in enumerate(self.resolver_monitors):
                thread = threading.Thread(
                    target=monitor.start,
                    name=f"ResolverMonitor-{i}",
                    daemon=True
                )
                thread.start()
                self.monitor_threads.append(thread)
                self.logger.info(f"Resolver monitoring thread {i} started")
            
            # Start cache monitoring instances
            for i, monitor in enumerate(self.cache_monitors):
                thread = threading.Thread(
                    target=monitor.start,
                    name=f"CacheMonitor-{i}",
                    daemon=True
                )
                thread.start()
                self.monitor_threads.append(thread)
                self.logger.info(f"Cache monitoring thread {i} started")
            
            self.logger.info("All monitoring components started successfully")
            
            # Main monitoring loop
            self._main_loop()
            
        except KeyboardInterrupt:
            self.logger.info("Monitoring interrupted by user")
        except Exception as e:
            self.logger.error(f"Monitoring system failed: {e}")
            self.stats['total_errors'] += 1
        finally:
            self.stop()
    
    def stop(self) -> None:
        """Stop all monitoring components"""
        if not self.running:
            return
        self.logger.info("Stopping DNS monitoring system...")
        self.running = False
        
        # Stop individual components
        if self.traffic_monitor:
            self.traffic_monitor.stop()
        
        for monitor in self.resolver_monitors:
            monitor.stop()

        for monitor in self.cache_monitors:
            monitor.stop()
        
        # Wait for threads to finish
        for thread in self.monitor_threads:
            if thread.is_alive():
                thread.join(timeout=5)
        
        # Calculate final statistics
        if self.start_time:
            self.stats['uptime'] = time.time() - self.start_time
        
        self._print_final_statistics()
        self.logger.info("DNS monitoring system stopped")
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.stop()
    
    # _run_* methods are no longer needed as target is now component.start
    
    def _main_loop(self) -> None:
        """Main monitoring loop for status updates and health checks"""
        while self.running:
            # Join threads to keep the main thread alive until they finish or are interrupted
            for t in self.monitor_threads:
                t.join(timeout=1.0)
            
            # Check if any threads have unexpectedly died
            is_any_thread_dead = any(not t.is_alive() for t in self.monitor_threads)
            if self.running and is_any_thread_dead:
                self.logger.error("One or more monitoring threads have stopped unexpectedly. Shutting down.")
                self.stop()
                break
    
    def _health_check(self) -> None:
        """Perform health check on all components"""
        pass # Simplified, as the main loop now checks thread liveness
    
    def _print_startup_banner(self) -> None:
        """Print startup banner with configuration info"""
        print(f"\n{Colors.BOLD}{Colors.CYAN}DNS Monitor v1.0{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"Start time: {colorize(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), Colors.GREEN)}")
        
        print(f"\n{Colors.BOLD}Active Components:{Colors.RESET}")
        if self.traffic_monitor:
            print(f"  {colorize('✓', Colors.GREEN)} Traffic Monitor: on interface {self.config.traffic.interface}")

        for i, monitor_config in enumerate(self.config.resolvers):
            print(f"  {colorize('✓', Colors.GREEN)} Resolver Path Monitor [{i}]: Client {monitor_config.client_ip} -> Resolver {monitor_config.resolver_ip}")

        for i, monitor_config in enumerate(self.config.caches):
            print(f"  {colorize('✓', Colors.GREEN)} Cache Monitor [{i}]: Type {monitor_config.server_type.upper()} on Resolver {monitor_config.common.resolver_ip}")
        
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}\n")

    # _print_status_update and _print_final_statistics can be updated to iterate over monitor lists
    # for more detailed stats, but are omitted here for brevity.
    def _print_final_statistics(self):
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