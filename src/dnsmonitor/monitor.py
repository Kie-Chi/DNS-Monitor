"""
Main DNS Monitor - Integrates traffic, resolver path, and cache monitoring
"""

import time
import threading
import signal
from typing import Optional, Dict, Any
from datetime import datetime

from config import MonitorConfig
from traffic import TrafficMonitor
from resolver import ResolverMonitor
from cache import CacheMonitor
from utils.logger import setup_logger, get_logger, log_system_info, PerformanceLogger
from utils import Colors, colorize


class DNSMonitor:
    """Main DNS monitoring system integrating all monitoring components"""
    
    def __init__(self, config: MonitorConfig):
        self.config = config
        
        # Setup logging first
        setup_logger(
            debug=(config.log_level.upper() == 'DEBUG'),
            log_file=config.log_file
        )
        self.logger = get_logger(__name__)
        
        # Log system information
        log_system_info(self.logger)
        
        # Monitoring components
        self.traffic_monitor: Optional[TrafficMonitor] = None
        self.resolver_monitor: Optional[ResolverMonitor] = None
        self.cache_monitor: Optional[CacheMonitor] = None
        
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
            # Initialize traffic monitor
            if self.config.enable_traffic_monitoring:
                self.traffic_monitor = TrafficMonitor(
                    self.config.traffic_config,
                    self.logger.getChild('traffic')
                )
                self.stats['components_active'].append('traffic')
                self.logger.info("Traffic monitoring component initialized")
            
            # Initialize resolver monitor
            if self.config.enable_resolver_monitoring:
                self.resolver_monitor = ResolverMonitor(
                    self.config.resolver_config,
                    self.logger.getChild('resolver')
                )
                self.stats['components_active'].append('resolver')
                self.logger.info("Resolver path monitoring component initialized")
            
            # Initialize cache monitor
            if self.config.enable_cache_monitoring:
                self.cache_monitor = CacheMonitor(
                    self.config.cache_config,
                    self.logger.getChild('cache')
                )
                self.stats['components_active'].append('cache')
                self.logger.info("Cache monitoring component initialized")
            
            if not self.stats['components_active']:
                raise ValueError("No monitoring components enabled")
                
        except Exception as e:
            self.logger.error(f"Failed to initialize monitoring components: {e}")
            raise
    
    def start(self) -> None:
        """Start all monitoring components"""
        self.logger.info("Starting DNS monitoring system...")
        self.running = True
        self.start_time = time.time()
        self.stats['start_time'] = self.start_time
        
        try:
            self._print_startup_banner()
            
            # Start traffic monitoring
            if self.traffic_monitor:
                traffic_thread = threading.Thread(
                    target=self._run_traffic_monitor,
                    name="TrafficMonitor",
                    daemon=True
                )
                traffic_thread.start()
                self.monitor_threads.append(traffic_thread)
                self.logger.info("Traffic monitoring thread started")
            
            # Start resolver monitoring
            if self.resolver_monitor:
                resolver_thread = threading.Thread(
                    target=self._run_resolver_monitor,
                    name="ResolverMonitor",
                    daemon=True
                )
                resolver_thread.start()
                self.monitor_threads.append(resolver_thread)
                self.logger.info("Resolver monitoring thread started")
            
            # Start cache monitoring
            if self.cache_monitor:
                cache_thread = threading.Thread(
                    target=self._run_cache_monitor,
                    name="CacheMonitor",
                    daemon=True
                )
                cache_thread.start()
                self.monitor_threads.append(cache_thread)
                self.logger.info("Cache monitoring thread started")
            
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
        self.logger.info("Stopping DNS monitoring system...")
        self.running = False
        
        # Stop individual components
        if self.traffic_monitor:
            try:
                self.traffic_monitor.stop()
            except Exception as e:
                self.logger.error(f"Error stopping traffic monitor: {e}")
        
        if self.resolver_monitor:
            try:
                self.resolver_monitor.stop()
            except Exception as e:
                self.logger.error(f"Error stopping resolver monitor: {e}")
        
        if self.cache_monitor:
            try:
                self.cache_monitor.stop()
            except Exception as e:
                self.logger.error(f"Error stopping cache monitor: {e}")
        
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
    
    def _run_traffic_monitor(self) -> None:
        """Run traffic monitor in separate thread"""
        try:
            self.traffic_monitor.start()
        except Exception as e:
            self.logger.error(f"Traffic monitor thread failed: {e}")
            self.stats['total_errors'] += 1
    
    def _run_resolver_monitor(self) -> None:
        """Run resolver monitor in separate thread"""
        try:
            self.resolver_monitor.start()
        except Exception as e:
            self.logger.error(f"Resolver monitor thread failed: {e}")
            self.stats['total_errors'] += 1
    
    def _run_cache_monitor(self) -> None:
        """Run cache monitor in separate thread"""
        try:
            self.cache_monitor.start()
        except Exception as e:
            self.logger.error(f"Cache monitor thread failed: {e}")
            self.stats['total_errors'] += 1
    
    def _main_loop(self) -> None:
        """Main monitoring loop for status updates and health checks"""
        last_status_time = time.time()
        last_health_check = time.time()
        
        while self.running:
            try:
                current_time = time.time()
                
                # Print status update every 5 minutes
                if current_time - last_status_time >= 300:
                    self._print_status_update()
                    last_status_time = current_time
                
                # Health check every minute
                if current_time - last_health_check >= 60:
                    self._health_check()
                    last_health_check = current_time
                
                time.sleep(10)  # Check every 10 seconds
                
            except Exception as e:
                self.logger.error(f"Error in main loop: {e}")
                self.stats['total_errors'] += 1
                time.sleep(10)
    
    def _health_check(self) -> None:
        """Perform health check on all components"""
        try:
            issues = []
            
            # Check if threads are still alive
            for thread in self.monitor_threads:
                if not thread.is_alive():
                    issues.append(f"{thread.name} thread has died")
            
            # Log any issues found
            if issues:
                for issue in issues:
                    self.logger.warning(f"Health check issue: {issue}")
                self.stats['total_errors'] += len(issues)
            else:
                self.logger.debug("Health check passed - all components running")
                
        except Exception as e:
            self.logger.error(f"Health check failed: {e}")
    
    def _print_startup_banner(self) -> None:
        """Print startup banner with configuration info"""
        print(f"\n{Colors.BOLD}{Colors.CYAN}DNS Monitor v1.0{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"Start time: {colorize(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), Colors.GREEN)}")
        print(f"Log level: {colorize(self.config.log_level.upper(), Colors.YELLOW)}")
        
        if self.config.log_file:
            print(f"Log file: {colorize(self.config.log_file, Colors.YELLOW)}")
        
        print(f"\n{Colors.BOLD}Active Components:{Colors.RESET}")
        
        if self.traffic_monitor:
            print(f"  {colorize('✓', Colors.GREEN)} Traffic Monitor")
            print(f"    - Interface: {self.config.traffic_config.interface}")
            print(f"    - Output: {self.config.traffic_config.output_dir}")
        
        if self.resolver_monitor:
            print(f"  {colorize('✓', Colors.GREEN)} Resolver Path Monitor")
            print(f"    - Client: {self.config.resolver_config.client_ip}")
            print(f"    - Resolver: {self.config.resolver_config.resolver_ip}")
        
        if self.cache_monitor:
            print(f"  {colorize('✓', Colors.GREEN)} Cache Monitor")
            print(f"    - Server: {self.config.cache_config.server_type}")
            print(f"    - Interval: {self.config.cache_config.interval}s")
        
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}\n")
    
    def _print_status_update(self) -> None:
        """Print periodic status update"""
        uptime = time.time() - self.start_time if self.start_time else 0
        uptime_str = self._format_duration(uptime)
        
        print(f"\n{Colors.BOLD}Status Update{Colors.RESET}")
        print(f"Uptime: {colorize(uptime_str, Colors.GREEN)}")
        print(f"Active components: {colorize(str(len(self.stats['components_active'])), Colors.CYAN)}")
        print(f"Total errors: {colorize(str(self.stats['total_errors']), Colors.RED if self.stats['total_errors'] > 0 else Colors.GREEN)}")
        
        # Component-specific statistics
        if self.traffic_monitor and hasattr(self.traffic_monitor, 'stats'):
            stats = self.traffic_monitor.stats
            print(f"Traffic: {colorize(str(stats['total_packets']), Colors.YELLOW)} packets, "
                  f"{colorize(str(stats['dns_packets']), Colors.YELLOW)} DNS")
        
        if self.resolver_monitor and hasattr(self.resolver_monitor, 'stats'):
            stats = self.resolver_monitor.stats
            print(f"Resolver: {colorize(str(stats['total_queries']), Colors.YELLOW)} queries, "
                  f"{colorize(str(stats['completed_transactions']), Colors.GREEN)} completed")
        
        if self.cache_monitor and hasattr(self.cache_monitor, 'stats'):
            stats = self.cache_monitor.stats
            print(f"Cache: {colorize(str(stats['total_snapshots']), Colors.YELLOW)} snapshots, "
                  f"{colorize(str(stats['total_changes']), Colors.MAGENTA)} changes")
    
    def _print_final_statistics(self) -> None:
        """Print final statistics on shutdown"""
        print(f"\n{Colors.BOLD}{Colors.CYAN}Final Statistics{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*50}{Colors.RESET}")
        
        if self.start_time:
            uptime_str = self._format_duration(self.stats['uptime'])
            print(f"Total uptime: {colorize(uptime_str, Colors.GREEN)}")
        
        print(f"Components run: {colorize(', '.join(self.stats['components_active']), Colors.CYAN)}")
        print(f"Total errors: {colorize(str(self.stats['total_errors']), Colors.RED if self.stats['total_errors'] > 0 else Colors.GREEN)}")
        
        # Detailed component statistics
        if self.traffic_monitor and hasattr(self.traffic_monitor, 'stats'):
            stats = self.traffic_monitor.stats
            print(f"\n{Colors.BOLD}Traffic Monitor:{Colors.RESET}")
            print(f"  Total packets: {colorize(str(stats['total_packets']), Colors.YELLOW)}")
            print(f"  DNS packets: {colorize(str(stats['dns_packets']), Colors.YELLOW)}")
            print(f"  Query types: {colorize(str(len(stats['query_types'])), Colors.CYAN)}")
        
        if self.resolver_monitor and hasattr(self.resolver_monitor, 'stats'):
            stats = self.resolver_monitor.stats
            print(f"\n{Colors.BOLD}Resolver Monitor:{Colors.RESET}")
            print(f"  Total queries: {colorize(str(stats['total_queries']), Colors.YELLOW)}")
            print(f"  Completed: {colorize(str(stats['completed_transactions']), Colors.GREEN)}")
            print(f"  Timeouts: {colorize(str(stats['timeout_transactions']), Colors.RED)}")
            if stats['average_resolution_time'] > 0:
                avg_time = stats['average_resolution_time']
                print(f"  Avg resolution time: {colorize(f'{avg_time:.3f}s', Colors.MAGENTA)}")
        
        if self.cache_monitor and hasattr(self.cache_monitor, 'stats'):
            stats = self.cache_monitor.stats
            print(f"\n{Colors.BOLD}Cache Monitor:{Colors.RESET}")
            print(f"  Snapshots taken: {colorize(str(stats['total_snapshots']), Colors.YELLOW)}")
            print(f"  Changes detected: {colorize(str(stats['total_changes']), Colors.MAGENTA)}")
            print(f"  Records added: {colorize(str(stats['records_added']), Colors.GREEN)}")
            print(f"  Records removed: {colorize(str(stats['records_removed']), Colors.RED)}")
        
        print(f"{Colors.CYAN}{'='*50}{Colors.RESET}\n")
    
    def _format_duration(self, seconds: float) -> str:
        """Format duration in human-readable format"""
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            return f"{seconds/60:.1f}m"
        else:
            hours = int(seconds // 3600)
            minutes = int((seconds % 3600) // 60)
            return f"{hours}h {minutes}m"
    
    def get_status(self) -> Dict[str, Any]:
        """Get current monitoring status"""
        status = {
            'running': self.running,
            'uptime': time.time() - self.start_time if self.start_time else 0,
            'components': {},
            'statistics': self.stats.copy()
        }
        
        # Add component-specific status
        if self.traffic_monitor:
            status['components']['traffic'] = {
                'active': hasattr(self.traffic_monitor, 'running') and self.traffic_monitor.running,
                'stats': getattr(self.traffic_monitor, 'stats', {})
            }
        
        if self.resolver_monitor:
            status['components']['resolver'] = {
                'active': hasattr(self.resolver_monitor, 'running') and self.resolver_monitor.running,
                'stats': getattr(self.resolver_monitor, 'stats', {})
            }
        
        if self.cache_monitor:
            status['components']['cache'] = {
                'active': hasattr(self.cache_monitor, 'running') and self.cache_monitor.running,
                'stats': getattr(self.cache_monitor, 'stats', {})
            }
        
        return status