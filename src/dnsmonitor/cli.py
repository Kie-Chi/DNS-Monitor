"""
Command Line Interface for DNS Monitor
"""

import click
import sys
from typing import Optional

from .utils.common import get_iface
from .config import ConfigManager
from .monitor import DNSMonitor
from .traffic import OptimizedTrafficMonitor, MonitorMode
from .utils.logger import setup_logger, get_logger
from .utils import print_header, print_info, print_error, Colors


@click.group()
@click.option('--config', '-c', type=click.Path(exists=True), 
              help='Configuration file path')
@click.option('--log-level', '-l', type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR']),
              default='INFO', help='Log level')
@click.option('--log-file', type=click.Path(), help='Log file path')
@click.pass_context
def cli(ctx, config: Optional[str], log_level: str, log_file: Optional[str]):
    """DNS Monitor - Comprehensive DNS monitoring tool"""
    ctx.ensure_object(dict)
    
    # Setup logging
    setup_logger(
        debug=(log_level.upper() == 'DEBUG'),
        log_file=log_file
    )
    logger = get_logger(__name__)
    ctx.obj['logger'] = logger
    
    # Load configuration
    try:
        config_manager = ConfigManager(config)
        ctx.obj['config_manager'] = config_manager
        ctx.obj['config'] = config_manager.get_config()
        # override log level if provided
        ctx.obj['config'].log_level = log_level
        ctx.obj['config'].log_file = log_file if log_file else None
    except Exception as e:
        print_error(f"Failed to load configuration: {e}")
        sys.exit(1)


@cli.command()
@click.option('--interface', '-i', help='Network interface to monitor')
@click.option('--client-ip', help='Client IP address to monitor')
@click.option('--resolver-ip', help='Resolver IP address to monitor')
@click.option('--cache-software', type=click.Choice(['bind', 'unbound']),
              help='DNS cache software type')
@click.option('--output-dir', '-o', help='Output directory for results')
@click.pass_context
def monitor(ctx, interface: Optional[str], client_ip: Optional[str], resolver_ip: Optional[str], cache_software: Optional[str], output_dir: Optional[str]):
    """Start comprehensive DNS monitoring"""
    config = ctx.obj['config']
    logger = ctx.obj['logger']
    
    # Override config with command line options
    if interface:
        config.traffic.interface = interface
    if client_ip:
        config.resolver.client_ip = client_ip
    if resolver_ip:
        config.resolver.resolver_ip = resolver_ip
    if cache_software:
        config.cache.server_type = cache_software
        config.cache.software = cache_software
    if output_dir:
        config.output_dir = output_dir
    
    print_header("DNS Monitor Starting")
    print_info(f"Interface: {config.traffic.interface}")
    print_info(f"Client IP: {config.resolver.client_ip}")
    print_info(f"Resolver IP: {config.resolver.resolver_ip}")
    print_info(f"Cache Software: {config.cache.software}")
    print_info(f"Output Directory: {config.output_dir}")
    
    try:
        monitor = DNSMonitor(config)
        monitor.start()
    except KeyboardInterrupt:
        print_info("Monitoring stopped by user")
    except Exception as e:
        print_error(f"Monitoring failed: {e}")
        logger.exception("Monitoring error")
        sys.exit(1)


@cli.command()
@click.option("--cidr", "-c", help="CIDR range to monitor")
@click.option('--interface', '-i', help='Network interface to monitor')
@click.option('--output-dir', '-o', help='Output directory for PCAP files')
@click.option('--rotation-size', '-rz', type=int, help='PCAP rotation size in MB')
@click.option('--rotation-time', '-rt', type=int, help='PCAP rotation time in seconds')
@click.option('--bpf-filter', '-f', help='BPF filter expression')
@click.option(
    '--mode', '-m',
    type=click.Choice([str(m) for m in MonitorMode]), 
    help='Monitoring mode'
)
@click.pass_context
def traffic(ctx, cidr: Optional[str], interface: Optional[str], output_dir: Optional[str], rotation_size: Optional[int], rotation_time: Optional[int], bpf_filter: Optional[str], mode: Optional[str]):
    """Monitor DNS traffic only"""
    config = ctx.obj['config']
    logger = ctx.obj['logger']
    if cidr:
        config.traffic.interface = get_iface(cidr)
        if not config.traffic.interface:
            print_error(f"Failed to find interface for CIDR {cidr}")
            sys.exit(1)
    # Override config with command line options
    if interface:
        config.traffic.interface = interface
    if output_dir:
        config.traffic.pcap_dir = output_dir
    if rotation_size:
        config.traffic.pcap_rotation_size = rotation_size
    if rotation_time:
        config.traffic.pcap_rotation_time = rotation_time
    if bpf_filter:
        config.traffic.bpf_filter = bpf_filter
    if not mode:
        mode = str(MonitorMode.DISPLAY_ONLY)

    print_header("DNS Traffic Monitor Starting")
    print_info(f"Interface: {config.traffic.interface}")
    print_info(f"Output Directory: {config.traffic.pcap_dir}")
    print_info(f"Rotation Size: {config.traffic.pcap_rotation_size} MB")
    print_info(f"Rotation Time: {config.traffic.pcap_rotation_time} seconds")
    print_info(f"Mode: {mode}")
    
    try:
        monitor_mode = MonitorMode(mode)
        monitor = OptimizedTrafficMonitor(config.traffic, mode=monitor_mode)
        monitor.start()
    except KeyboardInterrupt:
        print_info("Traffic monitoring stopped by user")
    except Exception as e:
        print_error(f"Traffic monitoring failed: {e}")
        logger.exception("Traffic monitoring error")
        sys.exit(1)


@cli.command()
@click.option("--cidr", "-cr", help="CIDR range to monitor")
@click.option('--client-ip', '-c', required=True, help='Client IP address')
@click.option('--resolver-ip', '-r', required=True, help='Resolver IP address')
@click.option('--output', '-o', help='Output file path')
@click.option('--enable-server', '-s', is_flag=True, help='Enable server monitoring')
@click.option('--analysis-port', '-p', type=int, help='Analysis server port')
@click.option('--timeout', '-t', type=int, help='Query timeout in seconds')
@click.pass_context
def resolv(ctx, cidr: Optional[str], client_ip: str, resolver_ip: str, output: Optional[str], enable_server: bool, analysis_port: Optional[int], timeout: Optional[int]):  
    """Monitor DNS resolution path"""
    config = ctx.obj['config']
    logger = ctx.obj['logger']
    
    config.resolver.client_ip = client_ip
    config.resolver.resolver_ip = resolver_ip
    if timeout:
        config.resolver.timeout = timeout
    if output:
        config.resolver.output_path = output
    if enable_server:
        config.resolver.enable_server = enable_server
        if analysis_port:
            config.resolver.analysis_port = analysis_port
    if cidr:
        config.resolver.interface = get_iface(cidr)
        if not config.resolver.interface:
            print_error(f"Failed to find interface for CIDR {cidr}")
            sys.exit(1)
    
    print_header("DNS Resolver Monitor Starting")
    print_info(f"Client IP: {config.resolver.client_ip}")
    print_info(f"Resolver IP: {config.resolver.resolver_ip}")
    print_info(f"Timeout: {config.resolver.timeout} seconds")
    
    try:
        from .resolver import ResolverMonitor
        monitor = ResolverMonitor(config.resolver)
        monitor.start()
    except KeyboardInterrupt:
        print_info("Resolver monitoring stopped by user")
    except Exception as e:
        print_error(f"Resolver monitoring failed: {e}")
        logger.exception("Resolver monitoring error")
        sys.exit(1)


@cli.command()
@click.option('--software', type=click.Choice(['bind', 'unbound']),
              required=True, help='DNS cache software type')
@click.option('--host', help='Cache server host')
@click.option('--port', type=int, help='Cache server port')
@click.option('--interval', type=int, help='Cache monitor interval seconds')
@click.pass_context
def cache(ctx, software: str, host: Optional[str], port: Optional[int], interval: Optional[int]):
    """Monitor DNS cache changes"""
    config = ctx.obj['config']
    logger = ctx.obj['logger']
    
    config.cache.server_type = software
    config.cache.software = software
    if host:
        config.cache.host = host
    if port:
        config.cache.port = port
    if interval:
        config.cache.interval = interval
    
    print_header("DNS Cache Monitor Starting")
    print_info(f"Software: {config.cache.software}")
    print_info(f"Host: {config.cache.host}")
    print_info(f"Port: {config.cache.port}")
    print_info(f"Interval: {config.cache.interval}s")
    
    try:
        from .cache import CacheMonitor
        monitor = CacheMonitor(config.cache)
        monitor.start()
    except KeyboardInterrupt:
        print_info("Cache monitoring stopped by user")
    except Exception as e:
        print_error(f"Cache monitoring failed: {e}")
        logger.exception("Cache monitoring error")
        sys.exit(1)


@cli.command()
@click.option('--output', '-o', type=click.Path(), 
              default='dnsmonitor_config.yaml',
              help='Output configuration file path')
@click.pass_context
def generate_config(ctx, output: str):
    """Generate sample configuration file"""
    config_manager = ctx.obj['config_manager']
    
    try:
        config_manager.save_to_file(output)
        print_info(f"Configuration file generated: {output}")
    except Exception as e:
        print_error(f"Failed to generate configuration: {e}")
        sys.exit(1)


@cli.command()
@click.pass_context
def version(ctx):
    """Show version information"""
    from . import __version__
    print(f"{Colors.BOLD}DNS Monitor{Colors.RESET} version {Colors.GREEN}{__version__}{Colors.RESET}")


def main():
    """Main entry point"""
    cli()


if __name__ == '__main__':
    main()