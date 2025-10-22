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
@click.option('--interface', '-i', help='Network interface to monitor traffic on')
@click.option('--resolver-ip', '-r', required=True, help='IP address of the resolver whose cache is being monitored')
@click.option('--software', '-sw', type=click.Choice(['bind', 'unbound']), required=True, help='DNS server software type')
@click.option('--cooldown', '-c', type=float, help='Minimum seconds between cache dumps')
@click.option('--save-changes', '-s', is_flag=True, default=False, help='Save detailed cache diffs to JSON files')
@click.option('--enable-server', '-e', is_flag=True, help='Enable analysis server')
@click.option('--analysis-address', '-a', type=str, help='Analysis server address')
@click.option('--analysis-port', '-p', type=int, help='Analysis server port')
# BIND specific options
@click.option('--rndc-key-file', '-k', help='Path to rndc.key file (for BIND)')
@click.option('--dump-file', '-d', help='Path to the cache dump file (for BIND)')
# Unbound specific options
@click.option('--unbound-control-config', '-uc', help='Path to unbound-control config file (for Unbound)')
@click.pass_context
def cache(ctx, interface: Optional[str], resolver_ip: str, software: str, cooldown: Optional[float], save_changes: bool, enable_server: bool, analysis_address: Optional[str], analysis_port: Optional[int], rndc_key_file: Optional[str], dump_file: Optional[str], unbound_control_config: Optional[str]):
    """Monitor DNS cache changes, triggered by resolver traffic."""
    config = ctx.obj['config'].cache
    logger = ctx.obj['logger']
    
    # Common settings
    if interface: config.common.interface = interface
    config.common.resolver_ip = resolver_ip
    if cooldown: config.common.cooldown_period = cooldown
    config.common.save_changes = save_changes
    if enable_server: config.common.enable_analysis_server = True
    if analysis_address: config.common.analysis_address = analysis_address
    if analysis_port: config.common.analysis_port = analysis_port
    
    # Software-specific settings
    config.server_type = software
    if software == 'bind':
        if rndc_key_file: config.bind.rndc_key_file = rndc_key_file
        if dump_file: config.bind.dump_file = dump_file
    elif software == 'unbound':
        if unbound_control_config: config.unbound.control_config = unbound_control_config
    
    # --- Print startup info ---
    print_header("DNS Cache Monitor Starting (Event-Driven)")
    print_info(f"Monitoring Interface: {config.common.interface}")
    print_info(f"Target Resolver IP: {config.common.resolver_ip}")
    print_info(f"DNS Software: {config.server_type.upper()}")
    print_info(f"Cooldown Period: {config.common.cooldown_period}s")
    if save_changes: print_info("Saving cache changes: Enabled")
    if config.common.enable_analysis_server:
        print_info(f"Analysis Server: Enabled on port {config.common.analysis_port}")

    try:
        from .cache import CacheMonitor
        monitor_service = CacheMonitor(config)
        monitor_service.start()
    except KeyboardInterrupt:
        print_info("\nCache monitoring stopped by user.")
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