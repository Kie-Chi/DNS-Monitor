"""
DNS Monitor Utilities Package

This package contains utility functions and classes for DNS Monitor:
- colors: Terminal color output utilities
- common: Common utility functions
- logger: Logging system
"""

# Import color utilities for backward compatibility
from colors import (
    Colors,
    colorize,
    print_header,
    print_info,
    print_warning,
    print_error,
    print_success,
    PerformanceTimer,
    format_duration
)

# Import common utilities
from common import (
    ensure_directory,
    get_timestamp,
    get_file_size,
    rotate_file,
    format_bytes,
    save_json,
    load_json,
    validate_ip,
    validate_port
)

# Import logger utilities
from logger import (
    setup_logger,
    get_logger,
    PerformanceLogger,
    log_system_info
)

__all__ = [
    # Color utilities
    'Colors',
    'colorize',
    'print_header',
    'print_info',
    'print_warning',
    'print_error',
    'print_success',
    'PerformanceTimer',
    'format_duration',
    
    # Common utilities
    'ensure_directory',
    'get_timestamp',
    'get_file_size',
    'rotate_file',
    'format_bytes',
    'save_json',
    'load_json',
    'validate_ip',
    'validate_port',
    
    # Logger utilities
    'setup_logger',
    'get_logger',
    'PerformanceLogger',
    'log_system_info'
]