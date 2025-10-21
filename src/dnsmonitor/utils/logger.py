"""Logger utilities for DNS Monitor."""

import logging
import sys
import os
from typing import Dict, Optional, Union
from pathlib import Path

try:
    import colorlog
except ImportError:
    # If colorlog is not installed, we'll use a basic fallback
    colorlog = None
    
try:
    from .. import constants
except ImportError:
    # 如果相对导入失败，尝试绝对导入
    import sys
    import os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    import constants


def setup_logger(
    debug: bool = False, 
    module_levels: Optional[Dict[str, str]] = None,
    log_file: Optional[Union[str, Path]] = None,
    log_format: Optional[str] = None
):
    """
    Configures the root logger for the DNS Monitor application with colored output.
    
    Args:
        debug: If True, sets logging level to DEBUG, otherwise INFO
        module_levels: Dictionary mapping module names to log levels
        log_file: Optional file path to write logs to
        log_format: Custom log format string
    """
    logger = logging.getLogger()
    level = logging.DEBUG if debug else logging.INFO
    logger.setLevel(level)

    # Prevent duplicate handlers if this function is called multiple times
    if logger.handlers:
        # Even if handlers exist, still allow adjusting module levels dynamically
        _apply_module_levels(module_levels)
        return

    # Setup console handler
    _setup_console_handler(logger, log_format)
    
    # Setup file handler if specified
    if log_file:
        _setup_file_handler(logger, log_file, log_format)

    # Apply per-module levels from env or argument
    _apply_module_levels(module_levels)


def _setup_console_handler(logger: logging.Logger, log_format: Optional[str] = None):
    """Setup console handler with color support."""
    # Check if we should use colors
    # Respect NO_COLOR env var (https://no-color.org/)
    use_colors = sys.stdout.isatty() and colorlog and not os.environ.get("NO_COLOR")

    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(logging.NOTSET)

    if use_colors:
        # Define the format with color codes
        if log_format is None:
            log_format = '%(log_color)s[%(levelname).4s]%(reset)s %(cyan)s%(name)s%(reset)s: %(message)s'
        
        formatter = colorlog.ColoredFormatter(
            log_format,
            log_colors={
                'DEBUG': 'cyan',
                'INFO': 'green',
                'WARNING': 'yellow',
                'ERROR': 'red',
                'CRITICAL': 'red,bg_white',
            },
            reset=True,
            style='%'
        )
    else:
        # Basic formatter for non-color environments
        if log_format is None:
            log_format = '[%(levelname).4s] %(name)s: %(message)s'
        formatter = logging.Formatter(log_format)

    handler.setFormatter(formatter)
    logger.addHandler(handler)


def _setup_file_handler(logger: logging.Logger, log_file: Union[str, Path], log_format: Optional[str] = None):
    """Setup file handler for logging to file."""
    log_path = Path(log_file)
    
    # Create directory if it doesn't exist
    log_path.parent.mkdir(parents=True, exist_ok=True)
    
    handler = logging.FileHandler(log_path, encoding='utf-8')
    handler.setLevel(logging.NOTSET)
    
    if log_format is None:
        log_format = '%(asctime)s [%(levelname).4s] %(name)s: %(message)s'
    
    formatter = logging.Formatter(log_format, datefmt='%Y-%m-%d %H:%M:%S')
    handler.setFormatter(formatter)
    logger.addHandler(handler)


def _apply_module_levels(module_levels: Optional[Dict[str, str]]):
    """Apply per-module logger levels from mapping or env var DNSMON_LOG_LEVELS.

    module_levels format: {"dnsmonitor.traffic": "DEBUG", "dnsmonitor.cache": "INFO"}
    Env var example: DNSMON_LOG_LEVELS="traffic=DEBUG,cache=INFO"
    """
    # Parse from env if not provided
    if module_levels is None:
        env = os.environ.get("DNSMON_LOG_LEVELS")
        if env:
            module_levels = {}
            for pair in env.split(','):
                pair = pair.strip()
                if not pair:
                    continue
                if '=' not in pair:
                    continue
                name, lvl = pair.split('=', 1)
                module_levels[name.strip()] = lvl.strip().upper()

    if not module_levels:
        return

    for name, lvl_str in module_levels.items():
        try:
            norm_name = _normalize_module_name(name)
            lvl = getattr(logging, lvl_str.upper())
            logging.getLogger(norm_name).setLevel(lvl)
        except Exception:
            # Silently ignore invalid levels to avoid crashing
            continue


def _normalize_module_name(name: str) -> str:
    """Normalize provided module name with alias and auto-prefix.

    - If name is an alias, expand to full module path.
    - If name ends with '.*', treat it as base logger (strip the wildcard).
    - If name does not start with 'dnsmonitor.' and begins with a known top module, prefix 'dnsmonitor.'.
    """
    # Alias expansion
    if name in constants.LOG_ALIAS_MAP:
        return constants.LOG_ALIAS_MAP[name]
    # Wildcard base (e.g., 'traffic.*' => 'dnsmonitor.traffic')
    if name.endswith('.*'):
        name = name[:-2]
    # Auto-prefix for our modules
    if not name.startswith('dnsmonitor.'):
        first = name.split('.', 1)[0]
        if first in constants.KNOWN_TOP_MODULES:
            name = f'dnsmonitor.{name}'
    return name


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Get a logger instance for the given name.
    
    Args:
        name: Logger name, typically __name__ from the calling module
        
    Returns:
        Logger instance
    """
    return logging.getLogger(name)


def configure_performance_logging():
    """Configure performance-related logging settings."""
    # Disable some noisy third-party loggers by default
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)
    logging.getLogger('scapy').setLevel(logging.WARNING)
    

def log_system_info(logger: logging.Logger):
    """Log system information for debugging purposes."""
    import platform
    import psutil
    
    logger.info(f"System: {platform.system()} {platform.release()}")
    logger.info(f"Python: {platform.python_version()}")
    logger.info(f"CPU cores: {psutil.cpu_count()}")
    logger.info(f"Memory: {psutil.virtual_memory().total // (1024**3)} GB")


def create_structured_logger(name: str, extra_fields: Optional[Dict] = None) -> logging.Logger:
    """Create a logger with structured logging capabilities.
    
    Args:
        name: Logger name
        extra_fields: Additional fields to include in all log messages
        
    Returns:
        Logger with structured logging adapter
    """
    logger = get_logger(name)
    
    if extra_fields:
        return logging.LoggerAdapter(logger, extra_fields)
    
    return logger


class PerformanceLogger:
    """Context manager for performance logging."""
    
    def __init__(self, logger: logging.Logger, operation: str, level: int = logging.INFO):
        self.logger = logger
        self.operation = operation
        self.level = level
        self.start_time = None
    
    def __enter__(self):
        import time
        self.start_time = time.time()
        self.logger.log(self.level, f"Starting {self.operation}")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        import time
        duration = time.time() - self.start_time
        if exc_type is None:
            self.logger.log(self.level, f"Completed {self.operation} in {duration:.3f}s")
        else:
            self.logger.error(f"Failed {self.operation} after {duration:.3f}s: {exc_val}")


def setup_rotating_file_logger(
    name: str,
    log_file: Union[str, Path],
    max_bytes: int = 10 * 1024 * 1024,  # 10MB
    backup_count: int = 5,
    level: int = logging.INFO
) -> logging.Logger:
    """Setup a rotating file logger.
    
    Args:
        name: Logger name
        log_file: Path to log file
        max_bytes: Maximum file size before rotation
        backup_count: Number of backup files to keep
        level: Logging level
        
    Returns:
        Configured logger
    """
    from logging.handlers import RotatingFileHandler
    
    logger = get_logger(name)
    logger.setLevel(level)
    
    # Create directory if it doesn't exist
    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    
    handler = RotatingFileHandler(
        log_path,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding='utf-8'
    )
    
    formatter = logging.Formatter(
        '%(asctime)s [%(levelname).4s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    handler.setFormatter(formatter)
    
    logger.addHandler(handler)
    return logger