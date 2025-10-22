"""
Common utility functions for DNS Monitor
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any


def ensure_directory(path: Any) -> None:
    """Ensure directory exists, create if not"""
    if isinstance(path, str):
        path = Path(path)
    path.mkdir(parents=True, exist_ok=True)


def get_timestamp() -> str:
    """Get current timestamp as string"""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def get_file_size(file_path: Any) -> int:
    """Get file size in bytes"""
    if isinstance(file_path, str):
        file_path = Path(file_path)
    try:
        return file_path.stat().st_size
    except OSError:
        return 0


def rotate_file(file_path: Any, max_size: int) -> bool:
    """Rotate file if it exceeds max_size (in MB)"""
    if isinstance(file_path, str):
        file_path = Path(file_path)
    if not file_path.exists():
        return False
    
    size_mb = get_file_size(file_path) / (1024 * 1024)
    if size_mb >= max_size:
        timestamp = get_timestamp()
        rotated_path = file_path.with_suffix(f".{timestamp}{file_path.suffix}")
        file_path.rename(rotated_path)
        return True
    return False


def format_bytes(bytes_count: int) -> str:
    """Format bytes count to human readable string"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_count < 1024.0:
            return f"{bytes_count:.1f} {unit}"
        bytes_count /= 1024.0
    return f"{bytes_count:.1f} TB"


def save_json(data: Dict[Any, Any], file_path: Any) -> None:
    """Save data to JSON file"""
    if isinstance(file_path, str):
        file_path = Path(file_path)
    ensure_directory(file_path.parent)
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)


def load_json(file_path: Any) -> Optional[Dict[Any, Any]]:
    """Load data from JSON file"""
    if isinstance(file_path, str):
        file_path = Path(file_path)
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def validate_ip(ip: str) -> bool:
    """Validate IP address format"""
    import socket
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


def validate_port(port: int) -> bool:
    """Validate port number"""
    return 1 <= port <= 65535


# Import network utilities
from .network import get_iface, validate_cidr

__all__ = [
    'ensure_directory',
    'get_timestamp',
    'get_file_size',
    'rotate_file',
    'format_bytes',
    'save_json',
    'load_json',
    'validate_ip',
    'validate_port',
    'get_iface',
    'validate_cidr'
]