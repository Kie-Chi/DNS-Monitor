"""
Common utility functions for DNS Monitor
"""

import os
import json
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any


def ensure_directory(path: str) -> None:
    """Ensure directory exists, create if not"""
    Path(path).mkdir(parents=True, exist_ok=True)


def get_timestamp() -> str:
    """Get current timestamp as string"""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def get_file_size(file_path: str) -> int:
    """Get file size in bytes"""
    try:
        return os.path.getsize(file_path)
    except OSError:
        return 0


def rotate_file(file_path: str, max_size: int) -> bool:
    """Rotate file if it exceeds max_size (in MB)"""
    if not os.path.exists(file_path):
        return False
    
    size_mb = get_file_size(file_path) / (1024 * 1024)
    if size_mb >= max_size:
        timestamp = get_timestamp()
        rotated_path = f"{file_path}.{timestamp}"
        os.rename(file_path, rotated_path)
        return True
    return False


def format_bytes(bytes_count: int) -> str:
    """Format bytes count to human readable string"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_count < 1024.0:
            return f"{bytes_count:.1f} {unit}"
        bytes_count /= 1024.0
    return f"{bytes_count:.1f} TB"


def save_json(data: Dict[Any, Any], file_path: str) -> None:
    """Save data to JSON file"""
    ensure_directory(os.path.dirname(file_path))
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)


def load_json(file_path: str) -> Optional[Dict[Any, Any]]:
    """Load data from JSON file"""
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