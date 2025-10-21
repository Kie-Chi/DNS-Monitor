"""Constants for DNS Monitor."""

# --- Log and Debug ---
# Short aliases for module names to keep CLI/env concise
LOG_ALIAS_MAP = {
    "core": "dnsmonitor.core",
    "monitor": "dnsmonitor.monitor",
    "traffic": "dnsmonitor.traffic",
    "resolver": "dnsmonitor.resolver",
    "cache": "dnsmonitor.cache",
    "config": "dnsmonitor.config",
    "conf": "dnsmonitor.config",
    "cli": "dnsmonitor.cli",
    "utils": "dnsmonitor.utils",
    "exceptions": "dnsmonitor.exceptions",
    "exc": "dnsmonitor.exceptions",
}

# Top-level modules within dnsmonitor for auto-prefixing
KNOWN_TOP_MODULES = {
    "core",
    "monitor",
    "traffic",
    "resolver", 
    "cache",
    "config",
    "utils",
    "exceptions",
    "cli",
}

# --- DNS Monitoring Constants ---
DEFAULT_TIMEOUT = 5.0
DEFAULT_PORT = 53
DEFAULT_INTERFACE = "any"
DEFAULT_BPF_FILTER = "port 53"

# --- File Management ---
DEFAULT_MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
DEFAULT_MAX_FILES = 10
DEFAULT_STATS_INTERVAL = 60  # seconds

# --- Cache Monitoring ---
DEFAULT_CACHE_INTERVAL = 30  # seconds
DEFAULT_ANALYSIS_PORT = 8080

# --- Resolver Monitoring ---
DEFAULT_TRANSACTION_TIMEOUT = 10.0  # seconds

# --- Traffic Monitoring ---
DEFAULT_CAPTURE_BUFFER_SIZE = 65536
DEFAULT_CAPTURE_TIMEOUT = 1000  # milliseconds

# --- Log Levels ---
LOG_LEVELS = {
    "DEBUG": 10,
    "INFO": 20,
    "WARNING": 30,
    "ERROR": 40,
    "CRITICAL": 50,
}

# --- Output Formats ---
OUTPUT_FORMATS = {
    "JSON",
    "PCAP",
    "TEXT",
    "CSV",
}

# --- DNS Server Types ---
DNS_SERVER_TYPES = {
    "BIND",
    "UNBOUND",
    "POWERDNS",
    "KNOT",
}

# --- Monitoring Modes ---
MONITORING_MODES = {
    "TRAFFIC_ONLY",
    "RESOLVER_ONLY", 
    "CACHE_ONLY",
    "COMPREHENSIVE",
}

# --- Performance Tuning ---
DEFAULT_WORKER_THREADS = 4
DEFAULT_QUEUE_SIZE = 1000
DEFAULT_BATCH_SIZE = 100

# --- Network Constants ---
DNS_QUERY_TYPES = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "PTR": 12,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
    "SRV": 33,
    "ANY": 255,
}

DNS_CLASSES = {
    "IN": 1,
    "CS": 2,
    "CH": 3,
    "HS": 4,
}

# --- Error Codes ---
ERROR_CODES = {
    "CONFIG_ERROR": 1,
    "NETWORK_ERROR": 2,
    "PERMISSION_ERROR": 3,
    "FILE_ERROR": 4,
    "TIMEOUT_ERROR": 5,
    "PARSE_ERROR": 6,
}