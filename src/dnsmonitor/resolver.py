"""DNS Resolution Path Monitor - Tracks DNS query resolution paths using BPF filtering"""

import time
import threading
import json
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict

try:
    import pcapy
except ImportError:
    print("Warning: pcapy not available, using mock implementation")
    import pcapy_mock as pcapy
import dpkt
from dpkt.dns import DNS

from config import ResolverConfig
from utils.logger import get_logger
from utils import Colors, colorize


class DNSTransaction:
    """Represents a DNS transaction from query to response"""
    
    def __init__(self, query_packet: Dict[str, Any]):
        self.query_id = query_packet['dns_id']
        self.client_ip = query_packet['src_ip']
        self.resolver_ip = query_packet['dst_ip']
        self.query_name = query_packet['questions'][0]['name'] if query_packet['questions'] else 'UNKNOWN'
        self.query_type = query_packet['questions'][0]['type'] if query_packet['questions'] else 'UNKNOWN'
        self.start_time = query_packet['timestamp']
        self.end_time = None
        self.response_packet = None
        self.resolution_path = []
        self.status = 'PENDING'
        self.rcode = None
        self.answer_count = 0
        self.authority_count = 0
        self.additional_count = 0
    
    def add_intermediate_packet(self, packet: Dict[str, Any]) -> None:
        """Add intermediate packet to resolution path"""
        self.resolution_path.append({
            'timestamp': packet['timestamp'],
            'src_ip': packet['src_ip'],
            'dst_ip': packet['dst_ip'],
            'is_query': packet['is_query'],
            'questions': packet['questions'],
            'answers': packet['answers'],
            'authorities': packet['authorities'],
            'additionals': packet['additionals'],
        })
    
    def complete_transaction(self, response_packet: Dict[str, Any]) -> None:
        """Complete the transaction with response packet"""
        self.end_time = response_packet['timestamp']
        self.response_packet = response_packet
        self.status = 'COMPLETED'
        self.rcode = response_packet['rcode']
        self.answer_count = len(response_packet['answers'])
        self.authority_count = len(response_packet['authorities'])
        self.additional_count = len(response_packet['additionals'])
    
    def timeout_transaction(self) -> None:
        """Mark transaction as timed out"""
        self.status = 'TIMEOUT'
        self.end_time = time.time()
    
    def get_duration(self) -> Optional[float]:
        """Get transaction duration in seconds"""
        if self.end_time:
            return self.end_time - self.start_time
        return None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert transaction to dictionary"""
        return {
            'query_id': self.query_id,
            'client_ip': self.client_ip,
            'resolver_ip': self.resolver_ip,
            'query_name': self.query_name,
            'query_type': self.query_type,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'duration': self.get_duration(),
            'status': self.status,
            'rcode': self.rcode,
            'answer_count': self.answer_count,
            'authority_count': self.authority_count,
            'additional_count': self.additional_count,
            'resolution_path': self.resolution_path,
        }


class ResolverMonitor:
    """DNS Resolver Path Monitor with BPF filtering"""
    
    def __init__(self, config: ResolverConfig):
        self.config = config
        self.logger = get_logger(__name__)
        self.running = False
        self.capture_thread = None
        self.timeout_thread = None
        
        # Active transactions tracking
        self.active_transactions: Dict[Tuple[str, str, int], DNSTransaction] = {}
        self.completed_transactions: List[DNSTransaction] = []
        self.transaction_lock = threading.Lock()
        
        # Statistics
        self.stats = {
            'total_queries': 0,
            'completed_transactions': 0,
            'timeout_transactions': 0,
            'average_resolution_time': 0.0,
            'query_types': {},
            'response_codes': {},
        }
        
        # Validate configuration
        self._validate_config()
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _validate_config(self) -> None:
        """Validate configuration"""
        if not self.config.client_ip:
            raise ValueError("Client IP must be specified")
        if not self.config.resolver_ip:
            raise ValueError("Resolver IP must be specified")
        
        # Validate IP addresses
        try:
            socket.inet_aton(self.config.client_ip)
            socket.inet_aton(self.config.resolver_ip)
        except socket.error as e:
            raise ValueError(f"Invalid IP address: {e}")
    
    def start(self) -> None:
        """Start resolver path monitoring"""
        self.logger.info("Starting DNS resolver path monitoring...")
        self.running = True
        
        try:
            # Start capture thread
            self.capture_thread = threading.Thread(target=self._capture_worker, daemon=True)
            self.capture_thread.start()
            
            # Start timeout cleanup thread
            self.timeout_thread = threading.Thread(target=self._timeout_worker, daemon=True)
            self.timeout_thread.start()
            
            self.logger.info("Resolver path monitoring started successfully")
            self._print_monitoring_info()
            
            # Keep main thread alive and print periodic updates
            last_report_time = time.time()
            while self.running:
                current_time = time.time()
                
                # Print status every 30 seconds
                if current_time - last_report_time >= 30:
                    self._print_status()
                    last_report_time = current_time
                
                time.sleep(1)
                
        except Exception as e:
            self.logger.error(f"Failed to start resolver monitoring: {e}")
            self.stop()
            raise
    
    def stop(self) -> None:
        """Stop resolver path monitoring"""
        self.logger.info("Stopping DNS resolver path monitoring...")
        self.running = False
        
        # Wait for threads to finish
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=5)
        if self.timeout_thread and self.timeout_thread.is_alive():
            self.timeout_thread.join(timeout=5)
        
        # Save final results
        self._save_results()
        
        self.logger.info("Resolver path monitoring stopped")
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.stop()
    
    def _capture_worker(self) -> None:
        """Packet capture worker thread"""
        try:
            # Create BPF filter for client-resolver communication
            bpf_filter = (
                f"port 53 and "
                f"((src host {self.config.client_ip} and dst host {self.config.resolver_ip}) or "
                f"(src host {self.config.resolver_ip} and dst host {self.config.client_ip}) or "
                f"(src host {self.config.resolver_ip}) or (dst host {self.config.resolver_ip}))"
            )
            
            # Open capture device
            cap = pcapy.open_live(
                "any",  # Capture on all interfaces
                65536,  # Snaplen
                True,   # Promiscuous mode
                100     # Timeout in ms
            )
            
            # Set BPF filter
            cap.setfilter(bpf_filter)
            
            self.logger.info(f"Started packet capture with filter: {bpf_filter}")
            
            while self.running:
                try:
                    # Capture packet
                    header, packet_data = cap.next()
                    if header is None:
                        continue
                    
                    timestamp = header.getts()[0] + header.getts()[1] / 1000000.0
                    
                    # Analyze packet
                    packet_info = self._analyze_packet(timestamp, packet_data)
                    if packet_info:
                        self._process_dns_packet(packet_info)
                        
                except Exception as e:
                    if self.running:
                        self.logger.debug(f"Capture error: {e}")
                        
        except Exception as e:
            self.logger.error(f"Capture worker failed: {e}")
    
    def _timeout_worker(self) -> None:
        """Timeout cleanup worker thread"""
        self.logger.info("Started timeout cleanup worker")
        
        while self.running:
            try:
                current_time = time.time()
                timed_out_keys = []
                
                with self.transaction_lock:
                    for key, transaction in self.active_transactions.items():
                        if current_time - transaction.start_time > self.config.timeout:
                            transaction.timeout_transaction()
                            self.completed_transactions.append(transaction)
                            timed_out_keys.append(key)
                            self.stats['timeout_transactions'] += 1
                            
                            self.logger.warning(
                                f"Transaction timed out: {transaction.query_name} "
                                f"({transaction.query_type}) from {transaction.client_ip}"
                            )
                    
                    # Remove timed out transactions
                    for key in timed_out_keys:
                        del self.active_transactions[key]
                
                time.sleep(5)  # Check every 5 seconds
                
            except Exception as e:
                if self.running:
                    self.logger.debug(f"Timeout worker error: {e}")
    
    def _analyze_packet(self, timestamp: float, packet_data: bytes) -> Optional[Dict[str, Any]]:
        """Analyze packet and extract DNS information"""
        try:
            # Parse Ethernet frame
            eth = dpkt.ethernet.Ethernet(packet_data)
            
            # Check if it's IP
            if not isinstance(eth.data, dpkt.ip.IP):
                return None
            
            ip = eth.data
            
            # Check if it's UDP
            if not isinstance(ip.data, dpkt.udp.UDP):
                return None
            
            udp = ip.data
            
            # Check if it's DNS (port 53)
            if udp.sport != 53 and udp.dport != 53:
                return None
            
            # Parse DNS
            try:
                dns = dpkt.dns.DNS(udp.data)
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                return None
            
            # Extract packet information
            packet_info = {
                'timestamp': timestamp,
                'src_ip': self._ip_to_str(ip.src),
                'dst_ip': self._ip_to_str(ip.dst),
                'src_port': udp.sport,
                'dst_port': udp.dport,
                'dns_id': dns.id,
                'is_query': dns.qr == 0,
                'opcode': dns.opcode,
                'rcode': dns.rcode,
                'questions': [],
                'answers': [],
                'authorities': [],
                'additionals': [],
            }
            
            # Parse questions
            for question in dns.qd:
                packet_info['questions'].append({
                    'name': question.name.decode('utf-8', errors='ignore'),
                    'type': self._get_qtype_name(question.type),
                    'class': question.cls
                })
            
            # Parse answers
            for answer in dns.an:
                packet_info['answers'].append(self._parse_rr(answer))
            
            # Parse authorities
            for auth in dns.ns:
                packet_info['authorities'].append(self._parse_rr(auth))
            
            # Parse additionals
            for add in dns.ar:
                packet_info['additionals'].append(self._parse_rr(add))
            
            return packet_info
            
        except Exception as e:
            self.logger.debug(f"Error analyzing packet: {e}")
            return None
    
    def _process_dns_packet(self, packet: Dict[str, Any]) -> None:
        """Process DNS packet and update transactions"""
        with self.transaction_lock:
            if packet['is_query']:
                self._handle_query_packet(packet)
            else:
                self._handle_response_packet(packet)
    
    def _handle_query_packet(self, packet: Dict[str, Any]) -> None:
        """Handle DNS query packet"""
        # Check if this is a client query to resolver
        if (packet['src_ip'] == self.config.client_ip and 
            packet['dst_ip'] == self.config.resolver_ip):
            
            # Create new transaction
            transaction = DNSTransaction(packet)
            key = (packet['src_ip'], packet['dst_ip'], packet['dns_id'])
            self.active_transactions[key] = transaction
            
            self.stats['total_queries'] += 1
            
            # Update query type statistics
            if packet['questions']:
                qtype = packet['questions'][0]['type']
                self.stats['query_types'][qtype] = self.stats['query_types'].get(qtype, 0) + 1
            
            self.logger.info(
                f"{colorize('NEW QUERY', Colors.GREEN)}: "
                f"{transaction.query_name} ({transaction.query_type}) "
                f"from {transaction.client_ip} to {transaction.resolver_ip}"
            )
        
        # Check if this is an intermediate query (resolver to authoritative)
        elif packet['src_ip'] == self.config.resolver_ip:
            # Find matching transaction by DNS ID and add to resolution path
            for key, transaction in self.active_transactions.items():
                if key[2] == packet['dns_id'] or self._is_related_query(transaction, packet):
                    transaction.add_intermediate_packet(packet)
                    
                    if packet['questions']:
                        query_name = packet['questions'][0]['name']
                        query_type = packet['questions'][0]['type']
                        self.logger.debug(
                            f"{colorize('UPSTREAM QUERY', Colors.YELLOW)}: "
                            f"{query_name} ({query_type}) "
                            f"from {packet['src_ip']} to {packet['dst_ip']}"
                        )
                    break
    
    def _handle_response_packet(self, packet: Dict[str, Any]) -> None:
        """Handle DNS response packet"""
        # Check if this is a response from resolver to client
        if (packet['src_ip'] == self.config.resolver_ip and 
            packet['dst_ip'] == self.config.client_ip):
            
            key = (packet['dst_ip'], packet['src_ip'], packet['dns_id'])
            if key in self.active_transactions:
                transaction = self.active_transactions[key]
                transaction.complete_transaction(packet)
                
                # Move to completed transactions
                self.completed_transactions.append(transaction)
                del self.active_transactions[key]
                
                self.stats['completed_transactions'] += 1
                
                # Update response code statistics
                rcode_name = self._get_rcode_name(packet['rcode'])
                self.stats['response_codes'][rcode_name] = self.stats['response_codes'].get(rcode_name, 0) + 1
                
                # Update average resolution time
                duration = transaction.get_duration()
                if duration:
                    total_time = self.stats['average_resolution_time'] * (self.stats['completed_transactions'] - 1)
                    self.stats['average_resolution_time'] = (total_time + duration) / self.stats['completed_transactions']
                
                self.logger.info(
                    f"{colorize('COMPLETED', Colors.GREEN)}: "
                    f"{transaction.query_name} ({transaction.query_type}) "
                    f"-> {rcode_name} in {duration:.3f}s "
                    f"({transaction.answer_count} answers, {len(transaction.resolution_path)} hops)"
                )
        
        # Check if this is an intermediate response (authoritative to resolver)
        elif packet['dst_ip'] == self.config.resolver_ip:
            # Find matching transaction and add to resolution path
            for transaction in self.active_transactions.values():
                if self._is_related_response(transaction, packet):
                    transaction.add_intermediate_packet(packet)
                    
                    rcode_name = self._get_rcode_name(packet['rcode'])
                    self.logger.debug(
                        f"{colorize('UPSTREAM RESPONSE', Colors.CYAN)}: "
                        f"{rcode_name} from {packet['src_ip']} to {packet['dst_ip']} "
                        f"({len(packet['answers'])} answers)"
                    )
                    break
    
    def _is_related_query(self, transaction: DNSTransaction, packet: Dict[str, Any]) -> bool:
        """Check if a query packet is related to a transaction"""
        if not packet['questions']:
            return False
        
        query_name = packet['questions'][0]['name']
        
        # Check if query name is related to transaction query
        return (query_name == transaction.query_name or 
                query_name.endswith('.' + transaction.query_name) or
                transaction.query_name.endswith('.' + query_name))
    
    def _is_related_response(self, transaction: DNSTransaction, packet: Dict[str, Any]) -> bool:
        """Check if a response packet is related to a transaction"""
        # Check if any answers, authorities, or additionals are related
        all_records = packet['answers'] + packet['authorities'] + packet['additionals']
        
        for record in all_records:
            if (record['name'] == transaction.query_name or
                record['name'].endswith('.' + transaction.query_name) or
                transaction.query_name.endswith('.' + record['name'])):
                return True
        
        return False
    
    def _print_monitoring_info(self) -> None:
        """Print monitoring information"""
        print(f"\n{Colors.BOLD}{Colors.CYAN}DNS Resolver Path Monitor{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*50}{Colors.RESET}")
        print(f"Client IP: {colorize(self.config.client_ip, Colors.GREEN)}")
        print(f"Resolver IP: {colorize(self.config.resolver_ip, Colors.GREEN)}")
        print(f"Timeout: {colorize(f'{self.config.timeout}s', Colors.YELLOW)}")
        print(f"Status: {colorize('MONITORING', Colors.GREEN)}")
        print(f"{Colors.CYAN}{'='*50}{Colors.RESET}\n")
    
    def _print_status(self) -> None:
        """Print current monitoring status"""
        active_count = len(self.active_transactions)
        completed_count = len(self.completed_transactions)
        
        print(f"\n{Colors.BOLD}Status Update{Colors.RESET}")
        print(f"Active transactions: {colorize(str(active_count), Colors.YELLOW)}")
        print(f"Completed transactions: {colorize(str(completed_count), Colors.GREEN)}")
        print(f"Total queries: {colorize(str(self.stats['total_queries']), Colors.CYAN)}")
        print(f"Timeout transactions: {colorize(str(self.stats['timeout_transactions']), Colors.RED)}")
        
        if self.stats['average_resolution_time'] > 0:
            avg_time = self.stats['average_resolution_time']
        print(f"Average resolution time: {colorize(f'{avg_time:.3f}s', Colors.MAGENTA)}")
    
    def _save_results(self) -> None:
        """Save monitoring results to file"""
        try:
            results = {
                'config': {
                    'client_ip': self.config.client_ip,
                    'resolver_ip': self.config.resolver_ip,
                    'timeout': self.config.timeout,
                },
                'statistics': self.stats,
                'transactions': [t.to_dict() for t in self.completed_transactions],
            }
            
            timestamp = get_timestamp()
            results_file = f"resolver_monitor_results_{timestamp}.json"
            save_json(results, results_file)
            
            self.logger.info(f"Results saved to: {results_file}")
            
        except Exception as e:
            self.logger.error(f"Failed to save results: {e}")
    
    def _ip_to_str(self, ip_bytes: bytes) -> str:
        """Convert IP bytes to string"""
        return '.'.join(str(b) for b in ip_bytes)
    
    def _get_qtype_name(self, qtype: int) -> str:
        """Get DNS query type name"""
        qtype_names = {
            1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR',
            15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 255: 'ANY'
        }
        return qtype_names.get(qtype, f'TYPE{qtype}')
    
    def _get_rcode_name(self, rcode: int) -> str:
        """Get DNS response code name"""
        rcode_names = {
            0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN',
            4: 'NOTIMP', 5: 'REFUSED', 9: 'NOTAUTH', 10: 'NOTZONE'
        }
        return rcode_names.get(rcode, f'RCODE{rcode}')
    
    def _parse_rr(self, rr) -> Dict[str, Any]:
        """Parse DNS resource record"""
        try:
            return {
                'name': rr.name.decode('utf-8', errors='ignore'),
                'type': self._get_qtype_name(rr.type),
                'class': rr.cls,
                'ttl': rr.ttl,
                'data': self._format_rdata(rr.type, rr.rdata)
            }
        except Exception:
            return {
                'name': 'PARSE_ERROR',
                'type': 'UNKNOWN',
                'class': 0,
                'ttl': 0,
                'data': 'PARSE_ERROR'
            }
    
    def _format_rdata(self, rtype: int, rdata: bytes) -> str:
        """Format DNS resource record data"""
        try:
            if rtype == 1:  # A
                return self._ip_to_str(rdata)
            elif rtype == 28:  # AAAA
                return ':'.join(f'{rdata[i:i+2].hex()}' for i in range(0, 16, 2))
            elif rtype in [2, 5, 12]:  # NS, CNAME, PTR
                return rdata.decode('utf-8', errors='ignore')
            else:
                return rdata.hex()
        except Exception:
            return 'FORMAT_ERROR'