"""DNS Traffic Monitor - Captures and analyzes DNS packets using pcapy-ng and dpkt"""

import time
import threading
import os
import signal
import socket
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Set
from datetime import datetime
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv6Address

try:
    import pcapy
except ImportError:
    print("Warning: pcapy not available, using mock implementation")
import dpkt
from dpkt.dns import DNS

from .config import TrafficConfig
from .utils.logger import get_logger
from .utils.common import ensure_directory, rotate_file, save_json, get_timestamp


@dataclass(slots=True)
class Packet:
    """DNS Packet"""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str = "UDP"  # UDP or TCP
    
    # DNS fields
    query_id: int = 0
    is_response: bool = False
    opcode: int = 0
    rcode: int = 0
    flags: Dict[str, bool] = field(default_factory=dict)
    
    # DNS sections
    questions: List[Dict[str, Any]] = field(default_factory=list)
    answers: List[Dict[str, Any]] = field(default_factory=list)
    authorities: List[Dict[str, Any]] = field(default_factory=list)
    additionals: List[Dict[str, Any]] = field(default_factory=list)
    
    # Raw data
    raw_data: bytes = field(default=b"", repr=False)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert packet to dictionary representation"""
        result = {
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "query_id": self.query_id,
            "is_response": self.is_response,
            "opcode": self.opcode,
            "rcode": self.rcode,
            "flags": self.flags,
            "questions": self.questions,
            "answers": self.answers,
            "authorities": self.authorities,
            "additionals": self.additionals
        }
        return result
    
    @property
    def qname(self) -> str:
        """Get query domain name (first question's name)"""
        if self.questions:
            return self.questions[0].get("name", "")
        return ""
    
    @property
    def qtype(self) -> str:
        """Get query type (first question's type)"""
        if self.questions:
            return self.questions[0].get("type", "")
        return ""
    
    @property
    def response_time(self) -> Optional[float]:
        """Get response time (if this is a response packet)"""
        if self.is_response and hasattr(self, "_query_time"):
            return self.timestamp - getattr(self, "_query_time")
        return None
    
    def set_query_time(self, query_time: float) -> None:
        """Set query time (for response time calculation)"""
        self._query_time = query_time
        
class DNSPacketAnalyzer:
    """DNS packet analyzer using dpkt"""
    
    def __init__(self):
        self.stats = {
            'total_packets': 0,
            'dns_packets': 0,
            'queries': 0,
            'responses': 0,
            'errors': 0,
            'query_types': {},
            'response_codes': {},
            'clients': set(),
            'servers': set(),
        }
    
    def analyze_packet(self, timestamp: float, packet_data: bytes) -> Optional[Packet]:
        """Analyze a single packet and extract DNS information
        
        Args:
            timestamp: Packet capture timestamp
            packet_data: Raw packet data
            
        Returns:
            Packet: Parsed DNS packet object if it's a DNS packet, None otherwise
        """
        try:
            self.stats['total_packets'] += 1
            eth = dpkt.ethernet.Ethernet(packet_data)
            if not isinstance(eth.data, dpkt.ip.IP):
                return None
            ip = eth.data
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)
            protocol = ""
            if isinstance(ip.data, dpkt.udp.UDP):
                udp = ip.data
                src_port = udp.sport
                dst_port = udp.dport
                protocol = "UDP"
                transport_data = udp.data
                if udp.sport != 53 and udp.dport != 53:
                    return None
            elif isinstance(ip.data, dpkt.tcp.TCP):
                tcp = ip.data
                src_port = tcp.sport
                dst_port = tcp.dport
                protocol = "TCP"
                transport_data = tcp.data
                if tcp.sport != 53 and tcp.dport != 53:
                    return None
            else:
                return None
                
            try:
                dns = dpkt.dns.DNS(transport_data)
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                self.stats['errors'] += 1
                return None
            
            self.stats['dns_packets'] += 1
            
            packet = Packet(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                query_id=dns.id,
                is_response=dns.qr == 1,
                opcode=dns.opcode,
                rcode=dns.rcode,
                raw_data=packet_data
            )
            
            packet.flags = {
                'qr': dns.qr == 1,  # 1 for response, 0 for query
                'aa': dns.aa == 1,  # Authoritative Answer
                'tc': dns.tc == 1,  # Truncated
                'rd': dns.rd == 1,  # Recursion Desired
                'ra': dns.ra == 1,  # Recursion Available
                'z': dns.z == 1,    # Reserved
                'ad': dns.ad == 1,  # Authentic Data (DNSSEC)
                'cd': dns.cd == 1   # Checking Disabled (DNSSEC)
            }
            
            for question in dns.qd:
                q_name = question.name.decode('utf-8', errors='replace')
                q_type = self._get_qtype_name(question.type)
                
                # Update query type statistics
                if q_type not in self.stats['query_types']:
                    self.stats['query_types'][q_type] = 0
                self.stats['query_types'][q_type] += 1
                
                packet.questions.append({
                    'name': q_name,
                    'type': q_type,
                    'class': question.cls
                })
            
            for answer in dns.an:
                packet.answers.append(self._parse_rr(answer))
            for auth in dns.ns:
                packet.authorities.append(self._parse_rr(auth))
            for additional in dns.ar:
                packet.additionals.append(self._parse_rr(additional))
            if not packet.is_response:
                self.stats['queries'] += 1
                if packet.src_ip not in self.stats['clients']:
                    self.stats['clients'].add(packet.src_ip)
            else:
                self.stats['responses'] += 1
                if packet.src_ip not in self.stats['servers']:
                    self.stats['servers'].add(packet.src_ip)
                
                rcode_name = self._get_rcode_name(packet.rcode)
                if rcode_name not in self.stats['response_codes']:
                    self.stats['response_codes'][rcode_name] = 0
                self.stats['response_codes'][rcode_name] += 1
            
            return packet
            
        except Exception as e:
            self.stats['errors'] += 1
            return None
    
    def _parse_rr(self, rr) -> Dict[str, Any]:
        """Parse a DNS resource record"""
        try:
            name = rr.name.decode('utf-8', errors='replace')
            rr_type = self._get_dns_type(rr.type)
            ttl = rr.ttl
            
            # Parse different record types
            rdata = {}
            
            if rr.type == dpkt.dns.DNS_A:
                rdata['address'] = socket.inet_ntoa(rr.rdata)
            elif rr.type == dpkt.dns.DNS_AAAA:
                rdata['address'] = socket.inet_ntop(socket.AF_INET6, rr.rdata)
            elif rr.type == dpkt.dns.DNS_CNAME:
                rdata['cname'] = rr.cname.decode('utf-8', errors='replace')
            elif rr.type == dpkt.dns.DNS_MX:
                rdata['preference'] = rr.preference
                rdata['name'] = rr.name.decode('utf-8', errors='replace')
            elif rr.type == dpkt.dns.DNS_NS:
                rdata['name'] = rr.nsname.decode('utf-8', errors='replace')
            elif rr.type == dpkt.dns.DNS_PTR:
                rdata['name'] = rr.ptrname.decode('utf-8', errors='replace')
            elif rr.type == dpkt.dns.DNS_SOA:
                rdata['mname'] = rr.mname.decode('utf-8', errors='replace')
                rdata['rname'] = rr.rname.decode('utf-8', errors='replace')
                rdata['serial'] = rr.serial
                rdata['refresh'] = rr.refresh
                rdata['retry'] = rr.retry
                rdata['expire'] = rr.expire
                rdata['minimum'] = rr.minimum
            elif rr.type == dpkt.dns.DNS_TXT:
                rdata['text'] = b''.join(rr.text).decode('utf-8', errors='replace')
            else:
                # For other record types, store raw data as hex
                rdata['data'] = rr.rdata.hex()
            
            return {
                'name': name,
                'type': rr_type,
                'class': rr.cls,
                'ttl': ttl,
                'rdata': rdata
            }
        except Exception as e:
            return {
                'name': '',
                'type': 'UNKNOWN',
                'class': 0,
                'ttl': 0,
                'rdata': {'error': str(e)},
                'parse_error': True
            }
            self.stats['queries'] += 1

    
    def _get_qtype_name(self, qtype: int) -> str:
        qtype_names = {
            1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 255: 'ANY'
        }
        return qtype_names.get(qtype, f'TYPE{qtype}')
    
    def _get_rcode_name(self, rcode: int) -> str:
        rcode_names = {
            0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN',
            4: 'NOTIMP', 5: 'REFUSED', 9: 'NOTAUTH', 10: 'NOTZONE'
        }
        return rcode_names.get(rcode, f'RCODE{rcode}')
    

    
    def _format_rdata(self, rtype: int, rdata: bytes) -> str:
        try:
            if rtype in (1, 28):  # A, AAAA
                return '.'.join(str(b) for b in rdata)
            elif rtype in (5, 2):  # CNAME, NS
                return rdata.decode('utf-8', errors='ignore')
            elif rtype == 16:  # TXT
                return rdata.decode('utf-8', errors='ignore')
            else:
                return rdata.hex()
        except Exception:
            return 'PARSE_ERROR'
    
    def get_stats(self) -> Dict[str, Any]:
        return self.stats
    
    def reset_stats(self) -> None:
        self.stats = {
            'total_packets': 0,
            'dns_packets': 0,
            'queries': 0,
            'responses': 0,
            'errors': 0,
            'query_types': {},
            'response_codes': {},
            'clients': set(),
            'servers': set(),
        }
    

class TrafficMonitor:
    """DNS Traffic Monitor using pcapy"""
    
    def __init__(self, config: TrafficConfig):
        self.config = config
        self.logger = get_logger(__name__)
        self.running = False
        
        # Threads
        self.capture_thread = None
        self.analysis_thread = None
        self.stats_thread = None
        
        # Packet queue
        self.packet_queue: List[Tuple[float, bytes]] = []
        self.queue_lock = threading.Lock()
        
        # Analyzer
        self.analyzer = DNSPacketAnalyzer()
        
        # PCAP file handling
        self.pcap_writer = None
        self.current_pcap_file = None
        self.pcap_start_time = None
        
        # Ensure output directory exists
        ensure_directory(self.config.pcap_dir)
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def start(self) -> None:
        """Start traffic monitoring"""
        self.logger.info("Starting DNS traffic monitoring...")
        self.running = True
        
        try:
            # Start capture thread
            self.capture_thread = threading.Thread(target=self._capture_worker, daemon=True)
            self.capture_thread.start()
            
            # Start analysis thread
            self.analysis_thread = threading.Thread(target=self._analysis_worker, daemon=True)
            self.analysis_thread.start()
            
            # Start statistics thread
            self.stats_thread = threading.Thread(target=self._stats_worker, daemon=True)
            self.stats_thread.start()
            
            self.logger.info("Traffic monitoring started successfully")
            
            # Keep main thread alive
            while self.running:
                time.sleep(1)
                
        except Exception as e:
            self.logger.error(f"Failed to start traffic monitoring: {e}")
            self.stop()
            raise
    
    def stop(self) -> None:
        """Stop traffic monitoring"""
        self.logger.info("Stopping DNS traffic monitoring...")
        self.running = False
        
        # Close PCAP writer
        if self.pcap_writer:
            try:
                self.pcap_writer.close()
            except Exception:
                pass
            self.pcap_writer = None
        
        # Wait for threads to finish
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=5)
        if self.analysis_thread and self.analysis_thread.is_alive():
            self.analysis_thread.join(timeout=5)
        if self.stats_thread and self.stats_thread.is_alive():
            self.stats_thread.join(timeout=5)
        
        self.logger.info("Traffic monitoring stopped")
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.stop()
    
    def _capture_worker(self) -> None:
        """Packet capture worker thread"""
        try:
            # Open capture device
            cap = pcapy.open_live(
                self.config.interface,
                self.config.buffer_size,
                True,  # Promiscuous mode
                100    # Timeout in ms
            )
            
            # Set BPF filter
            cap.setfilter(self.config.bpf_filter)
            
            self.logger.info(f"Started packet capture on {self.config.interface}")
            
            # Initialize PCAP file
            self._rotate_pcap_file()
            
            while self.running:
                try:
                    # Capture packet
                    header, packet_data = cap.next()
                    if header is None:
                        continue
                    
                    # header.getts() may not exist in mock; emulate timestamp
                    try:
                        ts = header.getts()
                        timestamp = ts[0] + ts[1] / 1000000.0
                    except Exception:
                        timestamp = time.time()
                        ts = (int(timestamp), int((timestamp - int(timestamp)) * 1000000))
                    
                    # Write to PCAP file
                    if self.pcap_writer:
                        try:
                            self.pcap_writer.writepkt(packet_data, ts)
                        except Exception:
                            pass
                    
                    # Add to analysis queue
                    with self.queue_lock:
                        self.packet_queue.append((timestamp, packet_data))
                        
                        # Limit queue size to prevent memory issues
                        if len(self.packet_queue) > 10000:
                            self.packet_queue.pop(0)
                    
                    # Check if PCAP rotation is needed
                    self._check_pcap_rotation()
                    
                except Exception as e:
                    if self.running:
                        self.logger.debug(f"Capture error: {e}")
                        
        except Exception as e:
            self.logger.error(f"Capture worker failed: {e}")
        finally:
            if self.pcap_writer:
                try:
                    self.pcap_writer.close()
                except Exception:
                    pass
    
    def _analysis_worker(self) -> None:
        """Packet analysis worker thread"""
        self.logger.info("Started packet analysis worker")
        
        while self.running:
            try:
                # Get packets from queue
                packets_to_process = []
                with self.queue_lock:
                    if self.packet_queue:
                        packets_to_process = self.packet_queue[:100]  # Process in batches
                        self.packet_queue = self.packet_queue[100:]
                
                # Process packets
                for timestamp, packet_data in packets_to_process:
                    packet = self.analyzer.analyze_packet(timestamp, packet_data)
                    if packet:
                        self._handle_dns_packet(packet)
                
                # Sleep if no packets to process
                if not packets_to_process:
                    time.sleep(0.1)
                    
            except Exception as e:
                if self.running:
                    self.logger.debug(f"Analysis error: {e}")
    
    def _stats_worker(self) -> None:
        """Statistics reporting worker thread"""
        self.logger.info("Started statistics worker")
        last_stats_time = time.time()
        
        while self.running:
            try:
                current_time = time.time()
                
                # Report statistics every 60 seconds
                if current_time - last_stats_time >= 60:
                    self._report_statistics()
                    last_stats_time = current_time
                
                time.sleep(10)  # Check every 10 seconds
                
            except Exception as e:
                if self.running:
                    self.logger.debug(f"Stats worker error: {e}")
    
    def _handle_dns_packet(self, packet: Packet) -> None:
        """Handle analyzed DNS packet"""
        # Log interesting packets
        if not packet.is_response:
            questions = ', '.join([f"{q['name']} {q['type']}" for q in packet.questions])
            self.logger.debug(f"DNS Query: {packet.src_ip} -> {packet.dst_ip}: {questions}")
        else:
            rcode = self._get_rcode_name(packet.rcode)
            self.logger.debug(f"DNS Response: {packet.src_ip} -> {packet.dst_ip}: {rcode}")
    
    def _rotate_pcap_file(self) -> None:
        """Rotate PCAP file"""
        if self.pcap_writer:
            try:
                self.pcap_writer.close()
            except Exception:
                pass
        
        timestamp = get_timestamp()
        self.current_pcap_file = os.path.join(self.config.pcap_dir, f"dns_traffic_{timestamp}.pcap")
        
        try:
            # In real pcapy, dump_open(file) returns a Dumper; mock will offer compatible stub
            self.pcap_writer = pcapy.dump_open(self.current_pcap_file)
            self.pcap_start_time = time.time()
            self.logger.info(f"Started new PCAP file: {self.current_pcap_file}")
        except Exception as e:
            self.logger.error(f"Failed to create PCAP file: {e}")
            self.pcap_writer = None
    
    def _check_pcap_rotation(self) -> None:
        """Check if PCAP file needs rotation"""
        if not self.current_pcap_file or not self.pcap_start_time:
            return
        
        current_time = time.time()
        
        # Check time-based rotation
        if current_time - self.pcap_start_time >= self.config.pcap_rotation_time:
            self.logger.info("Rotating PCAP file (time limit reached)")
            self._rotate_pcap_file()
            return
        
        # Check size-based rotation
        if rotate_file(self.current_pcap_file, self.config.pcap_rotation_size):
            self.logger.info("Rotating PCAP file (size limit reached)")
            self._rotate_pcap_file()
    
    def _report_statistics(self) -> None:
        """Report current statistics"""
        stats = self.analyzer.get_stats()
        
        self.logger.info("=== DNS Traffic Statistics ===")
        self.logger.info(f"Total packets: {stats['total_packets']}")
        self.logger.info(f"DNS packets: {stats['dns_packets']}")
        self.logger.info(f"Queries: {stats['queries']}")
        self.logger.info(f"Responses: {stats['responses']}")
        self.logger.info(f"Errors: {stats['errors']}")
        self.logger.info(f"Unique clients: {len(stats['clients'])}")
        self.logger.info(f"Unique servers: {len(stats['servers'])}")
        
        # Save statistics to file
        stats_file = os.path.join(self.config.pcap_dir, f"stats_{get_timestamp()}.json")
        save_json(stats, stats_file)
    
    def _get_rcode_name(self, rcode: int) -> str:
        """Get DNS response code name"""
        rcode_names = {
            0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN',
            4: 'NOTIMP', 5: 'REFUSED', 9: 'NOTAUTH', 10: 'NOTZONE'
        }
        return rcode_names.get(rcode, f'RCODE{rcode}')