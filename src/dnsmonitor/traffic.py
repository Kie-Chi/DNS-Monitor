"""DNS Traffic Monitor - Captures and analyzes DNS packets using pcapy-ng and dpkt"""

import time
import threading
import queue
import json
import struct
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime

try:
    import pcapy
except ImportError:
    print("Warning: pcapy not available, using mock implementation")
    import pcapy_mock as pcapy
import dpkt
from dpkt.dns import DNS

from config import TrafficConfig
from utils.logger import get_logger


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
    
    def analyze_packet(self, timestamp: float, packet_data: bytes) -> Optional[Dict[str, Any]]:
        """Analyze a single packet and extract DNS information"""
        try:
            self.stats['total_packets'] += 1
            
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
            
            self.stats['dns_packets'] += 1
            
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
            
            # Update statistics
            if packet_info['is_query']:
                self.stats['queries'] += 1
                self.stats['clients'].add(packet_info['src_ip'])
                self.stats['servers'].add(packet_info['dst_ip'])
            else:
                self.stats['responses'] += 1
                self.stats['clients'].add(packet_info['dst_ip'])
                self.stats['servers'].add(packet_info['src_ip'])
                
                # Count response codes
                rcode_name = self._get_rcode_name(dns.rcode)
                self.stats['response_codes'][rcode_name] = self.stats['response_codes'].get(rcode_name, 0) + 1
            
            # Parse questions
            for question in dns.qd:
                qname = question.name.decode('utf-8', errors='ignore')
                qtype = self._get_qtype_name(question.type)
                packet_info['questions'].append({
                    'name': qname,
                    'type': qtype,
                    'class': question.cls
                })
                
                # Count query types
                if packet_info['is_query']:
                    self.stats['query_types'][qtype] = self.stats['query_types'].get(qtype, 0) + 1
            
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
            self.stats['errors'] += 1
            logging.debug(f"Error analyzing packet: {e}")
            return None
    
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
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current statistics"""
        stats = self.stats.copy()
        stats['clients'] = list(stats['clients'])
        stats['servers'] = list(stats['servers'])
        return stats
    
    def reset_stats(self) -> None:
        """Reset statistics"""
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
    """DNS Traffic Monitor with dual-process architecture"""
    
    def __init__(self, config: TrafficConfig):
        self.config = config
        self.logger = get_logger(__name__)
        self.analyzer = DNSPacketAnalyzer()
        self.running = False
        self.capture_thread = None
        self.analysis_thread = None
        self.stats_thread = None
        
        # Packet queue for communication between capture and analysis
        self.packet_queue = []
        self.queue_lock = threading.Lock()
        
        # PCAP writer
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
            self.pcap_writer.close()
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
                    
                    timestamp = header.getts()[0] + header.getts()[1] / 1000000.0
                    
                    # Write to PCAP file
                    if self.pcap_writer:
                        self.pcap_writer.writepkt(packet_data, header.getts())
                    
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
                self.pcap_writer.close()
    
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
                    packet_info = self.analyzer.analyze_packet(timestamp, packet_data)
                    if packet_info:
                        self._handle_dns_packet(packet_info)
                
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
    
    def _handle_dns_packet(self, packet_info: Dict[str, Any]) -> None:
        """Handle analyzed DNS packet"""
        # Log interesting packets
        if packet_info['is_query']:
            questions = ', '.join([f"{q['name']} {q['type']}" for q in packet_info['questions']])
            self.logger.debug(f"DNS Query: {packet_info['src_ip']} -> {packet_info['dst_ip']}: {questions}")
        else:
            rcode = self._get_rcode_name(packet_info['rcode'])
            self.logger.debug(f"DNS Response: {packet_info['src_ip']} -> {packet_info['dst_ip']}: {rcode}")
    
    def _rotate_pcap_file(self) -> None:
        """Rotate PCAP file"""
        if self.pcap_writer:
            self.pcap_writer.close()
        
        timestamp = get_timestamp()
        self.current_pcap_file = os.path.join(self.config.pcap_dir, f"dns_traffic_{timestamp}.pcap")
        
        try:
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