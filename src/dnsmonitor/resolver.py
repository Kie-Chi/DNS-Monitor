"""
DNS Resolution Path Monitor - Strict Serial Transaction Processor Model

This monitor assumes that only one DNS resolution transaction from the specified client
is actively being processed at any given time. It captures a complete transaction
before starting to look for the next one.
"""
import time
import threading
import json
import queue
import socket
import signal
import socketserver
from typing import List, Optional, Dict, Any
from dataclasses import asdict
from pathlib import Path
from .traffic import create_resolver_monitor
from .packet import DNSPacket, RCODE_MAP
from .config import ResolverConfig, TrafficConfig
from .utils.logger import get_logger
from .utils.common import get_timestamp, save_json
from .utils import Colors, colorize


class DNSTransaction:
    """Represents a DNS transaction from query to response. Populated after collection."""
    
    def __init__(self, query_packet: DNSPacket):
        self.query_id = query_packet.query_id
        self.client_ip = query_packet.src_ip
        self.resolver_ip = query_packet.dst_ip
        self.query_name = query_packet.qname
        self.query_type = query_packet.qtype
        self.start_time = query_packet.timestamp
        self.end_time: Optional[float] = None
        self.response_packet: Optional[DNSPacket] = None
        self.resolution_path: List[Dict[str, Any]] = []
        self.status = 'PENDING'
        self.rcode: Optional[int] = None
        self.answer_count = 0
        self.authority_count = 0
        self.additional_count = 0
    
    def add_resolv_pkt(self, packet: DNSPacket) -> None:
        """Add a packet to the resolution path."""
        self.resolution_path.append(packet.to_dict())
    
    def complete(self, response_packet: DNSPacket) -> None:
        """Finalize the transaction with a successful response."""
        self.end_time = response_packet.timestamp
        self.response_packet = response_packet
        self.status = 'COMPLETED'
        self.rcode = response_packet.rcode
        self.answer_count = len(response_packet.get_answers_list())
        self.authority_count = len(response_packet.get_authorities_list())
        self.additional_count = len(response_packet.get_additionals_list())
    
    def timeout(self) -> None:
        """Mark the transaction as timed out."""
        self.status = 'TIMEOUT'
        self.end_time = time.time()
    
    @property
    def duration(self) -> Optional[float]:
        """Get transaction duration in seconds."""
        if self.end_time:
            return self.end_time - self.start_time
        return None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert transaction to a dictionary for serialization."""
        return {
            'query_id': self.query_id,
            'client_ip': self.client_ip,
            'resolver_ip': self.resolver_ip,
            'query_name': self.query_name,
            'query_type': self.query_type,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'duration': self.duration,
            'status': self.status,
            'rcode': RCODE_MAP.get(self.rcode, f"RCODE{self.rcode}") if self.rcode is not None else None,
            'answer_count': self.answer_count,
            'authority_count': self.authority_count,
            'additional_count': self.additional_count,
            'resolution_path': self.resolution_path,
        }


class AnalysisServer(socketserver.ThreadingTCPServer):
    def __init__(self, server_address, RequestHandlerClass, monitor: 'ResolverMonitor') -> None:
        super().__init__(server_address, RequestHandlerClass)
        self.monitor = monitor

class ResolvHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        try:
            data = self.request.recv(1024).strip()
            self.server.monitor.logger.info(f"Recv request from {self.client_address}: {data}")
            resp = {}
            try:
                pos = int(data)
                with self.server.monitor.trans_lock:
                    if 0 <= pos < len(self.server.monitor.trans):
                        resp = {
                            "status": "success",
                            "transaction": self.server.monitor.trans[pos].to_dict()
                        }
                    else:
                        resp = {
                            "status": "error",
                            "message": f"Transaction {pos} not found"
                        }
            except (ValueError, TypeError) as e:
                resp = {
                    "status": "error",
                    "message": str(e)
                }
            self.request.sendall(json.dumps(resp, indent=2).encode())
        except Exception as e:
            self.server.monitor.logger.error(f"Error handling request: {e}")

class ResolverMonitor:
    """
    Implements a state machine to process one DNS transaction at a time,
    using a user-defined BPF filter for traffic capture.
    """
    
    def __init__(self, config: ResolverConfig):
        self.config = config
        self.logger = get_logger(__name__)
        self.running = threading.Event()
        
        self.packet_queue = queue.Queue(maxsize=10000)
        self.output_queue = queue.Queue(maxsize=10000)
        self.processing_thread = None
        self.output_thread = None
        self.trans_lock = threading.Lock()

        # Server
        self.analysis_server = None
        self.analysis_thread = None
        
        self.trans: List[DNSTransaction] = []
        self.stats = {
            'tot_qs': 0, 
            'trans': 0,
            'timeout_trans': 0, 
            'tot_running': 0.0,
            'dropped_qs': 0,   # dropped by monitor
            'discarded_qs': 0, # irrelevant queries
        }
        
        self._validate_config()
        
        traffic_config = TrafficConfig(interface="any")
        default_filter = (f"(host {self.config.client_ip} or host {self.config.resolver_ip}) and port 53")
        traffic_config.bpf_filter = default_filter
        self.logger.info(f"Using default BPF filter: {default_filter}")
            
        self.monitor = create_resolver_monitor(
            config=traffic_config,
            packet_callback=self._enqueue_packet
        )
        
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _validate_config(self):
        if not self.config.client_ip or not self.config.resolver_ip:
            raise ValueError("Client IP and Resolver IP must be specified in the config.")
        try:
            socket.inet_aton(self.config.client_ip)
            socket.inet_aton(self.config.resolver_ip)
        except socket.error as e:
            raise ValueError(f"Invalid IP address: {e}")

    def _enqueue_packet(self, packet: DNSPacket):
        """Callback to put packets from the monitor into our internal queue."""
        try:
            self.packet_queue.put_nowait(packet)
        except queue.Full:
            self.stats['dropped_qs'] += 1

    def start(self):
        """Starts the traffic monitor and the serial processing worker."""
        self.logger.info("Starting DNS resolver path monitor...")
        if self.running.is_set(): 
            return
        self.running.set()
        try:
            self.processing_thread = threading.Thread(target=self._processing_worker, daemon=True)
            self.output_thread = threading.Thread(target=self._output_worker, daemon=True)
            
            self.processing_thread.start()
            self.output_thread.start()

            if self.config.enable_server:
                self.analysis_thread = threading.Thread(target=self._server_worker, daemon=True)
                self.analysis_thread.start()

            self._print_info()
            self.monitor.start()
            
        except Exception as e:
            self.logger.error(f"Failed to start resolver monitoring: {e}")

    def stop(self):
        """Stops all threads and saves results."""
        if not self.running.is_set(): 
            return
        self.logger.info("Stopping DNS resolver path monitoring...")
        self.running.clear()

        if self.analysis_server:
            self.logger.info("Shutting down analysis server...")
            self.analysis_server.shutdown()
            if self.analysis_thread and self.analysis_thread.is_alive():
                self.analysis_thread.join(timeout=2)
        
        self.monitor.stop()
        self.packet_queue.put(None)  # Sentinel to unblock the processing thread
        self.output_queue.put(None)  # Sentinel to unblock the output thread

        if self.processing_thread and self.processing_thread.is_alive():
            self.processing_thread.join(timeout=2)
        if self.output_thread and self.output_thread.is_alive():
            self.output_thread.join(timeout=2)

        self.logger.info("Resolver path monitoring stopped")

    def _signal_handler(self, signum, frame):
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.stop()

    def _server_worker(self):
        try:
            host, port = "0.0.0.0", self.config.analysis_port
            self.analysis_server = AnalysisServer((host, port), ResolvHandler, self)
            
            self.logger.info(f"Starting analysis server on {host}:{port}")
            self.analysis_server.serve_forever()
            self.logger.info("Analysis server has stopped.")
        except Exception as e:
            self.logger.error(f"Could not start analysis server: {e}")
            self.analysis_server = None

    def _output_worker(self):
        """Dedicated thread to handle outputting completed transactions."""
        self.logger.info("Started output worker.")
        saved_trans = []
        last_save_time = time.time()
        while self.running.is_set() or not self.output_queue.empty():
            try:
                transaction = self.output_queue.get(timeout=1)
                if transaction is None: # Sentinel value
                    break
                
                saved_trans.append(transaction)
                with self.trans_lock:
                    self.trans.append(transaction)
                self._print_summary(transaction)

                if len(saved_trans) >= 10 or (time.time() - last_save_time > 5):
                    self._save_results(saved_trans)
                    saved_trans.clear()
                    last_save_time = time.time()
                    
            except queue.Empty:
                continue # Normal timeout, check running flag
        if saved_trans:
            self._save_results(saved_trans, is_final=True)

        self.logger.info("Output worker stopped.")

    def _processing_worker(self):
        """The core state machine worker thread."""
        self.logger.info("Started processing worker.")
        while self.running.is_set():
            self.logger.info("Waiting for a new client query...")
            initial_query = self._wait_reqs()
            
            if not initial_query: 
                break  # Shutdown signal received

            self.stats['tot_qs'] += 1
            self.logger.info(
                f"{colorize('NEW QUERY DETECTED', Colors.GREEN)}: "
                f"{initial_query.qname} ({initial_query.qtype}) ID:{initial_query.query_id}"
            )
            self.logger.info("Collecting resolution path packets...")
            all_packets = self._collect_all_pkts(initial_query)
            self.logger.info(f"Processing {len(all_packets)} collected packets for the transaction.")
            self._process_pkts(all_packets)

        self.logger.info("Processing worker stopped.")

    def _save_batch(self, transactions: List[DNSTransaction], is_final: bool = False):
        """Saves a batch of transactions"""
        count = len(transactions)
        self.logger.info(f"Output worker: would save a batch of {count} transactions.")
        if is_final:
            self.logger.info("Output worker: performing final save of all results.")
            self._save_results()

    def _save_results(self):
        """Saves final statistics and all captured transactions to a JSON file."""
        try:
            completed_count = self.stats['trans']
            if completed_count > 0:
                self.stats['average_resolution_time'] = self.stats['tot_running'] / completed_count

            results = {
                'config': asdict(self.config),
                'statistics': self.stats,
                'transactions': [t.to_dict() for t in self.trans],
            }
            
            timestamp = get_timestamp()

            path = Path(self.config.output_path)
            path.mkdir(parents=True, exist_ok=True)
            results_file = path / f"resolver_{timestamp}.json"
            save_json(results, results_file)
            self.logger.info(f"Results saved to: {results_file}")
        except Exception as e:
            self.logger.error(f"Failed to save results: {e}")

    def _wait_reqs(self) -> Optional[DNSPacket]:
        """Blocks until an initial client query is found, discarding others."""
        while self.running.is_set():
            try:
                packet = self.packet_queue.get(timeout=1)
                if packet is None: 
                    return None

                if (not packet.is_response and
                    packet.src_ip == self.config.client_ip and
                    packet.dst_ip == self.config.resolver_ip):
                    return packet  # Found the start of a new transaction
                else:
                    self.stats['discarded_qs'] += 1
            except queue.Empty:
                continue
        return None

    def _collect_all_pkts(self, initial_query: DNSPacket) -> List[DNSPacket]:
        """Collects all packets until the final response or a timeout occurs."""
        collected = [initial_query]
        transaction_start_time = time.time()
        
        while self.running.is_set():
            time_elapsed = time.time() - transaction_start_time
            remaining_time = self.config.timeout - time_elapsed
            
            if remaining_time <= 0:
                self.logger.warning(f"Transaction for {initial_query.qname} timed out.")
                self.stats['timeout_trans'] += 1
                break
                
            try:
                packet = self.packet_queue.get(timeout=remaining_time)
                if packet is None: 
                    break
                collected.append(packet)

                if (packet.is_response and
                    packet.src_ip == self.config.resolver_ip and
                    packet.dst_ip == self.config.client_ip and
                    packet.query_id == initial_query.query_id):
                    self.logger.info("Final response received. Transaction captured.")
                    self.stats['trans'] += 1
                    break
            except queue.Empty:
                self.logger.warning(f"Transaction for {initial_query.qname} timed out while waiting for packets.")
                self.stats['timeout_trans'] += 1
                break
        
        return collected

    def _process_pkts(self, packets: List[DNSPacket]):
        """Processes the complete list of packets for one transaction."""
        if not packets: 
            return
            
        initial_query = packets[0]
        transaction = DNSTransaction(initial_query)
        
        final_packet = packets[-1]
        is_completed = (len(packets) > 1 and
                        final_packet.is_response and
                        final_packet.src_ip == self.config.resolver_ip and
                        final_packet.dst_ip == self.config.client_ip and
                        final_packet.query_id == initial_query.query_id)

        # All packets after the first are part of the path
        for packet in packets[1:]:
            transaction.add_resolv_pkt(packet)
            
        if is_completed:
            transaction.complete(final_packet)
            if transaction.duration:
                self.stats['tot_running'] += transaction.duration
        else:
            transaction.timeout()
            
        try:
            self.output_queue.put_nowait(transaction)
        except queue.Full:
            self.logger.error("Output queue is full! A completed transaction was dropped.")

    def _print_summary(self, t: DNSTransaction):
        """Logs a one-line summary of a processed transaction."""
        if t.status == 'COMPLETED':
            rcode_name = RCODE_MAP.get(t.rcode, f"RCODE{t.rcode}")
            self.logger.info(
                f"{colorize('TRANSACTION PROCESSED', Colors.CYAN)}: "
                f"{t.query_name} -> {rcode_name} in {t.duration:.3f}s "
                f"({len(t.resolution_path)} packets in path)"
            )
        else:
            self.logger.warning(
                f"{colorize('TRANSACTION TIMEOUT', Colors.RED)}: "
                f"{t.query_name} after {t.duration:.3f}s. "
                f"Collected {len(t.resolution_path) + 1} packets."
            )

    def _print_info(self):
        print(f"\n{Colors.BOLD}{Colors.CYAN}DNS Resolver Path Monitor{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"Client IP: {colorize(self.config.client_ip, Colors.GREEN)}")
        print(f"Resolver IP: {colorize(self.config.resolver_ip, Colors.GREEN)}")
        print(f"Mode: {colorize('One transaction at a time', Colors.YELLOW)}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}\n")