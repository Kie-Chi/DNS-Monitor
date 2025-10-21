"""
Lightweight DNS Packet implementation with lazy loading
"""

import socket
import time
from typing import Optional, List, Dict, Any, Union, Iterator
from dataclasses import dataclass, field
import dpkt

# --- Packet ---
DNS_TYPE_MAP = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA"
}
RCODE_MAP = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"
}
DNS_PORT = 53


# A type alias for DNSPacket
Packet = 'DNSPacket'

@dataclass(slots=True)
class DNSPacket:
    """DNS packet object with lazy loading"""
    
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str  # "UDP" or "TCP"
    
    # DNS-specific fields
    query_id: int
    is_response: bool
    flags: int
    
    # lazy-loaded fields
    _raw_packet: bytes = field(repr=False)
    _dns_data: bytes = field(repr=False)
    
    # dpkt native objects (cached for performance)
    _dpkt_dns: Optional[dpkt.dns.DNS] = field(default=None, init=False, repr=False)
    _dpkt_eth: Optional[dpkt.ethernet.Ethernet] = field(default=None, init=False, repr=False)
    _dpkt_ip: Optional[dpkt.ip.IP] = field(default=None, init=False, repr=False)
    
    # Lightweight caches (only for frequently accessed data)
    _qname_cache: Optional[str] = field(default=None, init=False, repr=False)
    _qtype_cache: Optional[str] = field(default=None, init=False, repr=False)
    
    @property
    def dpkt_dns(self) -> Optional[dpkt.dns.DNS]:
        """Get dpkt DNS object (lazy loaded)"""
        if self._dpkt_dns is None:
            try:
                self._dpkt_dns = dpkt.dns.DNS(self._dns_data)
            except Exception:
                return None
        return self._dpkt_dns
    
    @property
    def dpkt_eth(self) -> Optional[dpkt.ethernet.Ethernet]:
        """Get dpkt Ethernet object (lazy loaded)"""
        if self._dpkt_eth is None:
            try:
                self._dpkt_eth = dpkt.ethernet.Ethernet(self._raw_packet)
            except Exception:
                return None
        return self._dpkt_eth
    
    @property
    def dpkt_ip(self) -> Optional[dpkt.ip.IP]:
        """Get dpkt IP object (lazy loaded)"""
        if self._dpkt_ip is None and self.dpkt_eth:
            try:
                if isinstance(self.dpkt_eth.data, dpkt.ip.IP):
                    self._dpkt_ip = self.dpkt_eth.data
            except Exception:
                return None
        return self._dpkt_ip
    
    @property
    def qname(self) -> str:
        """Get query name (cached)"""
        if self._qname_cache is None:
            dns = self.dpkt_dns
            if dns and dns.qd:
                try:
                    name = dns.qd[0].name
                    self._qname_cache = name if isinstance(name, str) else name.decode('utf-8', errors='replace')
                except Exception:
                    self._qname_cache = ""
            else:
                self._qname_cache = ""
        return self._qname_cache
    
    @property
    def qtype(self) -> str:
        """Get query type (cached)"""
        if self._qtype_cache is None:
            dns = self.dpkt_dns
            if dns and dns.qd:
                try:
                    self._qtype_cache = self._get_qtype_name(dns.qd[0].type)
                except Exception:
                    self._qtype_cache = ""
            else:
                self._qtype_cache = ""
        return self._qtype_cache
    
    @property
    def rcode(self) -> int:
        """Get response code"""
        dns = self.dpkt_dns
        return dns.rcode if dns else 0
    
    @property
    def questions(self) -> Iterator[dpkt.dns.DNS.Q]:
        """Get questions iterator"""
        dns = self.dpkt_dns
        if dns and dns.qd:
            yield from dns.qd
    
    @property
    def answers(self) -> Iterator[dpkt.dns.DNS.RR]:
        """Get answers iterator"""
        dns = self.dpkt_dns
        if dns and dns.an:
            yield from dns.an
    
    @property
    def authorities(self) -> Iterator[dpkt.dns.DNS.RR]:
        """Get authorities iterator"""
        dns = self.dpkt_dns
        if dns and dns.ns:
            yield from dns.ns
    
    @property
    def additionals(self) -> Iterator[dpkt.dns.DNS.RR]:
        """Get additionals iterator"""
        dns = self.dpkt_dns
        if dns and dns.ar:
            yield from dns.ar
    
    @property
    def raw_packet(self) -> bytes:
        """Get raw packet data"""
        return self._raw_packet
    
    def get_question_dict(self, q: dpkt.dns.DNS.Q) -> Dict[str, Any]:
        """Convert question to dictionary"""
        try:
            name = q.name if isinstance(q.name, str) else q.name.decode('utf-8', errors='replace')
            return {
                'name': name,
                'type': self._get_qtype_name(q.type),
                'class': q.cls
            }
        except Exception:
            return {'name': '', 'type': '', 'class': 0}

    def get_rr_dict(self, rr: dpkt.dns.DNS.RR) -> Dict[str, Any]:
        """Convert resource record to dictionary with optimized parsing"""
        try:
            name = rr.name if isinstance(rr.name, str) else rr.name.decode('utf-8', errors='replace')
            rr_type = self._get_qtype_name(rr.type)
            
            # basic fields
            result = {
                'name': name,
                'type': rr_type,
                'class': rr.cls,
                'ttl': rr.ttl,
                'rdata': {}
            }
            
            # parse rdata based on type
            try:
                if rr.type == dpkt.dns.DNS_A:  # A
                    if len(rr.rdata) == 4:
                        result['rdata']['address'] = socket.inet_ntoa(rr.rdata)
                elif rr.type == dpkt.dns.DNS_AAAA:  # AAAA
                    if len(rr.rdata) == 16:
                        result['rdata']['address'] = socket.inet_ntop(socket.AF_INET6, rr.rdata)
                elif rr.type == dpkt.dns.DNS_CNAME:  # CNAME
                    cname = rr.cname if isinstance(rr.cname, str) else rr.cname.decode('utf-8', errors='replace')
                    result['rdata']['cname'] = cname
                elif rr.type == dpkt.dns.DNS_MX:  # MX
                    exchange = rr.mxname if isinstance(rr.mxname, str) else rr.mxname.decode('utf-8', errors='replace')
                    result['rdata'] = {'preference': rr.preference, 'exchange': exchange}
                elif rr.type == dpkt.dns.DNS_NS:  # NS
                    nsname = rr.nsname if isinstance(rr.nsname, str) else rr.nsname.decode('utf-8', errors='replace')
                    result['rdata']['nsname'] = nsname
                elif rr.type == dpkt.dns.DNS_PTR:  # PTR
                    ptrname = rr.ptrname if isinstance(rr.ptrname, str) else rr.ptrname.decode('utf-8', errors='replace')
                    result['rdata']['ptrname'] = ptrname
                elif rr.type == dpkt.dns.DNS_SOA:  # SOA
                    mname = rr.mname if isinstance(rr.mname, str) else rr.mname.decode('utf-8', errors='replace')
                    rname = rr.rname if isinstance(rr.rname, str) else rr.rname.decode('utf-8', errors='replace')
                    result['rdata'] = {
                        'mname': mname, 'rname': rname, 'serial': rr.serial,
                        'refresh': rr.refresh, 'retry': rr.retry, 'expire': rr.expire, 'minimum': rr.minimum
                    }
                elif rr.type == dpkt.dns.DNS_TXT:  # TXT
                    try:
                        if hasattr(rr, 'text') and rr.text:
                            if isinstance(rr.text, list):
                                if rr.text and isinstance(rr.text[0], str):
                                    text = ''.join(rr.text)
                                else:
                                    text = b''.join(rr.text).decode('utf-8', errors='replace')
                            else:
                                text = rr.text if isinstance(rr.text, str) else rr.text.decode('utf-8', errors='replace')
                            result['rdata']['text'] = text
                        else:
                            if rr.rdata and len(rr.rdata) > 0:
                                text_parts = []
                                offset = 0
                                while offset < len(rr.rdata):
                                    if offset >= len(rr.rdata):
                                        break
                                    length = rr.rdata[offset]
                                    if length == 0 or offset + 1 + length > len(rr.rdata):
                                        break
                                    text_part = rr.rdata[offset + 1:offset + 1 + length]
                                    text_parts.append(text_part.decode('utf-8', errors='replace'))
                                    offset += 1 + length
                                result['rdata']['text'] = ''.join(text_parts)
                            else:
                                result['rdata']['text'] = ""
                    except Exception:
                        result['rdata']['text'] = ""
                else:
                    result['rdata']['raw'] = rr.rdata.hex() if rr.rdata else ""
                    
            except Exception:
                # parse error, mark as UNKNOWN
                result['rdata'] = "UNKNOWN {}"
                
            return result
            
        except Exception:
            return {
                'name': '', 'type': '', 'class': 0, 'ttl': 0, 'rdata': {}
            }

    def get_questions_list(self) -> List[Dict[str, Any]]:
        """Get questions as list of dictionaries"""
        return [self.get_question_dict(q) for q in self.questions]

    def get_answers_list(self) -> List[Dict[str, Any]]:
        """Get answers as list of dictionaries"""
        return [self.get_rr_dict(rr) for rr in self.answers]

    def get_authorities_list(self) -> List[Dict[str, Any]]:
        """Get authorities as list of dictionaries"""
        return [self.get_rr_dict(rr) for rr in self.authorities]

    def get_additionals_list(self) -> List[Dict[str, Any]]:
        """Get additionals as list of dictionaries"""
        return [self.get_rr_dict(rr) for rr in self.additionals]

    def _get_qtype_name(self, qtype: int) -> str:
        """Get DNS query type name - optimized version"""
        return DNS_TYPE_MAP.get(qtype, f"TYPE{qtype}")

    def to_dict(self) -> Dict[str, Any]:
        """Convert packet to dictionary"""
        return {
            'timestamp': self.timestamp,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'query_id': self.query_id,
            'is_response': self.is_response,
            'flags': self.flags,
            'qname': self.qname,
            'qtype': self.qtype,
            'rcode': self.rcode,
            'questions': self.get_questions_list(),
            'answers': self.get_answers_list(),
            'authorities': self.get_authorities_list(),
            'additionals': self.get_additionals_list()
        }

    def __str__(self) -> str:
        """String representation"""
        direction = "Response" if self.is_response else "Query"
        rcode_str = f" ({self._get_rcode_name(self.rcode)})" if self.is_response else ""
        return f"{self.timestamp:.6f} {self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} " \
               f"{self.protocol} DNS {direction} ID:{self.query_id} {self.qname} {self.qtype}{rcode_str}"

    def _get_rcode_name(self, rcode: int) -> str:
        """Get response code name - optimized version"""
        return RCODE_MAP.get(rcode, f"RCODE{rcode}")


class DNSAnalyzer:
    """Basic DNS analyzer using dpkt"""
    
    def __init__(self):
        self.stats = {
            'total_packets': 0,
            'dns_packets': 0,
            'parse_errors': 0,
            'dpkt_unpack_calls': 0
        }
    
    def analyze_packet(self, timestamp: float, packet_data: bytes) -> Optional[DNSPacket]:
        """Analyze packet using dpkt's efficient unpack methods"""
        try:
            self.stats['total_packets'] += 1
            try:
                eth = dpkt.ethernet.Ethernet(packet_data)
                self.stats['dpkt_unpack_calls'] += 1
            except (dpkt.UnpackError, dpkt.NeedData):
                return None
            if not isinstance(eth.data, dpkt.ip.IP):
                return None
            ip = eth.data
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)
            dns_data = None
            protocol = None
            src_port = dst_port = 0
            
            if isinstance(ip.data, dpkt.udp.UDP):
                udp = ip.data
                if udp.sport != DNS_PORT and udp.dport != DNS_PORT:
                    return None
                src_port, dst_port = udp.sport, udp.dport
                protocol = "UDP"
                dns_data = udp.data
            elif isinstance(ip.data, dpkt.tcp.TCP):
                tcp = ip.data
                if tcp.sport != DNS_PORT and tcp.dport != DNS_PORT:
                    return None
                src_port, dst_port = tcp.sport, tcp.dport
                protocol = "TCP"
                if len(tcp.data) >= 2:
                    dns_data = tcp.data[2:]
                else:
                    return None
            else:
                return None
            
            if not dns_data or len(dns_data) < 12:
                return None
            
            try:
                dns_header = dpkt.dns.DNS(dns_data)
                self.stats['dpkt_unpack_calls'] += 1
            except (dpkt.UnpackError, dpkt.NeedData):
                return None
            
            query_id = dns_header.id
            flags = (dns_header.qr << 15) | (dns_header.opcode << 11) | \
                   (dns_header.aa << 10) | (dns_header.tc << 9) | \
                   (dns_header.rd << 8) | (dns_header.ra << 7) | dns_header.rcode
            is_response = dns_header.qr == 1
            
            self.stats['dns_packets'] += 1
            
            return DNSPacket(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                query_id=query_id,
                is_response=is_response,
                flags=flags,
                _raw_packet=packet_data,
                _dns_data=dns_data
            )
            
        except Exception:
            self.stats['parse_errors'] += 1
            return None
    
    def get_stats(self) -> Dict[str, Any]:
        """Get analyzer statistics"""
        stats = self.stats.copy()
        if stats['total_packets'] > 0:
            stats['dns_packet_ratio'] = stats['dns_packets'] / stats['total_packets']
            stats['error_ratio'] = stats['parse_errors'] / stats['total_packets']
        return stats


class OptimizedDNSAnalyzer(DNSAnalyzer):
    """Optimized DNS analyzer with fast path and slow path"""
    
    def __init__(self):
        super().__init__()
        # Pre-allocate buffer for IP addresses
        self._ip_buffer = bytearray(4)
        self.stats.update({
            'fast_path_hits': 0,
            'slow_path_hits': 0,
            'header_parse_time': 0.0,
            'total_parse_time': 0.0
        })
    
    def analyze_packet(self, timestamp: float, packet_data: bytes) -> Optional[DNSPacket]:
        """Optimized packet analysis"""
        start_time = time.perf_counter()
        
        try:
            self.stats['total_packets'] += 1
            
            if len(packet_data) >= 42:
                try:
                    if packet_data[12:14] != b'\x08\x00':
                        return None
                    
                    if packet_data[23] != 17:
                        if packet_data[23] != 6:
                            return None
                        return self._parse_tcp_packet(timestamp, packet_data, start_time)
                    return self._parse_udp_packet_fast(timestamp, packet_data, start_time)
                    
                except Exception:
                    # parse error, pass
                    pass
            
            # dpkt slow path
            return self._parse_packet_slow(timestamp, packet_data, start_time)
            
        except Exception:
            self.stats['parse_errors'] += 1
            return None
        finally:
            self.stats['total_parse_time'] += time.perf_counter() - start_time
    
    def _parse_udp_packet_fast(self, timestamp: float, packet_data: bytes, start_time: float) -> Optional[DNSPacket]:
        """fast path for udp packet"""
        try:
            # extract ip addresses
            src_ip_bytes = packet_data[26:30]
            dst_ip_bytes = packet_data[30:34]
            
            # extract udp ports
            src_port = int.from_bytes(packet_data[34:36], 'big')
            dst_port = int.from_bytes(packet_data[36:38], 'big')
            
            # check if dns port
            if src_port != DNS_PORT and dst_port != DNS_PORT:
                return None
            
            # extract dns data
            udp_length = int.from_bytes(packet_data[38:40], 'big')
            dns_start = 42
            dns_data = packet_data[dns_start:dns_start + udp_length - 8]
            
            if len(dns_data) < 12:
                return None
            
            # fast parse dns header
            header_parse_start = time.perf_counter()
            query_id = int.from_bytes(dns_data[0:2], 'big')
            flags_raw = int.from_bytes(dns_data[2:4], 'big')
            is_response = (flags_raw & 0x8000) != 0
            
            self.stats['header_parse_time'] += time.perf_counter() - header_parse_start
            self.stats['fast_path_hits'] += 1
            self.stats['dns_packets'] += 1
            
            return DNSPacket(
                timestamp=timestamp,
                src_ip=socket.inet_ntoa(src_ip_bytes),
                dst_ip=socket.inet_ntoa(dst_ip_bytes),
                src_port=src_port,
                dst_port=dst_port,
                protocol="UDP",
                query_id=query_id,
                is_response=is_response,
                flags=flags_raw,
                _raw_packet=packet_data,
                _dns_data=dns_data
            )
            
        except Exception:
            # parse error, pass
            return self._parse_packet_slow(timestamp, packet_data, start_time)
    
    def _parse_tcp_packet(self, timestamp: float, packet_data: bytes, start_time: float) -> Optional[DNSPacket]:
        """TCP packet parse (usually less frequent, use slow path)"""
        return self._parse_packet_slow(timestamp, packet_data, start_time)
    
    def _parse_packet_slow(self, timestamp: float, packet_data: bytes, start_time: float) -> Optional[DNSPacket]:
        """slow path: complete dpkt parse"""
        self.stats['slow_path_hits'] += 1
        return super().analyze_packet(timestamp, packet_data)
    
    def get_stats(self) -> Dict[str, Any]:
        """get optimized analyzer stats"""
        stats = super().get_stats()
        
        # add performance stats
        if self.stats['total_packets'] > 0:
            stats.update({
                'fast_path_ratio': self.stats['fast_path_hits'] / self.stats['total_packets'],
                'slow_path_ratio': self.stats['slow_path_hits'] / self.stats['total_packets'],
                'avg_parse_time_us': (self.stats['total_parse_time'] * 1000000) / self.stats['total_packets'],
                'avg_header_parse_time_us': (self.stats['header_parse_time'] * 1000000) / max(1, self.stats['fast_path_hits'])
            })
        
        return stats