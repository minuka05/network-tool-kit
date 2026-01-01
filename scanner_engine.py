"""
Port Scanner Engine - Core scanning functionality
Supports TCP Connect, SYN, and UDP scans
"""

import socket
import struct
import threading
from enum import Enum
from datetime import datetime
from queue import Queue
import time
import logging

# Suppress Scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
    from scapy.all import sr1, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logging.warning("Scapy not available. SYN and advanced scans will be limited.")


class ScanType(Enum):
    """Enumeration of supported scan types"""
    TCP_CONNECT = "tcp_connect"
    SYN_SCAN = "syn_scan"
    ACK_SCAN = "ack_scan"
    FIN_SCAN = "fin_scan"
    XMAS_SCAN = "xmas_scan"
    NULL_SCAN = "null_scan"
    UDP_SCAN = "udp_scan"
    WINDOW_SCAN = "window_scan"


class PortScanner:
    """
    Advanced port scanner with multiple scan types and service detection
    """
    
    # Common service/port mappings
    COMMON_SERVICES = {
        20: 'ftp-data',
        21: 'ftp',
        22: 'ssh',
        23: 'telnet',
        25: 'smtp',
        53: 'dns',
        67: 'dhcp',
        68: 'dhcp',
        69: 'tftp',
        80: 'http',
        110: 'pop3',
        123: 'ntp',
        135: 'msrpc',
        137: 'netbios-ns',
        138: 'netbios-dgm',
        139: 'netbios-ssn',
        143: 'imap',
        161: 'snmp',
        162: 'snmp-trap',
        389: 'ldap',
        443: 'https',
        445: 'microsoft-ds',
        465: 'smtps',
        514: 'syslog',
        587: 'smtp',
        636: 'ldaps',
        993: 'imaps',
        995: 'pop3s',
        1433: 'mssql',
        1521: 'oracle',
        1723: 'pptp',
        3306: 'mysql',
        3389: 'rdp',
        5432: 'postgresql',
        5900: 'vnc',
        6379: 'redis',
        8080: 'http-proxy',
        8443: 'https-alt',
        9090: 'openfire',
        27017: 'mongodb',
    }
    
    # Educational Vulnerability Database
    VULN_DB = {
        21: "FTP: Plaintext credentials risk. Anonymous login often enabled.",
        23: "Telnet: Unencrypted communication. Credentials sent in plaintext.",
        25: "SMTP: Open relay risk if misconfigured. User enumeration possible.",
        53: "DNS: Zone transfer risk if misconfigured. DDoS amplification source.",
        80: "HTTP: Unencrypted web traffic. Check for outdated server software.",
        110: "POP3: Plaintext authentication. Use POP3S (995) instead.",
        135: "RPC: High risk target. Often vulnerable to enumeration/exploitation.",
        139: "NetBIOS: Information leakage (Usernames, Shares).",
        143: "IMAP: Plaintext authentication. Use IMAPS (993) instead.",
        445: "SMB: High risk (EternalBlue etc). Ensure SMBv1 is disabled.",
        3306: "MySQL: Database exposed. Brute-force risk.",
        3389: "RDP: Remote Desktop exposed. High brute-force/exploit risk.",
        5432: "PostgreSQL: Database exposed. Brute-force risk.",
        5900: "VNC: Remote access exposed. Often weak passwords.",
        6379: "Redis: Often no authentication. RCE risk if exposed.",
        27017: "MongoDB: Often no authentication. Data leak risk.",
    }
    
    def __init__(self, target, ports, scan_type=ScanType.TCP_CONNECT,
                 threads=100, timeout=1.0, service_detection=True):
        """
        Initialize the port scanner
        
        Args:
            target: IP address or hostname to scan
            ports: List of ports to scan
            scan_type: Type of scan to perform
            threads: Number of concurrent threads
            timeout: Socket timeout in seconds
            service_detection: Enable service version detection
        """
        self.target = target
        self.ports = ports
        self.scan_type = scan_type
        self.max_threads = threads
        self.timeout = timeout
        self.service_detection = service_detection
        
        # Results storage
        self.results = []
        self.lock = threading.Lock()
        
        # Control flags
        self.stop_flag = False
        
        # Progress tracking
        self.scanned_count = 0
        self.total_ports = len(ports)
        
        # Resolve target to IP
        self.target_ip = self._resolve_target()
        
        logging.info(f"Scanner initialized for {target} ({self.target_ip})")
    
    def _resolve_target(self):
        """Resolve hostname to IP address"""
        try:
            return socket.gethostbyname(self.target)
        except socket.gaierror as e:
            logging.error(f"Failed to resolve {self.target}: {e}")
            raise ValueError(f"Cannot resolve target: {self.target}")
    
    def scan(self, progress_callback=None):
        """
        Execute the port scan
        
        Args:
            progress_callback: Optional callback function for progress updates
            
        Returns:
            List of scan results
        """
        logging.info(f"Starting {self.scan_type.value} scan on {self.target_ip}")
        start_time = time.time()
        
        # Create work queue
        work_queue = Queue()
        for port in self.ports:
            work_queue.put(port)
        
        # Start worker threads
        threads = []
        for _ in range(min(self.max_threads, len(self.ports))):
            t = threading.Thread(
                target=self._worker,
                args=(work_queue, progress_callback),
                daemon=True
            )
            t.start()
            threads.append(t)
        
        # Wait for completion
        for t in threads:
            t.join()
        
        # Sort results by port number
        self.results.sort(key=lambda x: x['port'])
        
        elapsed = time.time() - start_time
        logging.info(f"Scan completed in {elapsed:.2f} seconds")
        
        return self.results
    
    def _worker(self, work_queue, progress_callback):
        """Worker thread function"""
        while not work_queue.empty() and not self.stop_flag:
            try:
                port = work_queue.get(timeout=0.1)
            except:
                break
            
            # Perform scan based on type
            if self.scan_type == ScanType.TCP_CONNECT:
                result = self._tcp_connect_scan(port)
            elif self.scan_type == ScanType.SYN_SCAN:
                result = self._syn_scan(port)
            elif self.scan_type == ScanType.ACK_SCAN:
                result = self._ack_scan(port)
            elif self.scan_type == ScanType.FIN_SCAN:
                result = self._fin_scan(port)
            elif self.scan_type == ScanType.XMAS_SCAN:
                result = self._xmas_scan(port)
            elif self.scan_type == ScanType.NULL_SCAN:
                result = self._null_scan(port)
            elif self.scan_type == ScanType.WINDOW_SCAN:
                result = self._window_scan(port)
            elif self.scan_type == ScanType.UDP_SCAN:
                result = self._udp_scan(port)
            else:
                result = {'port': port, 'status': 'unknown'}
            
            # Add service detection if enabled and port is open
            if self.service_detection and result['status'] in ['open', 'open|filtered']:
                self._detect_service(result)
            
            # Store result
            with self.lock:
                self.results.append(result)
                self.scanned_count += 1
                
                # Call progress callback
                if progress_callback:
                    progress_callback(self.scanned_count, self.total_ports)
            
            work_queue.task_done()
    
    def _tcp_connect_scan(self, port):
        """
        TCP Connect scan - Completes three-way handshake
        Most reliable but also most detectable
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        
        try:
            result = sock.connect_ex((self.target_ip, port))
            if result == 0:
                status = 'open'
            else:
                status = 'closed'
        except socket.timeout:
            status = 'filtered'
        except socket.error:
            status = 'filtered'
        finally:
            sock.close()
        
        return {
            'port': port,
            'status': status,
            'service': self.COMMON_SERVICES.get(port, 'unknown')
        }
    
    def _syn_scan(self, port):
        """
        SYN scan (half-open scan) - Requires admin/root privileges
        Stealthier than TCP connect scan
        """
        if not SCAPY_AVAILABLE:
            logging.warning(f"Scapy not available, falling back to TCP connect for port {port}")
            return self._tcp_connect_scan(port)
        
        try:
            # Send SYN packet
            packet = IP(dst=self.target_ip) / TCP(dport=port, flags='S')
            response = sr1(packet, timeout=self.timeout, verbose=0)
            
            if response is None:
                status = 'filtered'
            elif response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x12:  # SYN-ACK
                    # Send RST to close connection
                    rst_packet = IP(dst=self.target_ip) / TCP(dport=port, flags='R')
                    sr1(rst_packet, timeout=self.timeout, verbose=0)
                    status = 'open'
                elif response.getlayer(TCP).flags == 0x14:  # RST-ACK
                    status = 'closed'
                else:
                    status = 'filtered'
            elif response.haslayer(ICMP):
                status = 'filtered'
            else:
                status = 'unknown'
        
        except PermissionError:
            logging.error("SYN scan requires administrator/root privileges")
            return self._tcp_connect_scan(port)
        except Exception as e:
            logging.error(f"SYN scan error on port {port}: {e}")
            status = 'error'
        
        return {
            'port': port,
            'status': status,
            'service': self.COMMON_SERVICES.get(port, 'unknown')
        }
    
    def _udp_scan(self, port):
        """
        UDP scan - Slower and less reliable than TCP
        """
        if SCAPY_AVAILABLE:
            try:
                # Send UDP packet
                packet = IP(dst=self.target_ip) / UDP(dport=port)
                response = sr1(packet, timeout=self.timeout, verbose=0)
                
                if response is None:
                    # No response could mean open or filtered
                    status = 'open|filtered'
                elif response.haslayer(ICMP):
                    icmp_type = response.getlayer(ICMP).type
                    icmp_code = response.getlayer(ICMP).code
                    if icmp_type == 3 and icmp_code == 3:  # Port unreachable
                        status = 'closed'
                    else:
                        status = 'filtered'
                elif response.haslayer(UDP):
                    status = 'open'
                else:
                    status = 'unknown'
            except Exception as e:
                logging.error(f"UDP scan error on port {port}: {e}")
                status = 'error'
        else:
            # Fallback UDP scan without scapy
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            try:
                sock.sendto(b'', (self.target_ip, port))
                try:
                    data, addr = sock.recvfrom(1024)
                    status = 'open'
                except socket.timeout:
                    status = 'open|filtered'
            except socket.error:
                status = 'filtered'
            finally:
                sock.close()
        
        return {
            'port': port,
            'status': status,
            'service': self.COMMON_SERVICES.get(port, 'unknown')
        }
    
    def _ack_scan(self, port):
        """
        ACK scan - Firewall detection
        Used to determine if ports are filtered by a firewall
        """
        if not SCAPY_AVAILABLE:
            logging.warning(f"Scapy not available, falling back to TCP connect for port {port}")
            return self._tcp_connect_scan(port)
        
        try:
            # Send ACK packet
            packet = IP(dst=self.target_ip) / TCP(dport=port, flags='A')
            response = sr1(packet, timeout=self.timeout, verbose=0)
            
            if response is None:
                status = 'filtered'
            elif response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x04:  # RST
                    status = 'unfiltered'
                else:
                    status = 'filtered'
            elif response.haslayer(ICMP):
                status = 'filtered'
            else:
                status = 'filtered'
        
        except Exception as e:
            logging.error(f"ACK scan error on port {port}: {e}")
            status = 'error'
        
        return {
            'port': port,
            'status': status,
            'service': self.COMMON_SERVICES.get(port, 'unknown')
        }
    
    def _fin_scan(self, port):
        """
        FIN scan - Stealth scan technique
        Sends FIN flag, open ports ignore it, closed ports send RST
        """
        if not SCAPY_AVAILABLE:
            logging.warning(f"Scapy not available, falling back to TCP connect for port {port}")
            return self._tcp_connect_scan(port)
        
        try:
            # Send FIN packet
            packet = IP(dst=self.target_ip) / TCP(dport=port, flags='F')
            response = sr1(packet, timeout=self.timeout, verbose=0)
            
            if response is None:
                status = 'open|filtered'
            elif response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x14:  # RST-ACK
                    status = 'closed'
                else:
                    status = 'open|filtered'
            elif response.haslayer(ICMP):
                icmp_type = response.getlayer(ICMP).type
                icmp_code = response.getlayer(ICMP).code
                if icmp_type == 3 and icmp_code in [1, 2, 3, 9, 10, 13]:
                    status = 'filtered'
                else:
                    status = 'open|filtered'
            else:
                status = 'open|filtered'
        
        except Exception as e:
            logging.error(f"FIN scan error on port {port}: {e}")
            status = 'error'
        
        return {
            'port': port,
            'status': status,
            'service': self.COMMON_SERVICES.get(port, 'unknown')
        }
    
    def _xmas_scan(self, port):
        """
        Xmas scan - Sets FIN, PSH, and URG flags
        Named because packet is "lit up like a Christmas tree"
        """
        if not SCAPY_AVAILABLE:
            logging.warning(f"Scapy not available, falling back to TCP connect for port {port}")
            return self._tcp_connect_scan(port)
        
        try:
            # Send packet with FIN, PSH, URG flags
            packet = IP(dst=self.target_ip) / TCP(dport=port, flags='FPU')
            response = sr1(packet, timeout=self.timeout, verbose=0)
            
            if response is None:
                status = 'open|filtered'
            elif response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x14:  # RST-ACK
                    status = 'closed'
                else:
                    status = 'open|filtered'
            elif response.haslayer(ICMP):
                icmp_type = response.getlayer(ICMP).type
                icmp_code = response.getlayer(ICMP).code
                if icmp_type == 3 and icmp_code in [1, 2, 3, 9, 10, 13]:
                    status = 'filtered'
                else:
                    status = 'open|filtered'
            else:
                status = 'open|filtered'
        
        except Exception as e:
            logging.error(f"Xmas scan error on port {port}: {e}")
            status = 'error'
        
        return {
            'port': port,
            'status': status,
            'service': self.COMMON_SERVICES.get(port, 'unknown')
        }
    
    def _null_scan(self, port):
        """
        NULL scan - Sends packet with no flags set
        More stealthy than other techniques
        """
        if not SCAPY_AVAILABLE:
            logging.warning(f"Scapy not available, falling back to TCP connect for port {port}")
            return self._tcp_connect_scan(port)
        
        try:
            # Send packet with no flags
            packet = IP(dst=self.target_ip) / TCP(dport=port, flags='')
            response = sr1(packet, timeout=self.timeout, verbose=0)
            
            if response is None:
                status = 'open|filtered'
            elif response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x14:  # RST-ACK
                    status = 'closed'
                else:
                    status = 'open|filtered'
            elif response.haslayer(ICMP):
                icmp_type = response.getlayer(ICMP).type
                icmp_code = response.getlayer(ICMP).code
                if icmp_type == 3 and icmp_code in [1, 2, 3, 9, 10, 13]:
                    status = 'filtered'
                else:
                    status = 'open|filtered'
            else:
                status = 'open|filtered'
        
        except Exception as e:
            logging.error(f"NULL scan error on port {port}: {e}")
            status = 'error'
        
        return {
            'port': port,
            'status': status,
            'service': self.COMMON_SERVICES.get(port, 'unknown')
        }
    
    def _window_scan(self, port):
        """
        Window scan - Similar to ACK scan but examines TCP window field
        Can sometimes distinguish open vs closed on some systems
        """
        if not SCAPY_AVAILABLE:
            logging.warning(f"Scapy not available, falling back to TCP connect for port {port}")
            return self._tcp_connect_scan(port)
        
        try:
            # Send ACK packet and examine window
            packet = IP(dst=self.target_ip) / TCP(dport=port, flags='A')
            response = sr1(packet, timeout=self.timeout, verbose=0)
            
            if response is None:
                status = 'filtered'
            elif response.haslayer(TCP):
                if response.getlayer(TCP).window > 0:
                    status = 'open'
                elif response.getlayer(TCP).flags == 0x04:  # RST
                    status = 'closed'
                else:
                    status = 'filtered'
            elif response.haslayer(ICMP):
                status = 'filtered'
            else:
                status = 'filtered'
        
        except Exception as e:
            logging.error(f"Window scan error on port {port}: {e}")
            status = 'error'
        
        return {
            'port': port,
            'status': status,
            'service': self.COMMON_SERVICES.get(port, 'unknown')
        }
    
    def _detect_service(self, result):
        """
        Attempt to detect service version by banner grabbing
        """
        port = result['port']
        
        # Only attempt banner grabbing for TCP ports
        if self.scan_type == ScanType.UDP_SCAN:
            return
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        
        try:
            sock.connect((self.target_ip, port))
            
            # Send probe based on common ports
            if port in [80, 8080, 8000, 8008]:
                # HTTP Probe
                sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
            elif port in [21, 22, 25, 110, 143]:
                # These services typically send banner on connect
                pass
            else:
                # Generic probe
                sock.send(b'HELP\r\n')
            
            # Receive banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            
            if banner:
                # Special handling for HTTP Server header
                if port in [80, 8080, 8000, 8008] and 'Server:' in banner:
                    for line in banner.split('\r\n'):
                        if line.startswith('Server:'):
                            banner = line.replace('Server:', '').strip()
                            break
                
                # Extract version info from banner
                result['banner'] = banner[:200]  # Limit banner length
                result['version'] = self._extract_version(banner)
                
                # Update service name from banner if more specific
                service_name = self._identify_service(banner)
                if service_name:
                    result['service'] = service_name
            
            # Check for vulnerabilities
            if port in self.VULN_DB:
                result['vuln_info'] = self.VULN_DB[port]
        
        except socket.timeout:
            pass
        except socket.error:
            pass
        except Exception as e:
            logging.debug(f"Service detection error on port {port}: {e}")
        finally:
            sock.close()
    
    def _extract_version(self, banner):
        """Extract version information from banner"""
        # Simple version extraction - looks for common patterns
        import re
        
        # Common version patterns
        patterns = [
            r'(\d+\.\d+\.\d+)',  # x.y.z
            r'(\d+\.\d+)',        # x.y
            r'version\s+(\S+)',   # version xxx
            r'v(\d+\.\d+)',       # vx.y
        ]
        
        for pattern in patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return ''
    
    def _identify_service(self, banner):
        """Identify service from banner"""
        banner_lower = banner.lower()
        
        # Service identification patterns
        services = {
            'ssh': 'ssh',
            'ftp': 'ftp',
            'smtp': 'smtp',
            'pop3': 'pop3',
            'imap': 'imap',
            'http': 'http',
            'https': 'https',
            'mysql': 'mysql',
            'postgresql': 'postgresql',
            'redis': 'redis',
            'mongodb': 'mongodb',
            'apache': 'apache',
            'nginx': 'nginx',
            'microsoft': 'microsoft-httpd',
        }
        
        for keyword, service in services.items():
            if keyword in banner_lower:
                return service
        
        return None
    
    def stop(self):
        """Stop the scan"""
        self.stop_flag = True
        logging.info("Scan stop requested")


class QuickScanner:
    """
    Quick scanner for common ports
    """
    
    COMMON_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
        993, 995, 1723, 3306, 3389, 5900, 8080
    ]
    
    @staticmethod
    def scan_common_ports(target, timeout=1.0):
        """Quick scan of common ports"""
        scanner = PortScanner(
            target=target,
            ports=QuickScanner.COMMON_PORTS,
            scan_type=ScanType.TCP_CONNECT,
            threads=50,
            timeout=timeout,
            service_detection=True
        )
        return scanner.scan()
