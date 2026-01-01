"""
IP Intelligence and Host Discovery Module
Provides information about target hosts and network discovery
"""

import socket
import struct
import platform
import subprocess
import logging
from typing import Dict, Optional, List

# Suppress Scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
    from scapy.all import sr1, IP, ICMP, TCP, UDP, ARP, Ether, srp
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class HostDiscovery:
    """Host discovery and reachability checking"""
    
    @staticmethod
    def ping_check(target: str, timeout: float = 2.0) -> Dict:
        """
        Check if host is alive using ICMP ping
        
        Args:
            target: Target IP address or hostname
            timeout: Timeout in seconds
            
        Returns:
            Dictionary with status and RTT
        """
        result = {
            'alive': False,
            'rtt': None,
            'method': 'icmp'
        }
        
        if SCAPY_AVAILABLE:
            try:
                # Send ICMP echo request
                packet = IP(dst=target) / ICMP()
                reply = sr1(packet, timeout=timeout, verbose=0)
                
                if reply:
                    result['alive'] = True
                    result['rtt'] = (reply.time - packet.sent_time) * 1000  # ms
                    return result
            except Exception as e:
                logging.debug(f"Scapy ping failed: {e}")
        
        # Fallback to system ping
        try:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            command = ['ping', param, '1', '-w' if platform.system().lower() == 'windows' else '-W', 
                      str(int(timeout)), target]
            
            output = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout + 1
            )
            
            if output.returncode == 0:
                result['alive'] = True
                # Try to extract RTT from output
                output_str = output.stdout.decode('utf-8', errors='ignore')
                if 'time=' in output_str:
                    try:
                        rtt_str = output_str.split('time=')[1].split()[0].replace('ms', '')
                        result['rtt'] = float(rtt_str)
                    except:
                        pass
        
        except Exception as e:
            logging.debug(f"System ping failed: {e}")
        
        return result
    
    @staticmethod
    def get_geoip_info(ip: str) -> Dict:
        """
        Get GeoIP information for an IP address using ip-api.com (free)
        """
        import json
        import urllib.request
        
        result = {
            'country': 'Unknown',
            'isp': 'Unknown',
            'city': 'Unknown',
            'org': 'Unknown'
        }
        
        # Skip private IPs
        if ip.startswith(('192.168.', '10.', '127.', '172.16.', '172.17.', '172.18.', '172.19.', '172.2', '172.3')):
            result['country'] = 'Local Network'
            result['isp'] = 'Private IP'
            return result
            
        try:
            url = f"http://ip-api.com/json/{ip}"
            with urllib.request.urlopen(url, timeout=3) as response:
                data = json.loads(response.read().decode())
                if data.get('status') == 'success':
                    result['country'] = data.get('country', 'Unknown')
                    result['isp'] = data.get('isp', 'Unknown')
                    result['city'] = data.get('city', 'Unknown')
                    result['org'] = data.get('org', 'Unknown')
        except Exception as e:
            logging.debug(f"GeoIP lookup failed: {e}")
            
        return result

    @staticmethod
    def traceroute_hop(target_ip: str, ttl: int, method: str = "ICMP", timeout: float = 2.0) -> Dict:
        """
        Perform a single hop traceroute
        """
        import time
        result = {
            'hop': ttl,
            'ip': '*',
            'hostname': '*',
            'loss': '100%',
            'rtt': '*',
            'status': 'Timeout'
        }
        
        if SCAPY_AVAILABLE:
            try:
                pkt = IP(dst=target_ip, ttl=ttl)
                if method == "ICMP":
                    pkt /= ICMP()
                elif method == "TCP":
                    pkt /= TCP(dport=80, flags="S")
                elif method == "UDP":
                    pkt /= UDP(dport=33434)
                
                start_time = time.time()
                reply = sr1(pkt, verbose=0, timeout=timeout)
                end_time = time.time()
                
                if reply:
                    result['ip'] = reply.src
                    result['rtt'] = f"{(end_time - start_time) * 1000:.2f}"
                    result['loss'] = '0%'
                    result['status'] = 'Reached'
                    
                    try:
                        result['hostname'] = socket.gethostbyaddr(reply.src)[0]
                    except:
                        result['hostname'] = reply.src
                        
                    if reply.src == target_ip:
                        result['status'] = 'Destination Reached'
                    elif reply.haslayer(ICMP):
                        if reply.getlayer(ICMP).type == 11: # Time Exceeded
                            result['status'] = 'Transit'
            except Exception as e:
                logging.debug(f"Scapy traceroute failed: {e}")
        
        # Fallback to system ping if Scapy failed or didn't find anything and method is ICMP
        if result['ip'] == '*' and method == "ICMP":
            try:
                import re
                # Windows specific ping command
                if platform.system().lower() == 'windows':
                    # -n 1: count 1, -w: timeout in ms, -i: TTL
                    cmd = ['ping', '-n', '1', '-w', str(int(timeout * 1000)), '-i', str(ttl), target_ip]
                else:
                    # Linux/Unix: -c 1: count 1, -W: timeout in seconds, -t: TTL
                    cmd = ['ping', '-c', '1', '-W', str(int(timeout)), '-t', str(ttl), target_ip]
                
                start_time = time.time()
                # Use creationflags to hide console window on Windows
                creationflags = 0
                if platform.system().lower() == 'windows':
                    creationflags = 0x08000000 # CREATE_NO_WINDOW
                
                proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, creationflags=creationflags)
                end_time = time.time()
                
                output = proc.stdout
                
                # Look for "Reply from <IP>:"
                match = re.search(r'Reply from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', output)
                if match:
                    found_ip = match.group(1)
                    result['ip'] = found_ip
                    result['loss'] = '0%'
                    result['status'] = 'Reached'
                    
                    # Try to find time=Xms
                    time_match = re.search(r'time[=<]([0-9]+)ms', output)
                    if time_match:
                        result['rtt'] = f"{float(time_match.group(1)):.2f}"
                    else:
                        result['rtt'] = f"{(end_time - start_time) * 1000:.2f}"
                    
                    if "TTL expired" in output:
                        result['status'] = 'Transit'
                    elif found_ip == target_ip:
                        result['status'] = 'Destination Reached'
                        
                    try:
                        result['hostname'] = socket.gethostbyaddr(found_ip)[0]
                    except:
                        result['hostname'] = found_ip
                        
            except Exception as e:
                logging.debug(f"System ping fallback failed: {e}")
        
        return result

    @staticmethod
    def tcp_ping(target: str, ports: List[int] = [80, 443, 22], timeout: float = 1.0) -> Dict:
        """
        Check if host is alive using TCP SYN to common ports
        
        Args:
            target: Target IP address
            ports: List of ports to try
            timeout: Timeout in seconds
            
        Returns:
            Dictionary with status and responding port
        """
        result = {
            'alive': False,
            'responding_ports': [],
            'method': 'tcp'
        }
        
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            try:
                sock.connect((target, port))
                result['alive'] = True
                result['responding_ports'].append(port)
                sock.close()
            except (socket.timeout, socket.error):
                pass
            finally:
                try:
                    sock.close()
                except:
                    pass
        
        return result
    
    @staticmethod
    def arp_scan(network: str, timeout: float = 2.0) -> List[Dict]:
        """
        Scan local network using ARP (LAN only)
        
        Args:
            network: Network in CIDR notation (e.g., "192.168.1.0/24")
            timeout: Timeout in seconds
            
        Returns:
            List of discovered hosts with IP and MAC
        """
        if not SCAPY_AVAILABLE:
            logging.warning("ARP scan requires Scapy")
            return []
        
        discovered = []
        
        try:
            # Create ARP request
            arp = ARP(pdst=network)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp
            
            # Send and receive
            result = srp(packet, timeout=timeout, verbose=0)[0]
            
            for sent, received in result:
                discovered.append({
                    'ip': received.psrc,
                    'mac': received.hwsrc,
                    'alive': True
                })
        
        except Exception as e:
            error_msg = str(e).lower()
            if "winpcap" in error_msg or "libpcap" in error_msg:
                logging.warning("ARP scan unavailable (missing Npcap/WinPcap). Install Npcap for Layer 2 scanning.")
            else:
                logging.error(f"ARP scan failed: {e}")
        
        return discovered
    
    @staticmethod
    def comprehensive_check(target: str, timeout: float = 1.0) -> Dict:
        """
        Comprehensive host discovery using multiple methods
        
        Args:
            target: Target IP or hostname
            timeout: Timeout for each method
            
        Returns:
            Dictionary with all discovery results
        """
        result = {
            'target': target,
            'alive': False,
            'methods': {}
        }
        
        # Try ICMP ping
        icmp_result = HostDiscovery.ping_check(target, timeout)
        result['methods']['icmp'] = icmp_result
        if icmp_result['alive']:
            result['alive'] = True
            result['rtt'] = icmp_result['rtt']
        
        # Try TCP ping if ICMP failed
        if not result['alive']:
            tcp_result = HostDiscovery.tcp_ping(target, timeout=timeout)
            result['methods']['tcp'] = tcp_result
            if tcp_result['alive']:
                result['alive'] = True
        
        return result


class MacVendorLookup:
    """Simple MAC address vendor lookup"""
    
    # Common vendors for demonstration
    COMMON_VENDORS = {
        "00:0C:29": "VMware",
        "00:50:56": "VMware",
        "00:1C:14": "VMware",
        "00:15:5D": "Microsoft (Hyper-V)",
        "08:00:27": "Oracle (VirtualBox)",
        "00:1A:2B": "Cisco Systems",
        "A4:C1:38": "Apple",
        "BC:92:6B": "Apple",
        "B8:27:EB": "Raspberry Pi",
        "DC:A6:32": "Raspberry Pi",
        "E4:5F:01": "Raspberry Pi",
        "00:11:32": "Synology",
        "00:11:11": "Intel",
        "18:66:DA": "Dell",
        "F0:1F:AF": "Dell",
        "74:86:7A": "Dell",
        "B0:83:FE": "HP",
        "C8:D3:FF": "HP",
        "98:90:96": "Dell",
        "00:23:24": "G-Pro Computer",
        "00:1B:21": "Intel",
        "00:21:86": "U-Blox",
        "00:24:8C": "Asus",
        "00:26:18": "Asus",
        "00:1E:8C": "Asus",
        "00:0F:FE": "Develco",
        "00:19:B9": "Dell",
        "00:14:22": "Dell",
        "00:16:3E": "Xensource",
        "00:16:41": "3Com",
        "00:18:8B": "Dell",
        "00:1C:23": "Dell",
        "00:1D:09": "Dell",
        "00:1E:4F": "Dell",
        "00:21:70": "Dell",
        "00:22:19": "Dell",
        "00:23:AE": "Dell",
        "00:24:E8": "Dell",
        "00:25:64": "Dell",
        "00:26:B9": "Dell",
        "00:10:18": "Broadcom",
        "00:0A:27": "Apple",
        "00:14:51": "Apple",
        "00:16:CB": "Apple",
        "00:17:F2": "Apple",
        "00:19:E3": "Apple",
        "00:1B:63": "Apple",
        "00:1C:B3": "Apple",
        "00:1D:4F": "Apple",
        "00:1E:52": "Apple",
        "00:1E:C2": "Apple",
        "00:1F:5B": "Apple",
        "00:1F:F3": "Apple",
        "00:21:E9": "Apple",
        "00:22:41": "Apple",
        "00:23:12": "Apple",
        "00:23:32": "Apple",
        "00:23:6C": "Apple",
        "00:23:DF": "Apple",
        "00:24:36": "Apple",
        "00:25:00": "Apple",
        "00:25:4B": "Apple",
        "00:25:BC": "Apple",
        "00:26:08": "Apple",
        "00:26:4A": "Apple",
        "00:26:B0": "Apple",
        "00:11:24": "Apple",
        "00:03:93": "Apple",
        "00:05:02": "Apple",
        "00:0A:95": "Apple",
        "00:30:65": "Apple",
        "00:50:E4": "Apple",
        "00:10:FA": "Apple",
        "00:11:24": "Apple",
        "00:14:51": "Apple",
        "00:16:CB": "Apple",
        "00:17:F2": "Apple",
        "00:19:E3": "Apple",
        "00:1B:63": "Apple",
        "00:1C:B3": "Apple",
        "00:1D:4F": "Apple",
        "00:1E:52": "Apple",
        "00:1E:C2": "Apple",
        "00:1F:5B": "Apple",
        "00:1F:F3": "Apple",
        "00:21:E9": "Apple",
        "00:22:41": "Apple",
        "00:23:12": "Apple",
        "00:23:32": "Apple",
        "00:23:6C": "Apple",
        "00:23:DF": "Apple",
        "00:24:36": "Apple",
        "00:25:00": "Apple",
        "00:25:4B": "Apple",
        "00:25:BC": "Apple",
        "00:26:08": "Apple",
        "00:26:4A": "Apple",
        "00:26:B0": "Apple",
        "00:11:24": "Apple",
        "00:03:93": "Apple",
        "00:05:02": "Apple",
        "00:0A:95": "Apple",
        "00:30:65": "Apple",
        "00:50:E4": "Apple",
        "00:10:FA": "Apple",
    }
    
    @staticmethod
    def lookup(mac: str) -> str:
        """Look up vendor by MAC address"""
        if not mac or mac == "Unknown":
            return "Unknown"
            
        # Normalize MAC
        mac = mac.upper().replace("-", ":")
        
        # Check first 3 bytes (OUI)
        if len(mac) >= 8:
            oui = mac[:8]
            if oui in MacVendorLookup.COMMON_VENDORS:
                return MacVendorLookup.COMMON_VENDORS[oui]
                
        return "Unknown"


class IPIntelligence:
    """IP information gathering (no external API calls by default)"""
    
    @staticmethod
    def get_basic_info(ip: str) -> Dict:
        """
        Get basic IP information without external APIs
        
        Args:
            ip: IP address
            
        Returns:
            Dictionary with IP information
        """
        info = {
            'ip': ip,
            'hostname': None,
            'is_private': False,
            'is_loopback': False,
            'type': 'unknown'
        }
        
        # Try reverse DNS
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            info['hostname'] = hostname
        except:
            pass
        
        # Check IP type
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            info['is_private'] = ip_obj.is_private
            info['is_loopback'] = ip_obj.is_loopback
            
            if ip_obj.is_private:
                info['type'] = 'Private'
            elif ip_obj.is_loopback:
                info['type'] = 'Loopback'
            elif ip_obj.is_multicast:
                info['type'] = 'Multicast'
            else:
                info['type'] = 'Public'
        except:
            pass
        
        return info
    
    @staticmethod
    def get_network_info(ip: str) -> Dict:
        """
        Get network classification information
        
        Args:
            ip: IP address
            
        Returns:
            Dictionary with network info
        """
        info = IPIntelligence.get_basic_info(ip)
        
        # Add network class information
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            
            # Determine network class (for IPv4)
            if isinstance(ip_obj, ipaddress.IPv4Address):
                first_octet = int(str(ip_obj).split('.')[0])
                if first_octet < 128:
                    info['network_class'] = 'Class A'
                elif first_octet < 192:
                    info['network_class'] = 'Class B'
                elif first_octet < 224:
                    info['network_class'] = 'Class C'
                elif first_octet < 240:
                    info['network_class'] = 'Class D (Multicast)'
                else:
                    info['network_class'] = 'Class E (Reserved)'
        except:
            pass
        
        return info


class LANScanner:
    """Local network scanning capabilities"""
    
    @staticmethod
    def get_interfaces() -> List[Dict]:
        """Get available network interfaces"""
        interfaces = []
        
        # Method 1: Connect to internet to find primary interface (Best for finding real Ethernet/WiFi)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # We don't actually send data, just connecting to a public IP determines the route
            s.connect(("8.8.8.8", 80))
            primary_ip = s.getsockname()[0]
            s.close()
            
            # Calculate subnet
            ip_parts = primary_ip.split('.')
            network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            
            interfaces.append({
                'name': 'Primary (Internet)',
                'ip': primary_ip,
                'network': network
            })
        except Exception as e:
            logging.error(f"Primary interface detection failed: {e}")

        # Method 2: Parse ipconfig (Windows) to find all other adapters (VirtualBox, VPNs, etc.)
        if platform.system() == "Windows":
            try:
                # Use chcp 437 to ensure English output if possible, but just running ipconfig is usually enough
                output = subprocess.check_output("ipconfig", text=True)
                current_adapter = "Unknown Adapter"
                
                for line in output.split('\n'):
                    line = line.strip()
                    if not line: continue
                    
                    # Adapter name usually ends with ':' and doesn't start with spaces
                    if line.endswith(':') and not line.startswith("IPv4"):
                        current_adapter = line[:-1].replace("Ethernet adapter ", "").replace("Wireless LAN adapter ", "")
                    
                    elif "IPv4 Address" in line:
                        # Extract IP: "   IPv4 Address. . . . . . . . . . . : 192.168.1.5"
                        parts = line.split(':')
                        if len(parts) > 1:
                            ip = parts[-1].strip().replace("(Preferred)", "")
                            
                            # Filter out the primary one we already found to avoid duplicates
                            is_duplicate = any(i['ip'] == ip for i in interfaces)
                            
                            # Filter out APIPA (169.254.x.x) and empty IPs
                            if not is_duplicate and ip and not ip.startswith("169.254"):
                                ip_parts = ip.split('.')
                                if len(ip_parts) == 4:
                                    network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
                                    interfaces.append({
                                        'name': current_adapter,
                                        'ip': ip,
                                        'network': network
                                    })
            except Exception as e:
                logging.error(f"ipconfig parsing failed: {e}")
            
        return interfaces

    @staticmethod
    def scan_subnet(network: str, method: str = "arp", timeout: float = 2.0, stop_event=None) -> List[Dict]:
        """
        Scan a subnet for alive hosts
        
        Args:
            network: Network in CIDR notation
            method: 'arp', 'ping', or 'both'
            timeout: Timeout per host
            stop_event: Optional threading.Event to stop the scan
            
        Returns:
            List of discovered hosts
        """
        discovered = []
        existing_ips = set()
        
        # Check stop before starting
        if stop_event and stop_event.is_set():
            return discovered
        
        # ARP Scan
        arp_success = False
        if method in ['arp', 'both'] and SCAPY_AVAILABLE:
            arp_results = HostDiscovery.arp_scan(network, timeout)
            if arp_results:
                arp_success = True
                for host in arp_results:
                    host['method'] = 'arp'
                    discovered.append(host)
                    existing_ips.add(host['ip'])
            else:
                logging.warning("ARP scan returned no results or failed. Falling back to Ping Sweep.")
        
        # Ping Scan (Run if selected OR if ARP failed)
        if method in ['ping', 'both'] or (method == 'arp' and not arp_success):
            try:
                import ipaddress
                network_obj = ipaddress.ip_network(network, strict=False)
                
                # Limit ping scan to /24 to avoid taking forever
                hosts = list(network_obj.hosts())
                if len(hosts) > 256:
                    logging.warning("Network too large for ping scan, limiting to first 256")
                    hosts = hosts[:256]
                
                for ip in hosts:
                    # Check stop event inside loop
                    if stop_event and stop_event.is_set():
                        break
                        
                    ip_str = str(ip)
                    if ip_str in existing_ips:
                        continue
                        
                    result = HostDiscovery.ping_check(ip_str, timeout=0.2) # Fast ping
                    if result['alive']:
                        discovered.append({
                            'ip': ip_str,
                            'alive': True,
                            'rtt': result.get('rtt'),
                            'method': 'icmp',
                            'mac': 'Unknown'
                        })
            except Exception as e:
                logging.error(f"Ping scan failed: {e}")
                
        # Resolve hostnames and vendors
        for host in discovered:
            if stop_event and stop_event.is_set():
                break
                
            try:
                host['hostname'] = socket.gethostbyaddr(host['ip'])[0]
            except:
                host['hostname'] = "Unknown"
            
            # Vendor lookup
            if 'mac' in host:
                host['vendor'] = MacVendorLookup.lookup(host['mac'])
            else:
                host['vendor'] = "Unknown"
                
        return discovered
    
    @staticmethod
    def get_local_network() -> Optional[str]:
        """
        Attempt to determine local network range
        
        Returns:
            Network in CIDR notation or None
        """
        try:
            import ipaddress
            
            # Get local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            # Assume /24 for local network
            ip_parts = local_ip.split('.')
            network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            
            return network
        except:
            return None


def perform_host_discovery(target: str, verbose: bool = True) -> Dict:
    """
    Convenience function to perform comprehensive host discovery
    
    Args:
        target: Target IP or hostname
        verbose: Enable verbose output
        
    Returns:
        Complete discovery results
    """
    if verbose:
        logging.info(f"Performing host discovery on {target}")
    
    # Host reachability
    discovery = HostDiscovery.comprehensive_check(target)
    
    # IP intelligence
    try:
        ip = socket.gethostbyname(target)
        intelligence = IPIntelligence.get_network_info(ip)
        discovery['ip_info'] = intelligence
    except:
        pass
    
    if verbose:
        if discovery['alive']:
            logging.info(f"Host {target} is ALIVE")
            if 'rtt' in discovery and discovery['rtt']:
                logging.info(f"RTT: {discovery['rtt']:.2f} ms")
        else:
            logging.info(f"Host {target} appears DOWN or filtered")
    
    return discovery
