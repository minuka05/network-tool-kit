"""
Utility functions for port scanning
"""

import socket
import ipaddress
import re
from typing import List, Union


def validate_target(target: str) -> bool:
    """
    Validate if target is a valid IP address or hostname
    
    Args:
        target: IP address or hostname to validate
        
    Returns:
        True if valid, False otherwise
    """
    if not target:
        return False
    
    # Check if valid IP address
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass
    
    # Check if valid CIDR network
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        pass
    
    # Check if valid hostname
    try:
        socket.gethostbyname(target)
        return True
    except socket.gaierror:
        pass
    
    # Check hostname format
    hostname_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
    if re.match(hostname_pattern, target):
        return True
    
    return False


def parse_ports(port_string: str) -> List[int]:
    """
    Parse port specification string into list of port numbers
    
    Supports formats:
    - Single port: "80"
    - Port range: "1-100"
    - Port list: "80,443,8080"
    - Mixed: "20-25,80,443,8000-8100"
    
    Args:
        port_string: String specifying ports to scan
        
    Returns:
        List of port numbers
    """
    ports = set()
    
    try:
        # Split by comma
        parts = port_string.split(',')
        
        for part in parts:
            part = part.strip()
            
            # Check if range
            if '-' in part:
                start, end = part.split('-', 1)
                start = int(start.strip())
                end = int(end.strip())
                
                # Validate range
                if start < 1 or end > 65535 or start > end:
                    continue
                
                # Add all ports in range
                ports.update(range(start, end + 1))
            else:
                # Single port
                port = int(part)
                if 1 <= port <= 65535:
                    ports.add(port)
        
        return sorted(list(ports))
    
    except (ValueError, AttributeError):
        return []


def format_scan_results(results: List[dict]) -> str:
    """
    Format scan results for display
    
    Args:
        results: List of scan result dictionaries
        
    Returns:
        Formatted string
    """
    if not results:
        return "No results to display"
    
    # Separate by status
    open_ports = [r for r in results if r['status'] == 'open']
    closed_ports = [r for r in results if r['status'] == 'closed']
    filtered_ports = [r for r in results if r['status'] == 'filtered']
    
    output = []
    output.append("=" * 80)
    output.append("SCAN RESULTS")
    output.append("=" * 80)
    
    # Open ports
    if open_ports:
        output.append(f"\nOPEN PORTS ({len(open_ports)}):")
        output.append("-" * 80)
        output.append(f"{'Port':<10} {'Service':<20} {'Version':<30}")
        output.append("-" * 80)
        
        for result in open_ports:
            port = result['port']
            service = result.get('service', 'unknown')
            version = result.get('version', '')
            output.append(f"{port:<10} {service:<20} {version:<30}")
    
    # Summary
    output.append("\n" + "=" * 80)
    output.append("SUMMARY")
    output.append("=" * 80)
    output.append(f"Total Ports Scanned: {len(results)}")
    output.append(f"Open: {len(open_ports)}")
    output.append(f"Closed: {len(closed_ports)}")
    output.append(f"Filtered: {len(filtered_ports)}")
    output.append("=" * 80)
    
    return "\n".join(output)


def is_private_ip(ip: str) -> bool:
    """
    Check if IP address is in private range
    
    Args:
        ip: IP address to check
        
    Returns:
        True if private IP, False otherwise
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False


def get_local_ip() -> str:
    """
    Get local IP address
    
    Returns:
        Local IP address as string
    """
    try:
        # Create a socket to determine local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"


def resolve_hostname(hostname: str) -> Union[str, None]:
    """
    Resolve hostname to IP address
    
    Args:
        hostname: Hostname to resolve
        
    Returns:
        IP address or None if resolution fails
    """
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def get_service_name(port: int) -> str:
    """
    Get service name for a port number using socket.getservbyport
    
    Args:
        port: Port number
        
    Returns:
        Service name or 'unknown'
    """
    try:
        return socket.getservbyport(port)
    except OSError:
        return 'unknown'


def validate_port_range(start: int, end: int) -> bool:
    """
    Validate port range
    
    Args:
        start: Start port
        end: End port
        
    Returns:
        True if valid range, False otherwise
    """
    if not isinstance(start, int) or not isinstance(end, int):
        return False
    
    if start < 1 or end > 65535:
        return False
    
    if start > end:
        return False
    
    return True


def calculate_scan_time(num_ports: int, threads: int, timeout: float) -> float:
    """
    Estimate scan time
    
    Args:
        num_ports: Number of ports to scan
        threads: Number of concurrent threads
        timeout: Timeout per port
        
    Returns:
        Estimated time in seconds
    """
    # Rough estimate: (ports / threads) * timeout
    # Add some overhead
    batches = (num_ports + threads - 1) // threads
    estimated = batches * timeout * 1.2  # 20% overhead
    return estimated


def format_time(seconds: float) -> str:
    """
    Format time duration in human-readable format
    
    Args:
        seconds: Time in seconds
        
    Returns:
        Formatted time string
    """
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{minutes}m {secs}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours}h {minutes}m"


def get_network_range(ip: str, cidr: int = 24) -> List[str]:
    """
    Get all IPs in a network range
    
    Args:
        ip: Base IP address
        cidr: CIDR notation (default /24)
        
    Returns:
        List of IP addresses in range
    """
    try:
        network = ipaddress.ip_network(f"{ip}/{cidr}", strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        return []


def is_port_in_use(port: int, host: str = '127.0.0.1') -> bool:
    """
    Check if a port is in use
    
    Args:
        port: Port number to check
        host: Host to check (default localhost)
        
    Returns:
        True if port is in use, False otherwise
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    
    try:
        result = sock.connect_ex((host, port))
        return result == 0
    except socket.error:
        return False
    finally:
        sock.close()


def get_common_ports() -> dict:
    """
    Get dictionary of common ports and their services
    
    Returns:
        Dictionary mapping port numbers to service names
    """
    return {
        20: 'FTP Data',
        21: 'FTP Control',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        445: 'SMB',
        465: 'SMTPS',
        587: 'SMTP (Submission)',
        993: 'IMAPS',
        995: 'POP3S',
        1433: 'MSSQL',
        1521: 'Oracle DB',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        5900: 'VNC',
        6379: 'Redis',
        8080: 'HTTP Proxy',
        8443: 'HTTPS Alt',
        27017: 'MongoDB',
    }


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename for safe file system operations
    
    Args:
        filename: Original filename
        
    Returns:
        Sanitized filename
    """
    # Remove invalid characters
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    
    # Limit length
    max_length = 200
    if len(filename) > max_length:
        filename = filename[:max_length]
    
    return filename
