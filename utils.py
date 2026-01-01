"""
Utility functions for port scanning
"""

import socket
import ipaddress
import re
from typing import List


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




