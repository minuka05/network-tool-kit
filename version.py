"""
Version information for Network Analyzer
"""

__version__ = "1.0"
__version_info__ = (1, 0, 0)
__author__ = "github.com/minuka05"
__license__ = "Educational Use Only"
__copyright__ = "Copyright (c) 2026"
__email__ = "contact@example.com"
__url__ = "https://github.com/yourusername/port-scan"
__description__ = "Network Analyzer - Educational Tool for Cybersecurity Students"
__build_date__ = "2026-01-01"

VERSION_STRING = f"v{__version__}"
FULL_VERSION_STRING = f"Network Analyzer {VERSION_STRING}"

# Feature flags for this version
FEATURES_V1_0 = {
    'tcp_scan': True,
    'syn_scan': True,
    'udp_scan': True,
    'service_detection': True,
    'banner_grabbing': True,
    'multi_threading': True,
    'gui': True,
    'export_json': True,
    'export_txt': True,
    'scan_history': True,
}

# Version history
VERSION_HISTORY = {
    "1.0": {
        "date": "2026-01-01",
        "changes": [
            "Initial release",
            "TCP Connect scan support",
            "SYN scan support (requires admin)",
            "UDP scan support",
            "Service detection and banner grabbing",
            "Multi-threaded scanning",
            "GUI with tkinter",
            "Export functionality",
            "Scan history tracking",
        ]
    }
}

def get_version():
    """Get version string"""
    return __version__

def get_version_info():
    """Get detailed version information"""
    return {
        'version': __version__,
        'version_info': __version_info__,
        'author': __author__,
        'build_date': __build_date__,
        'license': __license__,
    }

def print_version():
    """Print version information to console"""
    print(f"""
{'='*60}
{FULL_VERSION_STRING}
{'='*60}
Version: {__version__}
Build Date: {__build_date__}
Author: {__author__}
License: {__license__}
{'='*60}
""")

if __name__ == "__main__":
    print_version()
