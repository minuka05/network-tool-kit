"""
Configuration file for Advanced Port Scanner
Customize default settings here
"""

# Application Settings
APP_NAME = "Advanced Port Scanner"
APP_VERSION = "1.0"
APP_AUTHOR = "github.com/minuka05"
BUILD_DATE = "2026-01-01"

# Default Scan Settings
DEFAULT_TARGET = "127.0.0.1"
DEFAULT_PORTS = "1-1024"
DEFAULT_SCAN_TYPE = "TCP Connect"
DEFAULT_THREADS = 100
DEFAULT_TIMEOUT = 1.0
DEFAULT_SERVICE_DETECTION = True

# Thread Limits
MIN_THREADS = 1
MAX_THREADS = 1000
RECOMMENDED_THREADS = 100

# Timeout Limits (seconds)
MIN_TIMEOUT = 0.1
MAX_TIMEOUT = 10.0
RECOMMENDED_TIMEOUT = 1.0

# Port Limits
MIN_PORT = 1
MAX_PORT = 65535

# Common Port Ranges
WELL_KNOWN_PORTS = (1, 1023)
REGISTERED_PORTS = (1024, 49151)
DYNAMIC_PORTS = (49152, 65535)

# Quick Scan Presets
QUICK_SCAN_PRESETS = {
    "Top 20 Ports": [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080],
    "Web Services": [80, 443, 8000, 8008, 8080, 8443, 8888, 9000, 9090],
    "Mail Services": [25, 110, 143, 465, 587, 993, 995],
    "Database Services": [1433, 1521, 3306, 5432, 6379, 27017, 27018, 27019],
    "Remote Access": [22, 23, 3389, 5900, 5901, 5902],
    "File Sharing": [20, 21, 69, 137, 138, 139, 445, 2049],
}

# GUI Settings
WINDOW_WIDTH = 00
WINDOW_HEIGHT = 700
WINDOW_MIN_WIDTH = 800
WINDOW_MIN_HEIGHT = 600

# Color Scheme
COLORS = {
    'open': '#2ecc71',      # Green
    'closed': '#e74c3c',    # Red
    'filtered': '#f39c12',  # Orange
    'header': '#3498db',    # Blue
    'info': '#9b59b6',      # Purple
    'background': '#ecf0f1', # Light gray
}

# Logging Settings
LOG_FILE = "port_scanner.log"
LOG_LEVEL = "INFO"  # DEBUG, INFO, WARNING, ERROR, CRITICAL
LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'
LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
MAX_LOG_SIZE = 10 * 1024 * 1024  # 10 MB
LOG_BACKUP_COUNT = 5

# Export Settings
EXPORT_FORMATS = ['json', 'txt', 'csv', 'html']
DEFAULT_EXPORT_FORMAT = 'json'
EXPORT_DIRECTORY = "scan_results"

# Performance Settings
BANNER_GRAB_TIMEOUT = 2.0
MAX_BANNER_LENGTH = 200
SERVICE_DETECTION_RETRIES = 2

# Network Settings
DNS_TIMEOUT = 3.0
PING_TIMEOUT = 2.0
MAX_PACKET_SIZE = 65535

# Security Settings
REQUIRE_CONFIRMATION = True
SHOW_LEGAL_DISCLAIMER = True
LOG_ALL_SCANS = True
ENABLE_SCAN_HISTORY = True
MAX_HISTORY_ITEMS = 100

# Advanced Features
ENABLE_OS_DETECTION = False  # Future feature
ENABLE_VULNERABILITY_SCAN = False  # Future feature
ENABLE_NETWORK_MAPPING = False  # Future feature

# Rate Limiting (to prevent network flooding)
ENABLE_RATE_LIMITING = False
MAX_PACKETS_PER_SECOND = 1000

# Notification Settings
ENABLE_SOUND_NOTIFICATIONS = False
ENABLE_POPUP_NOTIFICATIONS = True

# Auto-Save Settings
AUTO_SAVE_RESULTS = True
AUTO_SAVE_INTERVAL = 300  # seconds

# Development/Debug Settings
DEBUG_MODE = False
VERBOSE_OUTPUT = False
SHOW_CLOSED_PORTS = False  # Show closed ports in results
SHOW_FILTERED_PORTS = False  # Show filtered ports in results

# API Settings (for future integration)
API_ENABLED = False
API_PORT = 5000
API_HOST = "127.0.0.1"

# Database Settings (for future features)
DATABASE_ENABLED = False
DATABASE_PATH = "scan_history.db"

# User Preferences (can be overridden at runtime)
USER_PREFERENCES = {
    'remember_last_target': True,
    'remember_scan_settings': True,
    'auto_scroll_results': True,
    'confirm_on_exit': True,
    'theme': 'default',
}

# Help and Documentation
HELP_URL = "https://github.com/minuka05/network-tool-kit/wiki"
DOCUMENTATION_URL = "https://github.com/minuka05/network-tool-kit/blob/main/README.md"
ISSUES_URL = "https://github.com/minuka05/network-tool-kit/issues"

# Legal and Compliance
DISCLAIMER_TEXT = """
LEGAL DISCLAIMER

This port scanning tool is intended for educational purposes and 
authorized network security testing only.

You must have explicit permission to scan any network or system.

Unauthorized port scanning may violate:
• Computer Fraud and Abuse Act (CFAA)
• Computer Misuse Act
• Other local and international laws

By using this tool, you confirm that you will only use it on 
networks and systems you own or have explicit authorization to test.

The authors are not responsible for any misuse of this tool.
"""

# Feature Flags
FEATURES = {
    'tcp_connect_scan': True,
    'syn_scan': True,
    'udp_scan': True,
    'service_detection': True,
    'banner_grabbing': True,
    'export_results': True,
    'scan_history': True,
    'multi_threading': True,
    'progress_tracking': True,
}
