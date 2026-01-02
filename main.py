"""
Network Toolkit - Main GUI Application
Educational tool for cybersecurity students and analysts
Version: 1.0
Date: January 2026

LEGAL DISCLAIMER: This tool is for educational and authorized network testing only.
Unauthorized port scanning may be illegal in your jurisdiction.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import tkinter.font as tkfont
import webbrowser
from datetime import datetime
import threading
import ipaddress
from scanner_engine import PortScanner, ScanType
from utils import validate_target, parse_ports
from host_discovery import HostDiscovery, IPIntelligence, LANScanner
from reporting import export_scan_results
import logging

# Version Information
__version__ = "1.0"
__author__ = "Minuka"
__date__ = "January 2026"

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('port_scanner.log'),
        logging.StreamHandler()
    ]
)


class PortScannerGUI:
    """Main GUI application for the Network Toolkit"""
    
    def __init__(self, root):
        self.root = root
        self.root.title(f"Network Toolkit v{__version__} - Educational Tool")
        self.root.geometry("850x680")
        self.root.minsize(850, 680)
        self.root.resizable(True, True)
        
        # Scanner instance
        self.scanner = None
        self.is_scanning = False
        
        # Scan history
        self.scan_history = []
        
        # Create GUI components
        self.create_widgets()
        
        # Show legal disclaimer
        self.show_disclaimer()
        
        # Ensure window has focus after disclaimer
        self.root.lift()
        self.root.focus_force()
        
        # Set initial focus to host check entry
        self.root.after(500, lambda: self.host_check_entry.focus_force())
    
    def show_disclaimer(self):
        """Display legal disclaimer on startup"""
        disclaimer = (
            "LEGAL DISCLAIMER\n\n"
            "This port scanning tool is intended for educational purposes and "
            "authorized network security testing only.\n\n"
            "You must have explicit permission to scan any network or system.\n\n"
            "Unauthorized port scanning may violate:\n"
            "• Computer Fraud and Abuse Act (CFAA)\n"
            "• Computer Misuse Act\n"
            "• Other local and international laws\n\n"
            "By clicking 'I Agree', you confirm that you will only use this tool "
            "on networks and systems you own or have explicit authorization to test.\n\n"
            "The authors are not responsible for any misuse of this tool."
        )
        
        response = messagebox.askokcancel(
            "Legal Disclaimer - Please Read",
            disclaimer,
            icon='warning'
        )
        
        if not response:
            self.root.quit()
    
    def create_widgets(self):
        """Create all GUI components"""
        # Main container with padding
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights for responsiveness
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(2, weight=1)  # Notebook expands (now row 2)
        
        # Title
        title_label = ttk.Label(
            main_frame, 
            text=f"Network Toolkit v{__version__}", 
            font=('Arial', 16, 'bold')
        )
        title_label.grid(row=0, column=0, pady=(0, 5))
        
        # Subtitle with author info
        subtitle_label = ttk.Label(
            main_frame,
            text=f"Educational Tool",
            font=('Arial', 8),
            foreground='gray'
        )
        subtitle_label.grid(row=1, column=0, pady=(0, 10))
        
        # Create Notebook (Tabbed Interface)
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)
        
        # Footer Frame
        footer_frame = ttk.Frame(main_frame)
        footer_frame.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=(5, 0))
        footer_frame.columnconfigure(0, weight=1)
        
        # Left side text
        ttk.Label(
            footer_frame, 
            text=f"Network Toolkit v{__version__}", 
            font=('Arial', 8)
        ).grid(row=0, column=0, sticky=tk.W)
        
        # Right side link
        link_label = ttk.Label(
            footer_frame,
            text="Github",
            font=('Arial', 8, 'underline'),
            foreground='blue',
            cursor='hand2'
        )
        link_label.grid(row=0, column=1, sticky=tk.E)
        link_label.bind("<Button-1>", lambda e: webbrowser.open_new("https://github.com/minuka05/network-tool-kit"))

        # Bind tab change to handle focus
        self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_change)
        
        # Create pages
        self.create_host_info_page()
        self.create_port_scanner_page()
        self.create_traceroute_page()
        self.create_network_discovery_page()
    
    def on_tab_change(self, event):
        """Handle tab changes to ensure proper focus"""
        try:
            current_tab = self.notebook.index("current")
            if current_tab == 0:  # Host Info tab
                self.root.after(100, lambda: self.host_check_entry.focus_force())
            elif current_tab == 1:  # Port Scanner tab
                self.root.after(100, lambda: self.target_entry.focus_force())
            elif current_tab == 2:  # Traceroute tab
                self.root.after(100, lambda: self.trace_target_entry.focus_force())
            elif current_tab == 3:  # Network Discovery tab
                pass
        except:
            pass
    
    def create_host_info_page(self):
        """Create Host Information Checker page"""
        page = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(page, text="🌐 Host Information")
        
        # Configure grid
        page.columnconfigure(0, weight=1)
        page.rowconfigure(2, weight=1)  # Results expand
        
        # Host Input Section
        input_frame = ttk.LabelFrame(page, text="Target Host", padding="10")
        input_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=5)
        input_frame.columnconfigure(1, weight=1)
        
        ttk.Label(input_frame, text="IP/Hostname:").grid(row=0, column=0, sticky=tk.W, padx=5)
        
        self.host_check_entry = ttk.Entry(input_frame, width=30)  # Reduced width to ensure button fits
        self.host_check_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5)
        
        # Add explicit click binding to ensure focus
        self.host_check_entry.bind("<Button-1>", lambda e: self.host_check_entry.focus_force())
        
        self.host_check_btn = ttk.Button(
            input_frame,
            text="🔍 Check Host",
            command=self.perform_host_check,
            width=15
        )
        self.host_check_btn.grid(row=0, column=2, padx=10, sticky=tk.E)
        
        # Host Information Display
        info_frame = ttk.LabelFrame(page, text="Host Details", padding="10")
        info_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=5)
        info_frame.columnconfigure(1, weight=1)
        info_frame.columnconfigure(3, weight=1)
        
        # Status
        ttk.Label(info_frame, text="Status:").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.host_status_label = ttk.Label(info_frame, text="Unknown", foreground="gray")
        self.host_status_label.grid(row=0, column=1, sticky=tk.W, padx=5)
        
        # RTT
        ttk.Label(info_frame, text="RTT:").grid(row=0, column=2, sticky=tk.W, padx=20)
        self.rtt_label = ttk.Label(info_frame, text="-", foreground="gray")
        self.rtt_label.grid(row=0, column=3, sticky=tk.W, padx=5)
        
        # Hostname
        ttk.Label(info_frame, text="Hostname:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.hostname_label = ttk.Label(info_frame, text="-", foreground="gray")
        self.hostname_label.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        
        # IP Type
        ttk.Label(info_frame, text="IP Type:").grid(row=1, column=2, sticky=tk.W, padx=20, pady=5)
        self.ip_type_label = ttk.Label(info_frame, text="-", foreground="gray")
        self.ip_type_label.grid(row=1, column=3, sticky=tk.W, padx=5, pady=5)
        
        # Network Class
        ttk.Label(info_frame, text="Network Class:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.network_class_label = ttk.Label(info_frame, text="-", foreground="gray")
        self.network_class_label.grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Location (if available)
        ttk.Label(info_frame, text="Resolved IP:").grid(row=2, column=2, sticky=tk.W, padx=20, pady=5)
        self.resolved_ip_label = ttk.Label(info_frame, text="-", foreground="gray")
        self.resolved_ip_label.grid(row=2, column=3, sticky=tk.W, padx=5, pady=5)
        
        # Detailed Results
        results_frame = ttk.LabelFrame(page, text="Detailed Information", padding="10")
        results_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        
        self.host_results_text = scrolledtext.ScrolledText(
            results_frame,
            wrap=tk.WORD,
            width=50,
            height=15,
            font=('Courier', 9)
        )
        self.host_results_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure tags
        self.host_results_text.tag_config('header', foreground='blue', font=('Courier', 9, 'bold'))
        self.host_results_text.tag_config('success', foreground='green', font=('Courier', 9, 'bold'))
        self.host_results_text.tag_config('error', foreground='red')
        self.host_results_text.tag_config('info', foreground='purple')
    
    def create_port_scanner_page(self):
        """Create Port Scanner page"""
        page = ttk.Frame(self.notebook)
        self.notebook.add(page, text="🔍 Port Scanner")
        
        # Main Layout: PanedWindow
        self.paned_window = ttk.PanedWindow(page, orient=tk.HORIZONTAL)
        self.paned_window.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Left Panel (Controls)
        self.left_panel = ttk.Frame(self.paned_window, width=300)
        self.paned_window.add(self.left_panel, weight=0)  # Fixed width, doesn't shrink/grow aggressively
        
        # Right Panel (Results)
        self.right_panel = ttk.Frame(self.paned_window)
        self.paned_window.add(self.right_panel, weight=1) # Takes all extra space
        
        # Populate Left Panel
        self.create_target_section(self.left_panel)
        self.create_basic_options_section(self.left_panel)
        self.create_advanced_options_section(self.left_panel)
        self.create_control_section(self.left_panel)
        
        # Populate Right Panel
        self.create_results_section(self.right_panel)
        
        # Status Bar (Bottom of page, outside pane)
        self.create_status_section(page)
        
        # Initialize results_text as None since we removed the UI
        self.results_text = None
    
    def create_traceroute_page(self):
        """Create Traceroute / MTR page"""
        page = ttk.Frame(self.notebook)
        self.notebook.add(page, text="🛣️ Trace Route")
        
        # Configure grid
        page.columnconfigure(0, weight=1)
        page.rowconfigure(1, weight=1)
        
        # Top section: Target input
        top_frame = ttk.LabelFrame(page, text="Target Selection", padding="10")
        top_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=10, pady=5)
        top_frame.columnconfigure(1, weight=1)
        
        ttk.Label(top_frame, text="Target Host/IP:").grid(row=0, column=0, sticky=tk.W, padx=5)
        
        self.trace_target_entry = ttk.Entry(top_frame, width=40)
        self.trace_target_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5)
        
        self.trace_button = ttk.Button(top_frame, text="Start Trace", command=self.start_traceroute)
        self.trace_button.grid(row=0, column=2, padx=5)
        
        self.stop_trace_button = ttk.Button(top_frame, text="Stop", command=self.stop_traceroute, state=tk.DISABLED)
        self.stop_trace_button.grid(row=0, column=3, padx=5)
        
        # Options
        options_frame = ttk.Frame(top_frame)
        options_frame.grid(row=1, column=0, columnspan=4, sticky=tk.W, pady=5)
        
        self.trace_method_var = tk.StringVar(value="ICMP")
        
        ttk.Label(options_frame, text="Max Hops:").pack(side=tk.LEFT, padx=(5, 5))
        self.max_hops_var = tk.StringVar(value="30")
        ttk.Spinbox(options_frame, from_=1, to=100, textvariable=self.max_hops_var, width=5).pack(side=tk.LEFT)
        
        # Results section
        results_frame = ttk.LabelFrame(page, text="Trace Results (MTR)", padding="10")
        results_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=10, pady=5)
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        
        # Treeview for results (MTR style)
        columns = ("hop", "ip", "hostname", "loss", "snt", "last", "avg", "best", "worst")
        self.trace_tree = ttk.Treeview(results_frame, columns=columns, show="headings")
        
        self.trace_tree.heading("hop", text="#")
        self.trace_tree.heading("ip", text="IP Address")
        self.trace_tree.heading("hostname", text="Hostname")
        self.trace_tree.heading("loss", text="Loss %")
        self.trace_tree.heading("snt", text="Snt")
        self.trace_tree.heading("last", text="Last")
        self.trace_tree.heading("avg", text="Avg")
        self.trace_tree.heading("best", text="Best")
        self.trace_tree.heading("worst", text="Wrst")
        
        self.trace_tree.column("hop", width=30, anchor=tk.CENTER)
        self.trace_tree.column("ip", width=100)
        self.trace_tree.column("hostname", width=120)
        self.trace_tree.column("loss", width=50, anchor=tk.CENTER)
        self.trace_tree.column("snt", width=40, anchor=tk.CENTER)
        self.trace_tree.column("last", width=50, anchor=tk.CENTER)
        self.trace_tree.column("avg", width=50, anchor=tk.CENTER)
        self.trace_tree.column("best", width=50, anchor=tk.CENTER)
        self.trace_tree.column("worst", width=50, anchor=tk.CENTER)
        
        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.trace_tree.yview)
        self.trace_tree.configure(yscroll=scrollbar.set)
        
        self.trace_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # Status bar for trace
        self.trace_status_var = tk.StringVar(value="Ready")
        ttk.Label(page, textvariable=self.trace_status_var, relief=tk.SUNKEN).grid(row=2, column=0, sticky=(tk.W, tk.E))

    def stop_traceroute(self):
        """Stop the running traceroute"""
        if hasattr(self, 'stop_event'):
            self.stop_event.set()
        self.trace_status_var.set("Stopping...")
        self.trace_button.config(state=tk.NORMAL)
        self.stop_trace_button.config(state=tk.DISABLED)

    def start_traceroute(self):
        """Start the traceroute in a separate thread"""
        target = self.trace_target_entry.get().strip()
        if not target:
            messagebox.showwarning("Input Error", "Please enter a target IP or hostname")
            return
            
        self.trace_button.config(state=tk.DISABLED)
        self.stop_trace_button.config(state=tk.NORMAL)
        self.trace_tree.delete(*self.trace_tree.get_children())
        self.trace_status_var.set(f"Tracing route to {target}...")
        
        # Stop event for thread
        self.stop_event = threading.Event()
        
        threading.Thread(target=self._run_traceroute, args=(target,), daemon=True).start()

    def _run_traceroute(self, target):
        import socket
        import time
        try:
            max_hops = int(self.max_hops_var.get())
            method = self.trace_method_var.get()
            
            # Resolve target first
            try:
                target_ip = socket.gethostbyname(target)
            except socket.gaierror:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Could not resolve {target}"))
                self.root.after(0, lambda: self.trace_button.config(state=tk.NORMAL))
                self.root.after(0, lambda: self.stop_trace_button.config(state=tk.DISABLED))
                return

            self.root.after(0, lambda: self.trace_status_var.set(f"Tracing route to {target} ({target_ip})..."))
            
            # Data structure to hold stats: {hop: {'ip': ..., 'hostname': ..., 'rtts': [], 'sent': 0, 'lost': 0}}
            hop_data = {}
            
            while not self.stop_event.is_set():
                target_reached = False
                
                for hop in range(1, max_hops + 1):
                    if self.stop_event.is_set():
                        break
                    
                    # Initialize hop data if new
                    if hop not in hop_data:
                        hop_data[hop] = {
                            'ip': 'N/A', 
                            'hostname': 'N/A', 
                            'rtts': [], 
                            'sent': 0, 
                            'lost': 0,
                            'best': 9999,
                            'worst': 0
                        }
                    
                    # Increment sent count
                    hop_data[hop]['sent'] += 1
                    
                    # Call backend to get hop info
                    hop_info = HostDiscovery.traceroute_hop(target_ip, hop, method, timeout=1.0)
                    
                    # Update stats
                    current_rtt = 0
                    if hop_info['status'] in ['Reached', 'Destination Reached', 'Transit']:
                        hop_data[hop]['ip'] = hop_info['ip']
                        hop_data[hop]['hostname'] = hop_info['hostname']
                        try:
                            current_rtt = float(hop_info['rtt'])
                            hop_data[hop]['rtts'].append(current_rtt)
                            hop_data[hop]['best'] = min(hop_data[hop]['best'], current_rtt)
                            hop_data[hop]['worst'] = max(hop_data[hop]['worst'], current_rtt)
                        except:
                            pass
                    else:
                        hop_data[hop]['lost'] += 1
                    
                    # Calculate aggregates
                    sent = hop_data[hop]['sent']
                    lost = hop_data[hop]['lost']
                    loss_pct = (lost / sent) * 100 if sent > 0 else 0
                    rtts = hop_data[hop]['rtts']
                    avg_rtt = sum(rtts) / len(rtts) if rtts else 0
                    last_rtt = current_rtt if current_rtt > 0 else 0
                    best_rtt = hop_data[hop]['best'] if hop_data[hop]['best'] != 9999 else 0
                    worst_rtt = hop_data[hop]['worst']
                    
                    # Update UI
                    values = (
                        hop,
                        hop_data[hop]['ip'],
                        hop_data[hop]['hostname'],
                        f"{loss_pct:.1f}%",
                        sent,
                        f"{last_rtt:.1f}",
                        f"{avg_rtt:.1f}",
                        f"{best_rtt:.1f}",
                        f"{worst_rtt:.1f}"
                    )
                    
                    def update_tree(h=hop, v=values):
                        # Check if item exists
                        if self.trace_tree.exists(h):
                            self.trace_tree.item(h, values=v)
                        else:
                            self.trace_tree.insert("", "end", iid=h, values=v)
                            
                    self.root.after(0, update_tree)
                    
                    if hop_info['ip'] == target_ip:
                        target_reached = True
                        # Don't break here, let it finish the loop or maybe break inner loop to restart?
                        # MTR usually continues probing all hops. But if we reached target at hop 5, we shouldn't probe hop 6.
                        # So we should limit max_hops for next iteration.
                        max_hops = hop 
                        break
                
                # Small pause between cycles
                time.sleep(1)
                    
            self.root.after(0, lambda: self.trace_status_var.set("Trace stopped."))
            
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
        finally:
            self.root.after(0, lambda: self.trace_button.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.stop_trace_button.config(state=tk.DISABLED))

    def create_network_discovery_page(self):
        """Create Network Discovery page"""
        page = ttk.Frame(self.notebook)
        self.notebook.add(page, text="⭐ Network Discovery")
        
        # Configure grid
        page.columnconfigure(0, weight=1)
        page.rowconfigure(1, weight=1)
        
        # Top Section: Interface & Controls
        top_frame = ttk.LabelFrame(page, text="🧠 Network Interface", padding="10")
        top_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=10, pady=5)
        top_frame.columnconfigure(1, weight=1)
        
        # Interface Info
        self.interface_var = tk.StringVar()
        self.interface_info_var = tk.StringVar(value="Detecting...")
        
        ttk.Label(top_frame, text="Interface:").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.interface_combo = ttk.Combobox(top_frame, textvariable=self.interface_var, state="readonly", width=30)
        self.interface_combo.grid(row=0, column=1, sticky=tk.W, padx=5)
        self.interface_combo.bind("<<ComboboxSelected>>", self.on_interface_change)
        
        ttk.Label(top_frame, textvariable=self.interface_info_var, foreground="gray").grid(row=0, column=2, sticky=tk.W, padx=5)
        
        # Discovery Method
        method_frame = ttk.Frame(top_frame)
        method_frame.grid(row=1, column=0, columnspan=3, sticky=tk.W, pady=10)
        
        ttk.Label(method_frame, text="Method:").pack(side=tk.LEFT, padx=5)
        self.discovery_method_var = tk.StringVar(value="arp")
        
        ttk.Radiobutton(method_frame, text="ARP Scan (Recommended)", variable=self.discovery_method_var, value="arp").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(method_frame, text="Ping Sweep", variable=self.discovery_method_var, value="ping").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(method_frame, text="ARP + Ping", variable=self.discovery_method_var, value="both").pack(side=tk.LEFT, padx=5)
        
        # Controls
        btn_frame = ttk.Frame(top_frame)
        btn_frame.grid(row=2, column=0, columnspan=3, sticky=tk.W, pady=5)
        
        self.nd_start_btn = ttk.Button(btn_frame, text="🔍 Start Discovery", command=self.start_network_discovery)
        self.nd_start_btn.pack(side=tk.LEFT, padx=5)
        
        self.nd_stop_btn = ttk.Button(btn_frame, text="■ Stop", command=self.stop_network_discovery, state=tk.DISABLED)
        self.nd_stop_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(btn_frame, text="🧹 Clear", command=self.clear_network_discovery).pack(side=tk.LEFT, padx=5)
        
        # Results Section
        results_frame = ttk.LabelFrame(page, text="🖥 Discovered Devices", padding="10")
        results_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=10, pady=5)
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(1, weight=1)
        
        # Filter
        filter_frame = ttk.Frame(results_frame)
        filter_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 5))
        
        ttk.Label(filter_frame, text="🔍 Filter (IP / MAC / Hostname):").pack(side=tk.LEFT)
        self.nd_filter_var = tk.StringVar()
        self.nd_filter_var.trace("w", self.filter_nd_results)
        ttk.Entry(filter_frame, textvariable=self.nd_filter_var, width=30).pack(side=tk.LEFT, padx=5)
        
        # Treeview
        columns = ("ip", "mac", "hostname", "status", "vendor")
        self.nd_tree = ttk.Treeview(results_frame, columns=columns, show="headings", selectmode="browse")
        
        self.nd_tree.heading("ip", text="IP Address")
        self.nd_tree.heading("mac", text="MAC Address")
        self.nd_tree.heading("hostname", text="Hostname")
        self.nd_tree.heading("status", text="Status")
        self.nd_tree.heading("vendor", text="Vendor")
        
        self.nd_tree.column("ip", width=120)
        self.nd_tree.column("mac", width=140)
        self.nd_tree.column("hostname", width=150)
        self.nd_tree.column("status", width=80, anchor=tk.CENTER)
        self.nd_tree.column("vendor", width=150)
        
        # Configure tags for colors
        self.nd_tree.tag_configure('online', foreground='green')
        self.nd_tree.tag_configure('unknown', foreground='gray')
        
        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.nd_tree.yview)
        self.nd_tree.configure(yscroll=scrollbar.set)
        
        self.nd_tree.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=1, column=1, sticky=(tk.N, tk.S))
        
        # Context Menu
        self.nd_context_menu = tk.Menu(self.root, tearoff=0)
        self.nd_context_menu.add_command(label="Port Scan Device", command=self.nd_port_scan_device)
        self.nd_context_menu.add_command(label="Trace Route", command=self.nd_trace_device)
        self.nd_context_menu.add_separator()
        self.nd_context_menu.add_command(label="Copy IP", command=self.nd_copy_ip)
        self.nd_context_menu.add_command(label="Copy MAC", command=self.nd_copy_mac)
        
        self.nd_tree.bind("<Button-3>", self.show_nd_context_menu)
        
        # Status Bar
        self.nd_status_var = tk.StringVar(value="Ready")
        ttk.Label(page, textvariable=self.nd_status_var, relief=tk.SUNKEN).grid(row=2, column=0, sticky=(tk.W, tk.E))
        
        # Disclaimer
        ttk.Label(page, text="⚠️ Use only on networks you own or have permission to scan.", foreground="red", font=("Arial", 8)).grid(row=3, column=0, pady=5)
        
        # Initialize interfaces
        self.refresh_interfaces()

    def refresh_interfaces(self):
        """Refresh network interfaces list"""
        interfaces = LANScanner.get_interfaces()
        if interfaces:
            values = [f"{i['name']} ({i['ip']})" for i in interfaces]
            self.interface_combo['values'] = values
            self.interface_combo.current(0)
            self.on_interface_change()
            self.interfaces_data = interfaces
        else:
            self.interface_combo['values'] = ["No interfaces found"]
            self.interface_info_var.set("Check connection")

    def on_interface_change(self, event=None):
        """Update interface info when selection changes"""
        try:
            idx = self.interface_combo.current()
            if idx >= 0 and hasattr(self, 'interfaces_data'):
                iface = self.interfaces_data[idx]
                self.interface_info_var.set(f"IP: {iface['ip']}  Subnet: {iface['network']}")
        except:
            pass

    def start_network_discovery(self):
        """Start network discovery scan"""
        try:
            idx = self.interface_combo.current()
            if idx < 0 or not hasattr(self, 'interfaces_data'):
                messagebox.showerror("Error", "No interface selected")
                return
                
            iface = self.interfaces_data[idx]
            network = iface['network']
            method = self.discovery_method_var.get()
            
            self.nd_start_btn.config(state=tk.DISABLED)
            self.nd_stop_btn.config(state=tk.NORMAL)
            self.nd_tree.delete(*self.nd_tree.get_children())
            self.nd_status_var.set(f"Scanning {network} using {method.upper()}...")
            
            self.nd_stop_event = threading.Event()
            threading.Thread(target=self._run_network_discovery, args=(network, method), daemon=True).start()
            
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def stop_network_discovery(self):
        """Stop network discovery"""
        if hasattr(self, 'nd_stop_event'):
            self.nd_stop_event.set()
        self.nd_status_var.set("Stopping...")

    def clear_network_discovery(self):
        """Clear discovery results"""
        self.nd_tree.delete(*self.nd_tree.get_children())
        self.nd_status_var.set("Ready")

    def _run_network_discovery(self, network, method):
        """Background thread for discovery"""
        try:
            # Pass stop event to scanner to allow interruption
            results = LANScanner.scan_subnet(network, method=method, stop_event=self.nd_stop_event)
            
            if not self.nd_stop_event.is_set():
                self.root.after(0, lambda: self.update_nd_results(results))
                self.root.after(0, lambda: self.nd_status_var.set(f"Scan complete. Found {len(results)} devices."))
            else:
                self.root.after(0, lambda: self.nd_status_var.set("Scan stopped."))
                
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
        finally:
            self.root.after(0, lambda: self.nd_start_btn.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.nd_stop_btn.config(state=tk.DISABLED))

    def update_nd_results(self, results):
        """Update the treeview with results"""
        self.nd_results_data = results # Store for filtering
        
        # Update tab title with count
        self.notebook.tab(3, text=f"⭐ Network Discovery ({len(results)})")
        
        # Update status bar with detailed info
        method = self.discovery_method_var.get().upper()
        timestamp = datetime.now().strftime("%H:%M")
        self.nd_status_var.set(f"Status: Complete | Devices: {len(results)} | Method: {method} | Time: {timestamp}")
        
        for device in results:
            values = (
                device['ip'],
                device.get('mac', 'Unknown'),
                device.get('hostname', 'Unknown'),
                "Online",
                device.get('vendor', 'Unknown')
            )
            self.nd_tree.insert("", "end", values=values, tags=('online',))
            
        # Auto-fit columns
        self.autofit_columns(self.nd_tree)

    def filter_nd_results(self, *args):
        """Filter results based on search text"""
        search = self.nd_filter_var.get().lower()
        self.nd_tree.delete(*self.nd_tree.get_children())
        
        if hasattr(self, 'nd_results_data'):
            for device in self.nd_results_data:
                if (search in device['ip'].lower() or 
                    search in device.get('hostname', '').lower() or 
                    search in device.get('mac', '').lower()):
                    
                    values = (
                        device['ip'],
                        device.get('mac', 'Unknown'),
                        device.get('hostname', 'Unknown'),
                        "Online",
                        device.get('vendor', 'Unknown')
                    )
                    self.nd_tree.insert("", "end", values=values, tags=('online',))

    def autofit_columns(self, tree):
        """Auto-resize columns to fit content"""
        font = tkfont.Font()
        for col in tree['columns']:
            # Start with heading width
            max_width = font.measure(tree.heading(col, 'text')) + 20
            
            # Check content width
            for item in tree.get_children():
                cell_value = tree.set(item, col)
                width = font.measure(str(cell_value)) + 20
                if width > max_width:
                    max_width = width
            
            # Cap max width to avoid huge columns
            if max_width > 300: max_width = 300
            
            tree.column(col, width=max_width)

    def show_nd_context_menu(self, event):
        """Show context menu on right click"""
        item = self.nd_tree.identify_row(event.y)
        if item:
            self.nd_tree.selection_set(item)
            self.nd_context_menu.post(event.x_root, event.y_root)

    def nd_port_scan_device(self):
        """Switch to port scanner and set target"""
        selection = self.nd_tree.selection()
        if selection:
            item = self.nd_tree.item(selection[0])
            ip = item['values'][0]
            
            # Switch tab
            self.notebook.select(1)
            
            # Set target
            self.target_entry.delete(0, tk.END)
            self.target_entry.insert(0, ip)
            self.scan_mode_var.set("Single Host")
            self.toggle_scan_mode()

    def nd_trace_device(self):
        """Switch to traceroute and set target"""
        selection = self.nd_tree.selection()
        if selection:
            item = self.nd_tree.item(selection[0])
            ip = item['values'][0]
            
            # Switch tab
            self.notebook.select(2)
            
            # Set target
            self.trace_target_entry.delete(0, tk.END)
            self.trace_target_entry.insert(0, ip)

    def nd_copy_ip(self):
        """Copy IP to clipboard"""
        selection = self.nd_tree.selection()
        if selection:
            item = self.nd_tree.item(selection[0])
            ip = item['values'][0]
            self.root.clipboard_clear()
            self.root.clipboard_append(ip)

    def nd_copy_mac(self):
        """Copy MAC to clipboard"""
        selection = self.nd_tree.selection()
        if selection:
            item = self.nd_tree.item(selection[0])
            mac = item['values'][1]
            self.root.clipboard_clear()
            self.root.clipboard_append(mac)

    def perform_host_check(self):
        """Perform comprehensive host information check"""
        target = self.host_check_entry.get().strip()
        
        if not target:
            messagebox.showwarning("No Target", "Please enter an IP address or hostname.")
            return
        
        # Clear previous results
        self.host_results_text.delete(1.0, tk.END)
        
        # Set initial status
        self.host_status_label.config(text="Checking...", foreground="orange")
        self.rtt_label.config(text="-", foreground="gray")
        self.hostname_label.config(text="-", foreground="gray")
        self.ip_type_label.config(text="-", foreground="gray")
        self.network_class_label.config(text="-", foreground="gray")
        self.resolved_ip_label.config(text="-", foreground="gray")
        
        def _check_thread():
            try:
                # Header
                header = f"""
{'='*70}
Host Information Check
{'='*70}
Target: {target}
Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{'='*70}

"""
                self.root.after(0, lambda: self.host_results_text.insert(tk.END, header, 'header'))
                
                # 1. Resolve hostname to IP
                self.root.after(0, lambda: self.host_results_text.insert(tk.END, "Resolving hostname...\n", 'info'))
                try:
                    import socket
                    resolved_ip = socket.gethostbyname(target)
                    self.root.after(0, lambda: self.resolved_ip_label.config(text=resolved_ip, foreground="blue"))
                    self.root.after(0, lambda: self.host_results_text.insert(tk.END, f"✓ Resolved to: {resolved_ip}\n\n", 'success'))
                except Exception as e:
                    self.root.after(0, lambda: self.host_results_text.insert(tk.END, f"✗ Resolution failed: {e}\n\n", 'error'))
                    resolved_ip = target
                
                # 2. Ping check
                self.root.after(0, lambda: self.host_results_text.insert(tk.END, "Performing reachability check...\n", 'info'))
                discovery = HostDiscovery.comprehensive_check(target, timeout=1.0)
                
                if discovery['alive']:
                    self.root.after(0, lambda: self.host_status_label.config(text="Alive ✓", foreground="green"))
                    self.root.after(0, lambda: self.host_results_text.insert(tk.END, "✓ Host is ALIVE\n", 'success'))
                    if discovery.get('rtt'):
                        rtt_val = discovery['rtt']
                        self.root.after(0, lambda: self.rtt_label.config(text=f"{rtt_val:.2f} ms", foreground="green"))
                        self.root.after(0, lambda: self.host_results_text.insert(tk.END, f"  RTT: {rtt_val:.2f} ms\n", 'info'))
                else:
                    self.root.after(0, lambda: self.host_status_label.config(text="Down/Filtered ✗", foreground="red"))
                    self.root.after(0, lambda: self.host_results_text.insert(tk.END, "✗ Host appears DOWN or filtered\n", 'error'))
                
                # 3. GeoIP Lookup
                self.root.after(0, lambda: self.host_results_text.insert(tk.END, "\nPerforming GeoIP lookup...\n", 'info'))
                geoip = HostDiscovery.get_geoip_info(resolved_ip)
                
                geoip_info = f"""
GeoIP Information:
------------------
Country: {geoip['country']}
ISP:     {geoip['isp']}
City:    {geoip['city']}
Org:     {geoip['org']}
"""
                self.root.after(0, lambda: self.host_results_text.insert(tk.END, geoip_info, 'info'))
                
                self.root.after(0, lambda: self.host_results_text.insert(tk.END, "\n", 'info'))
                
                # 3. Get IP intelligence
                self.root.after(0, lambda: self.host_results_text.insert(tk.END, "Gathering IP intelligence...\n", 'info'))
                ip_info = IPIntelligence.get_network_info(resolved_ip)
                
                # Update labels
                self.root.after(0, lambda: self.hostname_label.config(
                    text=ip_info.get('hostname', '-') or '-',
                    foreground="blue"
                ))
                self.root.after(0, lambda: self.ip_type_label.config(
                    text=ip_info.get('type', 'Unknown'),
                    foreground="blue"
                ))
                self.root.after(0, lambda: self.network_class_label.config(
                    text=ip_info.get('network_class', '-') or '-',
                    foreground="blue"
                ))
                
                # Display details
                self.root.after(0, lambda: self.host_results_text.insert(tk.END, f"\nIP Details:\n", 'header'))
                self.root.after(0, lambda: self.host_results_text.insert(tk.END, f"  Hostname: {ip_info.get('hostname', 'N/A') or 'N/A'}\n", 'info'))
                self.root.after(0, lambda: self.host_results_text.insert(tk.END, f"  IP Type: {ip_info.get('type', 'Unknown')}\n", 'info'))
                self.root.after(0, lambda: self.host_results_text.insert(tk.END, f"  Network Class: {ip_info.get('network_class', 'N/A') or 'N/A'}\n", 'info'))
                self.root.after(0, lambda: self.host_results_text.insert(tk.END, f"  Private: {ip_info.get('is_private', False)}\n", 'info'))
                self.root.after(0, lambda: self.host_results_text.insert(tk.END, f"  Loopback: {ip_info.get('is_loopback', False)}\n\n", 'info'))
                
                # 4. Discovery methods
                if 'methods' in discovery:
                    self.root.after(0, lambda: self.host_results_text.insert(tk.END, f"Discovery Methods:\n", 'header'))
                    if 'icmp' in discovery['methods']:
                        icmp = discovery['methods']['icmp']
                        status = "✓ Success" if icmp['alive'] else "✗ Failed"
                        self.root.after(0, lambda: self.host_results_text.insert(tk.END, f"  ICMP Ping: {status}\n", 'info'))
                    if 'tcp' in discovery['methods']:
                        tcp = discovery['methods']['tcp']
                        status = "✓ Success" if tcp['alive'] else "✗ Failed"
                        self.root.after(0, lambda: self.host_results_text.insert(tk.END, f"  TCP Ping: {status}\n", 'info'))
                        if tcp.get('responding_ports'):
                            ports_str = ', '.join(map(str, tcp['responding_ports']))
                            self.root.after(0, lambda: self.host_results_text.insert(tk.END, f"    Responding Ports: {ports_str}\n", 'info'))
                
                footer = f"\n{'='*70}\nCheck completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n{'='*70}\n"
                self.root.after(0, lambda: self.host_results_text.insert(tk.END, footer, 'header'))
                
            except Exception as e:
                logging.error(f"Host check failed: {e}")
                self.root.after(0, lambda: self.host_status_label.config(text="Error", foreground="red"))
                self.root.after(0, lambda: self.host_results_text.insert(tk.END, f"\n✗ Error: {str(e)}\n", 'error'))

        threading.Thread(target=_check_thread, daemon=True).start()
    
    def create_target_section(self, parent):
        """Create target configuration section"""
        frame = ttk.LabelFrame(parent, text="Target", padding="10")
        frame.pack(fill=tk.X, pady=5)
        
        # Target Type
        type_frame = ttk.Frame(frame)
        type_frame.pack(fill=tk.X, pady=2)
        
        self.scan_mode_var = tk.StringVar(value="Single Host")
        ttk.Radiobutton(type_frame, text="Single Host", variable=self.scan_mode_var, 
                       value="Single Host", command=self.toggle_scan_mode).pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(type_frame, text="Network Range", variable=self.scan_mode_var, 
                       value="Network Range", command=self.toggle_scan_mode).pack(side=tk.LEFT, padx=5)
        
        # Target Input
        input_frame = ttk.Frame(frame)
        input_frame.pack(fill=tk.X, pady=5)
        ttk.Label(input_frame, text="Target IP/Hostname:").pack(anchor=tk.W)
        self.target_entry = ttk.Entry(input_frame)
        self.target_entry.pack(fill=tk.X, pady=2)
        
        # Port Selection
        port_frame = ttk.Frame(frame)
        port_frame.pack(fill=tk.X, pady=5)
        ttk.Label(port_frame, text="Ports (e.g. 80, 443, 1-1000):").pack(anchor=tk.W)
        self.port_entry = ttk.Entry(port_frame)
        self.port_entry.pack(fill=tk.X, pady=2)

    def toggle_scan_mode(self):
        """Toggle between single host and network range mode"""
        pass

    def create_basic_options_section(self, parent):
        """Create basic scan options"""
        frame = ttk.LabelFrame(parent, text="Scan Profile", padding="10")
        frame.pack(fill=tk.X, pady=5)
        
        # Profile Selection
        p_frame = ttk.Frame(frame)
        p_frame.pack(fill=tk.X, pady=2)
        ttk.Label(p_frame, text="Profile:", width=10).pack(side=tk.LEFT)
        
        self.scan_profile_var = tk.StringVar(value="Normal")
        profiles = ["Quick Scan", "Normal", "Full Scan", "Stealth Scan", "Custom"]
        self.profile_combo = ttk.Combobox(p_frame, textvariable=self.scan_profile_var, values=profiles, state="readonly")
        self.profile_combo.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.profile_combo.bind("<<ComboboxSelected>>", self.on_profile_change)
        
        # Scan Type
        t_frame = ttk.Frame(frame)
        t_frame.pack(fill=tk.X, pady=2)
        ttk.Label(t_frame, text="Scan Type:", width=10).pack(side=tk.LEFT)
        
        self.scan_type_var = tk.StringVar(value="TCP Connect")
        scan_types = ["TCP Connect", "SYN Scan", "UDP Scan", "ACK Scan", "FIN Scan"]
        self.scan_type_combo = ttk.Combobox(t_frame, textvariable=self.scan_type_var, values=scan_types, state="readonly")
        self.scan_type_combo.pack(side=tk.LEFT, fill=tk.X, expand=True)

    def create_advanced_options_section(self, parent):
        """Create collapsible advanced options"""
        self.advanced_frame_container = ttk.Frame(parent)
        self.advanced_frame_container.pack(fill=tk.X, pady=5)
        
        # Toggle Button
        self.show_advanced_var = tk.BooleanVar(value=False)
        self.advanced_toggle_btn = ttk.Checkbutton(
            self.advanced_frame_container, 
            text="Show Advanced Options", 
            variable=self.show_advanced_var,
            command=self.toggle_advanced_options
        )
        self.advanced_toggle_btn.pack(anchor=tk.W)
        
        # Advanced Content Frame (Hidden by default)
        self.advanced_content = ttk.LabelFrame(self.advanced_frame_container, text="Advanced Configuration", padding="10")
        
        # Threading
        ttk.Label(self.advanced_content, text="Threads:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.thread_var = tk.StringVar(value="100")
        ttk.Spinbox(self.advanced_content, from_=1, to=1000, textvariable=self.thread_var, width=10).grid(row=0, column=1, sticky=tk.W, pady=2)
        
        # Timeout
        ttk.Label(self.advanced_content, text="Timeout (s):").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.timeout_var = tk.StringVar(value="1.0")
        ttk.Spinbox(self.advanced_content, from_=0.1, to=10.0, increment=0.1, textvariable=self.timeout_var, width=10).grid(row=1, column=1, sticky=tk.W, pady=2)
        
        # Checkboxes
        self.service_detect_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(self.advanced_content, text="Service Detection", variable=self.service_detect_var).grid(row=2, column=0, columnspan=2, sticky=tk.W)
        
        self.ping_check_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(self.advanced_content, text="Ping Before Scan", variable=self.ping_check_var).grid(row=3, column=0, columnspan=2, sticky=tk.W)

    def toggle_advanced_options(self):
        if self.show_advanced_var.get():
            self.advanced_content.pack(fill=tk.X, pady=5)
        else:
            self.advanced_content.pack_forget()

    def on_profile_change(self, event=None):
        """Update settings based on scan profile"""
        profile = self.scan_profile_var.get()
        if profile == "Quick Scan":
            self.thread_var.set("200")
            self.timeout_var.set("0.5")
            self.scan_type_var.set("TCP Connect")
            self.port_entry.delete(0, tk.END)
            self.port_entry.insert(0, "80,443,8080,21,22,23,25,53,110,143,3306,3389")
        elif profile == "Normal":
            self.thread_var.set("100")
            self.timeout_var.set("1.0")
            self.scan_type_var.set("TCP Connect")
            self.port_entry.delete(0, tk.END)
            self.port_entry.insert(0, "1-1024")
        elif profile == "Full Scan":
            self.thread_var.set("500")
            self.timeout_var.set("1.0")
            self.port_entry.delete(0, tk.END)
            self.port_entry.insert(0, "1-65535")
        elif profile == "Stealth Scan":
            self.thread_var.set("10")
            self.timeout_var.set("2.0")
            self.scan_type_var.set("SYN Scan")

    def create_control_section(self, parent):
        """Create control buttons section"""
        frame = ttk.Frame(parent, padding="10")
        frame.pack(fill=tk.X, pady=5)
        
        # Action Buttons
        self.start_btn = ttk.Button(frame, text="🚀 Start Scan", command=self.start_scan)
        self.start_btn.pack(fill=tk.X, pady=2)
        
        self.stop_btn = ttk.Button(frame, text="⏹ Stop Scan", command=self.stop_scan, state='disabled')
        self.stop_btn.pack(fill=tk.X, pady=2)
        
        self.clear_btn = ttk.Button(frame, text="🗑 Clear Results", command=self.clear_results)
        self.clear_btn.pack(fill=tk.X, pady=2)
        
        # Export (Compact)
        ttk.Separator(frame, orient='horizontal').pack(fill=tk.X, pady=5)
        
        export_frame = ttk.Frame(frame)
        export_frame.pack(fill=tk.X, pady=2)
        
        ttk.Label(export_frame, text="Export:", width=8).pack(side=tk.LEFT)
        
        self.export_format_var = tk.StringVar(value="HTML")
        ttk.Combobox(export_frame, textvariable=self.export_format_var, 
                    values=["HTML", "JSON", "CSV", "TXT"], state='readonly', width=8).pack(side=tk.LEFT, padx=5)
        
        self.export_btn = ttk.Button(export_frame, text="📥", width=4, command=self.export_results)
        self.export_btn.pack(side=tk.LEFT)
    
    def create_results_section(self, parent):
        """Create results table section"""
        # Treeview
        columns = ("host", "port", "protocol", "state", "service", "version")
        self.result_tree = ttk.Treeview(parent, columns=columns, show="headings", selectmode="browse")
        
        self.result_tree.heading("host", text="Host")
        self.result_tree.heading("port", text="Port")
        self.result_tree.heading("protocol", text="Protocol")
        self.result_tree.heading("state", text="State")
        self.result_tree.heading("service", text="Service")
        self.result_tree.heading("version", text="Version")
        
        self.result_tree.column("host", width=100, minwidth=80, anchor=tk.W)
        self.result_tree.column("port", width=50, minwidth=50, anchor=tk.CENTER)
        self.result_tree.column("protocol", width=60, minwidth=60, anchor=tk.CENTER)
        self.result_tree.column("state", width=70, minwidth=70, anchor=tk.CENTER)
        self.result_tree.column("service", width=100, minwidth=80, anchor=tk.W)
        self.result_tree.column("version", width=160, minwidth=100, anchor=tk.W)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.result_tree.yview)
        self.result_tree.configure(yscrollcommand=scrollbar.set)
        
        self.result_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def create_status_section(self, parent):
        """Create status bar section"""
        frame = ttk.Frame(parent, padding="2")
        frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=5)
        
        # Status label
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W).pack(side=tk.LEFT, fill=tk.X, expand=True)
    
    def start_scan(self):
        """Start the port scan in a separate thread"""
        if self.is_scanning:
            messagebox.showwarning("Scan in Progress", "A scan is already running!")
            return
        
        # Validate input
        target = self.target_entry.get().strip()
        if not validate_target(target):
            messagebox.showerror("Invalid Target", "Please enter a valid IP address, hostname, or CIDR network.")
            return
        
        port_input = self.port_entry.get().strip()
        ports = parse_ports(port_input)
        if not ports:
            messagebox.showerror("Invalid Ports", "Please enter valid port range or list.")
            return
        
        # Check if target is a network range
        is_network = False
        try:
            if '/' in target:
                ipaddress.ip_network(target, strict=False)
                is_network = True
        except ValueError:
            pass
        
        # Get scan parameters
        scan_type_str = self.scan_type_var.get()
        if "SYN" in scan_type_str:
            scan_type = ScanType.SYN_SCAN
        elif "ACK" in scan_type_str:
            scan_type = ScanType.ACK_SCAN
        elif "FIN" in scan_type_str:
            scan_type = ScanType.FIN_SCAN
        elif "Xmas" in scan_type_str:
            scan_type = ScanType.XMAS_SCAN
        elif "NULL" in scan_type_str:
            scan_type = ScanType.NULL_SCAN
        elif "Window" in scan_type_str:
            scan_type = ScanType.WINDOW_SCAN
        elif "UDP" in scan_type_str:
            scan_type = ScanType.UDP_SCAN
        else:
            scan_type = ScanType.TCP_CONNECT
        
        try:
            threads = int(self.thread_var.get())
            timeout = float(self.timeout_var.get())
        except ValueError:
            messagebox.showerror("Invalid Input", "Thread count and timeout must be numbers.")
            return
        
        service_detect = self.service_detect_var.get()
        ping_before = self.ping_check_var.get()
        
        # Check host if ping enabled (only for single host)
        if ping_before and not is_network:
            self.status_var.set("Checking host availability...")
            discovery = HostDiscovery.comprehensive_check(target)
            if not discovery['alive']:
                response = messagebox.askyesno(
                    "Host Appears Down",
                    f"Host {target} appears to be down or filtered.\nContinue anyway?"
                )
                if not response:
                    return
        
        # Update UI state
        self.is_scanning = True
        self.start_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        self.progress_var.set(0)
        self.status_var.set(f"Scanning {target}...")
        
        if is_network:
            # Start network scan
            scan_thread = threading.Thread(
                target=self.run_network_scan,
                args=(target, ports, scan_type, threads, timeout, service_detect, scan_type_str),
                daemon=True
            )
            scan_thread.start()
        else:
            # Start single host scan
            scan_thread = threading.Thread(
                target=self.run_scan,
                args=(target, ports, scan_type, threads, timeout, service_detect, scan_type_str),
                daemon=True
            )
            scan_thread.start()
    
    def run_network_scan(self, network, ports, scan_type, threads, timeout, service_detect, scan_type_str):
        """Execute network scan (runs in separate thread)"""
        try:
            net = ipaddress.ip_network(network, strict=False)
            hosts = list(net.hosts())
            total_hosts = len(hosts)
            
            self.root.after(0, lambda: self.status_var.set("Discovering alive hosts..."))
            
            alive_hosts = []
            lock = threading.Lock()
            
            # Discovery phase
            def check_host(ip):
                try:
                    res = HostDiscovery.comprehensive_check(str(ip), timeout=1.0)
                    if res['alive']:
                        with lock:
                            alive_hosts.append(str(ip))
                except:
                    pass

            # Run discovery in batches to avoid too many threads
            batch_size = 50
            for i in range(0, total_hosts, batch_size):
                if not self.is_scanning: break
                batch = hosts[i:i+batch_size]
                threads_list = []
                for ip in batch:
                    t = threading.Thread(target=check_host, args=(ip,))
                    t.start()
                    threads_list.append(t)
                for t in threads_list:
                    t.join()
                
                # Update progress (first 20%)
                progress = ((i + len(batch)) / total_hosts) * 20
                self.root.after(0, lambda: self.progress_var.set(progress))
            
            if not self.is_scanning: return
            
            # Scan phase
            for i, host in enumerate(alive_hosts):
                if not self.is_scanning: break
                
                self.root.after(0, lambda: self.status_var.set(f"Scanning {host} ({i+1}/{len(alive_hosts)})..."))
                
                scanner = PortScanner(
                    target=host,
                    ports=ports,
                    scan_type=scan_type,
                    threads=threads,
                    timeout=timeout,
                    service_detection=service_detect
                )
                
                results = scanner.scan()
                
                # Display results in tree
                self.root.after(0, lambda h=host, r=results, s=scan_type_str: self.display_results_in_tree(h, r, s))
                
                # Update progress (remaining 80%)
                progress = 20 + ((i + 1) / len(alive_hosts)) * 80
                self.root.after(0, lambda: self.progress_var.set(progress))
                
        except Exception as e:
            logging.error(f"Network scan error: {str(e)}")
            self.root.after(0, lambda: messagebox.showerror("Scan Error", f"Error during network scan: {str(e)}"))
        
        finally:
            self.root.after(0, self.scan_complete)

    def run_scan(self, target, ports, scan_type, threads, timeout, service_detect, scan_type_str):
        """Execute the scan (runs in separate thread)"""
        try:
            # Create scanner instance
            self.scanner = PortScanner(
                target=target,
                ports=ports,
                scan_type=scan_type,
                threads=threads,
                timeout=timeout,
                service_detection=service_detect
            )
            
            # Run scan with callback for progress
            start_time = datetime.now()
            results = self.scanner.scan(progress_callback=self.update_progress)
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            # Display results in tree
            self.root.after(0, lambda: self.display_results_in_tree(target, results, scan_type_str))
            
            # Log completion
            logging.info(f"Scan completed for {target} in {duration:.2f}s")
            
        except Exception as e:
            logging.error(f"Scan error: {str(e)}")
            self.root.after(0, lambda: messagebox.showerror("Scan Error", f"Error during scan: {str(e)}"))
        
        finally:
            # Reset UI state
            self.root.after(0, self.scan_complete)

    def display_results_in_tree(self, host, results, scan_type="TCP"):
        """Add scan results to the treeview"""
        protocol = "udp" if "UDP" in str(scan_type).upper() else "tcp"
        
        # Handle list of results (from PortScanner.scan())
        if isinstance(results, list):
            for result in results:
                port = result.get('port')
                state = result.get('status', 'unknown')
                service = result.get('service', 'unknown')
                version = result.get('version', '')
                
                self.result_tree.insert("", tk.END, values=(host, port, protocol, state, service, version))
        
        # Handle dictionary (legacy fallback)
        elif isinstance(results, dict):
            for port, info in results.items():
                state = info.get('state', 'unknown') if isinstance(info, dict) else info
                service = info.get('service', 'unknown') if isinstance(info, dict) else 'unknown'
                version = info.get('version', '') if isinstance(info, dict) else ''
                
                self.result_tree.insert("", tk.END, values=(host, port, protocol, state, service, version))
    
    def update_progress(self, current, total):
        """Update progress bar (called from scan thread)"""
        progress = (current / total) * 100
        self.root.after(0, lambda: self.progress_var.set(progress))
        self.root.after(0, lambda: self.status_var.set(
            f"Scanning... {current}/{total} ports checked"
        ))
    
    def display_results(self, results):
        """Display scan results (Deprecated - Logic moved to show_results_window)"""
        pass
    
    def stop_scan(self):
        """Stop the current scan"""
        if self.scanner:
            self.scanner.stop()
            self.status_var.set("Scan stopped by user")
            logging.info("Scan stopped by user")
    
    def scan_complete(self):
        """Reset UI after scan completion"""
        self.is_scanning = False
        self.start_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        self.status_var.set("Scan completed")
        self.progress_var.set(100)
    
    def clear_results(self):
        """Clear the results display"""
        for item in self.result_tree.get_children():
            self.result_tree.delete(item)
        self.progress_var.set(0)
        self.status_var.set("Ready")
    
    def export_results(self):
        """Export scan results to file"""
        if not self.scan_history:
            messagebox.showinfo("No Results", "No scan results to export.")
            return
        
        # Get last scan results
        last_scan = self.scan_history[-1]
        results = last_scan.get('results', [])
        
        # Get export format
        export_format = self.export_format_var.get().lower()
        
        # File extension mapping
        ext_map = {
            'html': '.html',
            'json': '.json',
            'csv': '.csv',
            'txt': '.txt'
        }
        
        # File type mapping for dialog
        filetypes_map = {
            'html': [("HTML files", "*.html"), ("All files", "*.*")],
            'json': [("JSON files", "*.json"), ("All files", "*.*")],
            'csv': [("CSV files", "*.csv"), ("All files", "*.*")],
            'txt': [("Text files", "*.txt"), ("All files", "*.*")]
        }
        
        # Ask for file location
        filename = filedialog.asksaveasfilename(
            defaultextension=ext_map.get(export_format, '.txt'),
            filetypes=filetypes_map.get(export_format, [("All files", "*.*")])
        )
        
        if filename:
            try:
                # Prepare scan info
                scan_info = {
                    'Target': last_scan.get('target', 'Unknown'),
                    'Scan Type': last_scan.get('scan_type', 'Unknown'),
                    'Timestamp': last_scan.get('timestamp', datetime.now().isoformat()),
                    'Total Ports': len(results),
                    'Duration': last_scan.get('duration', 'Unknown')
                }
                
                # Export using new reporting module
                success = export_scan_results(results, scan_info, export_format, filename)
                
                if success:
                    messagebox.showinfo(
                        "Export Successful", 
                        f"Results exported to {filename}\n\nFormat: {export_format.upper()}"
                    )
                    logging.info(f"Results exported to {filename} as {export_format}")
                else:
                    messagebox.showerror("Export Failed", "Failed to export results")
                    
            except Exception as e:
                messagebox.showerror("Export Failed", f"Failed to export results: {str(e)}")
                logging.error(f"Export failed: {str(e)}")

    def show_results_window(self, results, target, duration, scan_type_str, ports, threads, timeout, service_detect, start_time):
        """Show scan results in a new popup window"""
        if not results:
            return
            
        result_window = tk.Toplevel(self.root)
        result_window.title(f"Scan Complete - {target}")
        result_window.geometry("700x600")
        
        # Header Frame
        header_frame = ttk.Frame(result_window, padding="10")
        header_frame.pack(fill=tk.X)
        
        ttk.Label(header_frame, text="Scan Completed Successfully", font=('Arial', 12, 'bold'), foreground='green').pack()
        
        # Text area
        text_area = scrolledtext.ScrolledText(
            result_window,
            wrap=tk.WORD,
            width=80,
            height=30,
            font=('Courier', 10)
        )
        text_area.pack(expand=True, fill='both', padx=10, pady=5)
        
        # Configure tags
        text_area.tag_config('header', foreground='blue', font=('Courier', 10, 'bold'))
        text_area.tag_config('open', foreground='green', font=('Courier', 10, 'bold'))
        text_area.tag_config('vuln', foreground='red', font=('Courier', 10, 'bold'))
        text_area.tag_config('info', foreground='purple')
        
        # Insert Header Info
        header_info = f"""
{'='*80}
Network Toolkit - Scan Report
{'='*80}
Target: {target}
Ports Scanned: {len(ports) if isinstance(ports, list) else 'Range'}
Scan Type: {scan_type_str}
Threads: {threads} | Timeout: {timeout}s
Service Detection: {'Enabled' if service_detect else 'Disabled'}
Start Time: {start_time.strftime('%Y-%m-%d %H:%M:%S')}
Duration: {duration if isinstance(duration, str) else f"{duration:.2f}s"}
{'='*80}

"""
        text_area.insert(tk.END, header_info, 'header')
        
        # Insert Results
        open_ports = [r for r in results if r['status'] == 'open']
        
        if open_ports:
            headers = f"{'PORT':<8} {'STATUS':<12} {'SERVICE':<20} {'VERSION'}\n"
            text_area.insert(tk.END, headers, 'header')
            text_area.insert(tk.END, "-"*80 + "\n", 'header')
            
            for result in open_ports:
                port = str(result['port'])
                status = result['status']
                service = result.get('service', 'unknown')
                version = result.get('version', '')
                
                line = f"{port:<8} {status:<12} {service:<20} {version}\n"
                text_area.insert(tk.END, line, 'open')
                
                if 'vuln_info' in result:
                    text_area.insert(tk.END, f"    ⚠ {result['vuln_info']}\n", 'vuln')
        else:
            text_area.insert(tk.END, "No open ports found.\n", 'info')
            
        # Insert Summary
        summary = f"""
{'='*80}
Scan Summary:
{'='*80}
Total Ports Scanned: {len(results)}
Open Ports: {len(open_ports)}
Closed Ports: {len([r for r in results if r['status'] == 'closed'])}
Filtered Ports: {len([r for r in results if r['status'] == 'filtered'])}
{'='*80}
"""
        text_area.insert(tk.END, summary, 'info')
            
        text_area.config(state='disabled')  # Make read-only
        
        # Close button
        ttk.Button(result_window, text="Close", command=result_window.destroy).pack(pady=10)


def main():
    """Main entry point"""
    root = tk.Tk()
    app = PortScannerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
