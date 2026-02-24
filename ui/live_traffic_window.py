#!/usr/bin/env python3
"""
Live Traffic Monitoring Window for CHOMBEZA
Shows real-time HTTP requests and responses during scanning
"""

import sys
import json
import time
import threading
from datetime import datetime
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    
    QLineEdit, QPushButton, QTabWidget, QTextEdit, QSplitter, QTreeWidget,
    QTreeWidgetItem, QHeaderView, QApplication, QMenu, QAction,
    QToolBar, QStatusBar, QCheckBox, QSpinBox, QGroupBox, QFileDialog
)
from PyQt5.QtCore import Qt, pyqtSignal, QTimer, QSize, QObject
from PyQt5.QtGui import QFont, QColor, QTextCharFormat, QSyntaxHighlighter, QTextDocument, QBrush

class JSONHighlighter(QSyntaxHighlighter):
    """Syntax highlighter for JSON"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.highlighting_rules = []
        
        # JSON key format
        key_format = QTextCharFormat()
        key_format.setForeground(QColor(255, 165, 0))  # Orange
        key_format.setFontWeight(QFont.Bold)
        self.highlighting_rules.append((
            r'\"[^\"]*\"(?=\s*:)',
            key_format
        ))
        
        # String value format
        string_format = QTextCharFormat()
        string_format.setForeground(QColor(0, 255, 0))  # Green
        self.highlighting_rules.append((
            r'\"[^\"]*\"',
            string_format
        ))
        
        # Number format
        number_format = QTextCharFormat()
        number_format.setForeground(QColor(255, 255, 0))  # Yellow
        self.highlighting_rules.append((
            r'\b\d+\b',
            number_format
        ))
        
        # Boolean format
        bool_format = QTextCharFormat()
        bool_format.setForeground(QColor(255, 0, 255))  # Magenta
        self.highlighting_rules.append((
            r'\b(true|false)\b',
            bool_format
        ))
        
        # Null format
        null_format = QTextCharFormat()
        null_format.setForeground(QColor(128, 128, 128))  # Gray
        self.highlighting_rules.append((
            r'\bnull\b',
            null_format
        ))
    
    def highlightBlock(self, text):
        import re
        for pattern, format in self.highlighting_rules:
            for match in re.finditer(pattern, text):
                start = match.start()
                length = match.end() - start
                self.setFormat(start, length, format)

class TrafficEntry:
    """Represents a single HTTP traffic entry"""
    
    def __init__(self, request_id, method, url, status_code=None, response_time=None, size=None):
        self.request_id = request_id
        self.timestamp = time.time()
        self.datetime = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        self.method = method
        self.url = url
        self.status_code = status_code
        self.response_time = response_time
        self.size = size
        self.request_headers = {}
        self.request_body = ""
        self.response_headers = {}
        self.response_body = ""
        self.vulnerability = None

class TrafficMonitorSignals(QObject):
    """Signals for traffic monitoring"""
    request_received = pyqtSignal(str, str, str, object, object)
    response_received = pyqtSignal(str, int, object, object, float, int)
    vulnerability_detected = pyqtSignal(str, object)
    clear_all = pyqtSignal()

# Singleton signal instance
traffic_signals = TrafficMonitorSignals()

class LiveTrafficWindow(QMainWindow):
    """Live traffic monitoring window"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("CHOMBEZA - Live Traffic Monitor")
        self.setGeometry(100, 100, 1400, 900)
        self.setMinimumSize(1200, 700)
        
        # Traffic storage
        self.traffic_entries = []
        self.filtered_entries = []
        self.request_counter = 0
        self.auto_scroll = True
        self.paused = False
        
        # Setup UI
        self._setup_ui()
        self._setup_menu()
        self._setup_connections()
        
        # Apply dark theme
        self._apply_dark_theme()
        
        # Connect to global signals
        self._connect_signals()
        
        # Update timer
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self._update_stats)
        self.update_timer.start(1000)
        # NOTE: do not auto-show. MainWindow controls when to open.
    def _connect_signals(self):
        """Connect to global traffic signals"""
        global traffic_signals
        traffic_signals.request_received.connect(self.add_request)
        traffic_signals.response_received.connect(self.add_response)
        traffic_signals.vulnerability_detected.connect(self.add_vulnerability)
        traffic_signals.clear_all.connect(self._clear_traffic)
        print("[+] Live traffic window connected to signals")  # Debug
    
    def _setup_ui(self):
        """Setup the user interface"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QVBoxLayout()
        central_widget.setLayout(main_layout)
        
        # Toolbar
        toolbar = QToolBar()
        toolbar.setMovable(False)
        self.addToolBar(toolbar)
        
        # Pause button
        self.pause_action = QAction("⏸️ Pause", self)
        self.pause_action.setCheckable(True)
        self.pause_action.triggered.connect(self._toggle_pause)
        toolbar.addAction(self.pause_action)
        
        toolbar.addSeparator()
        
        # Clear button
        clear_action = QAction("🗑️ Clear", self)
        clear_action.triggered.connect(self._clear_traffic)
        toolbar.addAction(clear_action)
        
        toolbar.addSeparator()
        
        # Auto-scroll checkbox
        self.auto_scroll_check = QCheckBox("Auto-scroll")
        self.auto_scroll_check.setChecked(True)
        self.auto_scroll_check.stateChanged.connect(self._toggle_auto_scroll)
        toolbar.addWidget(self.auto_scroll_check)
        
        toolbar.addSeparator()
        
        # Stats display
        self.stats_label = QLabel("Requests: 0 | Errors: 0 | Avg Time: 0ms")
        toolbar.addWidget(self.stats_label)
        
        # Main splitter
        main_splitter = QSplitter(Qt.Vertical)
        
        # Traffic list widget
        traffic_widget = QWidget()
        traffic_layout = QVBoxLayout()
        traffic_layout.setContentsMargins(0, 0, 0, 0)
        traffic_widget.setLayout(traffic_layout)
        
        # Filter bar
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter:"))
        
        self.method_filter = QPushButton("Method")
        self.method_filter.setMenu(self._create_method_menu())
        filter_layout.addWidget(self.method_filter)
        
        self.status_filter = QPushButton("Status")
        self.status_filter.setMenu(self._create_status_menu())
        filter_layout.addWidget(self.status_filter)
        
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search in URLs...")
        self.search_input.textChanged.connect(self._apply_filters)
        filter_layout.addWidget(self.search_input)
        
        self.apply_filter_btn = QPushButton("Apply")
        self.apply_filter_btn.clicked.connect(self._apply_filters)
        filter_layout.addWidget(self.apply_filter_btn)
        
        filter_layout.addStretch()
        traffic_layout.addLayout(filter_layout)
        
        # Traffic tree
        self.traffic_tree = QTreeWidget()
        self.traffic_tree.setHeaderLabels([
            "Time", "Method", "Status", "URL", "Size", "Time (ms)"
        ])
        self.traffic_tree.setColumnWidth(0, 100)
        self.traffic_tree.setColumnWidth(1, 80)
        self.traffic_tree.setColumnWidth(2, 70)
        self.traffic_tree.setColumnWidth(3, 500)
        self.traffic_tree.setColumnWidth(4, 100)
        self.traffic_tree.setColumnWidth(5, 100)
        self.traffic_tree.setAlternatingRowColors(True)
        self.traffic_tree.setSortingEnabled(True)
        self.traffic_tree.sortByColumn(0, Qt.DescendingOrder)
        self.traffic_tree.itemSelectionChanged.connect(self._show_traffic_details)
        
        traffic_layout.addWidget(self.traffic_tree)
        main_splitter.addWidget(traffic_widget)
        
        # Details tabs
        self.details_tabs = QTabWidget()
        
        # Request tab
        request_widget = QWidget()
        request_layout = QVBoxLayout()
        request_widget.setLayout(request_layout)
        
        self.request_headers = QTextEdit()
        self.request_headers.setReadOnly(True)
        self.request_headers.setFont(QFont("Courier New", 10))
        request_layout.addWidget(QLabel("Headers:"))
        request_layout.addWidget(self.request_headers)
        
        self.request_body = QTextEdit()
        self.request_body.setReadOnly(True)
        self.request_body.setFont(QFont("Courier New", 10))
        request_layout.addWidget(QLabel("Body:"))
        request_layout.addWidget(self.request_body)
        
        self.details_tabs.addTab(request_widget, "Request")
        
        # Response tab
        response_widget = QWidget()
        response_layout = QVBoxLayout()
        response_widget.setLayout(response_layout)
        
        self.response_headers = QTextEdit()
        self.response_headers.setReadOnly(True)
        self.response_headers.setFont(QFont("Courier New", 10))
        response_layout.addWidget(QLabel("Headers:"))
        response_layout.addWidget(self.response_headers)
        
        self.response_body = QTextEdit()
        self.response_body.setReadOnly(True)
        self.response_body.setFont(QFont("Courier New", 10))
        
        # Add JSON highlighter
        self.json_highlighter = JSONHighlighter(self.response_body.document())
        
        response_layout.addWidget(QLabel("Body:"))
        response_layout.addWidget(self.response_body)
        
        self.details_tabs.addTab(response_widget, "Response")
        
        # Vulnerability tab
        self.vuln_details = QTextEdit()
        self.vuln_details.setReadOnly(True)
        self.vuln_details.setFont(QFont("Courier New", 10))
        self.details_tabs.addTab(self.vuln_details, "Vulnerability")
        
        main_splitter.addWidget(self.details_tabs)
        
        # Set initial splitter sizes
        main_splitter.setSizes([500, 300])
        
        main_layout.addWidget(main_splitter)
        
        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Live traffic monitoring active")
    
    def _setup_menu(self):
        """Setup menu bar"""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("File")
        
        export_action = QAction("Export Traffic", self)
        export_action.triggered.connect(self._export_traffic)
        file_menu.addAction(export_action)
        
        file_menu.addSeparator()
        
        clear_action = QAction("Clear All", self)
        clear_action.triggered.connect(self._clear_traffic)
        file_menu.addAction(clear_action)
        
        file_menu.addSeparator()
        
        close_action = QAction("Close", self)
        close_action.triggered.connect(self.close)
        file_menu.addAction(close_action)
        
        # View menu
        view_menu = menubar.addMenu("View")
        
        self.show_timestamps_action = QAction("Show Timestamps", self)
        self.show_timestamps_action.setCheckable(True)
        self.show_timestamps_action.setChecked(True)
        view_menu.addAction(self.show_timestamps_action)
        
        # Filter menu
        filter_menu = menubar.addMenu("Filter")
        
        self.filter_2xx_action = QAction("Show 2xx Only", self)
        self.filter_2xx_action.setCheckable(True)
        filter_menu.addAction(self.filter_2xx_action)
        
        self.filter_3xx_action = QAction("Show 3xx Only", self)
        self.filter_3xx_action.setCheckable(True)
        filter_menu.addAction(self.filter_3xx_action)
        
        self.filter_4xx_action = QAction("Show 4xx Only", self)
        self.filter_4xx_action.setCheckable(True)
        filter_menu.addAction(self.filter_4xx_action)
        
        self.filter_5xx_action = QAction("Show 5xx Only", self)
        self.filter_5xx_action.setCheckable(True)
        filter_menu.addAction(self.filter_5xx_action)
    
    def _create_method_menu(self):
        """Create method filter menu"""
        menu = QMenu()
        
        methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]
        self.method_actions = {}
        
        for method in methods:
            action = QAction(method, self)
            action.setCheckable(True)
            action.setChecked(True)
            action.triggered.connect(self._apply_filters)
            menu.addAction(action)
            self.method_actions[method] = action
        
        return menu
    
    def _create_status_menu(self):
        """Create status code filter menu"""
        menu = QMenu()
        
        self.status_actions = {}
        
        action = QAction("1xx (Informational)", self)
        action.setCheckable(True)
        action.setChecked(True)
        action.triggered.connect(self._apply_filters)
        menu.addAction(action)
        self.status_actions['1xx'] = action
        
        action = QAction("2xx (Success)", self)
        action.setCheckable(True)
        action.setChecked(True)
        action.triggered.connect(self._apply_filters)
        menu.addAction(action)
        self.status_actions['2xx'] = action
        
        action = QAction("3xx (Redirection)", self)
        action.setCheckable(True)
        action.setChecked(True)
        action.triggered.connect(self._apply_filters)
        menu.addAction(action)
        self.status_actions['3xx'] = action
        
        action = QAction("4xx (Client Error)", self)
        action.setCheckable(True)
        action.setChecked(True)
        action.triggered.connect(self._apply_filters)
        menu.addAction(action)
        self.status_actions['4xx'] = action
        
        action = QAction("5xx (Server Error)", self)
        action.setCheckable(True)
        action.setChecked(True)
        action.triggered.connect(self._apply_filters)
        menu.addAction(action)
        self.status_actions['5xx'] = action
        
        return menu
    
    def _setup_connections(self):
        """Setup signal connections"""
        # Already connected via _connect_signals
        pass
    
    def _apply_dark_theme(self):
        """Apply dark theme to the window"""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1e1e1e;
            }
            QTreeWidget {
                background-color: #252526;
                color: #d4d4d4;
                border: 1px solid #3e3e42;
                font-family: 'Courier New';
                font-size: 11px;
            }
            QTreeWidget::item {
                padding: 4px;
                border-bottom: 1px solid #3e3e42;
            }
            QTreeWidget::item:selected {
                background-color: #094771;
            }
            QTreeWidget::item:hover {
                background-color: #2a2d2e;
            }
            QHeaderView::section {
                background-color: #2d2d30;
                color: #d4d4d4;
                padding: 8px;
                border: 1px solid #3e3e42;
                font-weight: bold;
            }
            QTextEdit {
                background-color: #1e1e1e;
                color: #d4d4d4;
                border: 1px solid #3e3e42;
                font-family: 'Courier New';
                font-size: 11px;
            }
            QTabWidget::pane {
                background-color: #1e1e1e;
                border: 1px solid #3e3e42;
            }
            QTabBar::tab {
                background-color: #2d2d30;
                color: #d4d4d4;
                padding: 8px 16px;
                border: 1px solid #3e3e42;
                border-bottom: none;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background-color: #094771;
                border-bottom: none;
            }
            QTabBar::tab:hover {
                background-color: #3e3e42;
            }
            QPushButton {
                background-color: #2d2d30;
                color: #d4d4d4;
                border: 1px solid #3e3e42;
                padding: 5px 10px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #3e3e42;
            }
            QPushButton:pressed {
                background-color: #094771;
            }
            QCheckBox {
                color: #d4d4d4;
                spacing: 5px;
            }
            QCheckBox::indicator {
                width: 16px;
                height: 16px;
            }
            QLineEdit {
                background-color: #2d2d30;
                color: #d4d4d4;
                border: 1px solid #3e3e42;
                padding: 5px;
                border-radius: 3px;
            }
            QStatusBar {
                background-color: #007acc;
                color: white;
                font-weight: bold;
            }
            QToolBar {
                background-color: #2d2d30;
                border: none;
                spacing: 5px;
                padding: 5px;
            }
            QToolBar QToolButton {
                background-color: #2d2d30;
                color: #d4d4d4;
                border: 1px solid #3e3e42;
                border-radius: 3px;
                padding: 5px;
            }
            QToolBar QToolButton:hover {
                background-color: #3e3e42;
            }
            QToolBar QToolButton:pressed {
                background-color: #094771;
            }
            QToolBar QToolButton:checked {
                background-color: #094771;
            }
            QMenuBar {
                background-color: #2d2d30;
                color: #d4d4d4;
                border-bottom: 1px solid #3e3e42;
            }
            QMenuBar::item {
                padding: 5px 10px;
            }
            QMenuBar::item:selected {
                background-color: #094771;
            }
            QMenu {
                background-color: #2d2d30;
                color: #d4d4d4;
                border: 1px solid #3e3e42;
            }
            QMenu::item {
                padding: 5px 20px;
            }
            QMenu::item:selected {
                background-color: #094771;
            }
            QMenu::separator {
                background-color: #3e3e42;
                height: 1px;
                margin: 5px 0;
            }
            QLabel {
                color: #d4d4d4;
            }
        """)
    
    def _toggle_pause(self, checked):
        """Toggle pause/resume traffic display"""
        self.paused = checked
        self.pause_action.setText("▶️ Resume" if checked else "⏸️ Pause")
        self.status_bar.showMessage("Traffic display " + ("paused" if checked else "resumed"), 3000)
    
    def _toggle_auto_scroll(self, state):
        """Toggle auto-scroll"""
        self.auto_scroll = (state == Qt.Checked)
    
    def _update_stats(self):
        """Update statistics display"""
        total = len(self.traffic_entries)
        errors = sum(1 for e in self.traffic_entries if e.status_code and e.status_code >= 400)
        vulnerabilities = sum(1 for e in self.traffic_entries if e.vulnerability)
        
        if total > 0:
            avg_time = sum(e.response_time or 0 for e in self.traffic_entries) / total
            avg_time_ms = int(avg_time * 1000)
        else:
            avg_time_ms = 0
        
        self.stats_label.setText(
            f"Requests: {total} | Errors: {errors} | Vulns: {vulnerabilities} | Avg Time: {avg_time_ms}ms"
        )
    
    def add_request(self, request_id, method, url, headers=None, body=None):
        """Add a request to the traffic log"""
        if self.paused:
            return
        
        self.request_counter += 1
        entry = TrafficEntry(request_id, method, url)
        
        if headers:
            entry.request_headers = headers
        if body:
            entry.request_body = str(body)[:2000]  # Limit size
        
        self.traffic_entries.append(entry)
        
        # Add to tree
        self._add_traffic_entry_to_tree(entry)
        
        print(f"[+] Request added: {method} {url}")  # Debug
    
    def add_response(self, request_id, status_code, headers=None, body=None, response_time=None, size=None):
        """Add a response to the traffic log"""
        if self.paused:
            return
        
        for entry in self.traffic_entries:
            if entry.request_id == request_id:
                entry.status_code = status_code
                entry.response_time = response_time
                entry.size = size
                
                if headers:
                    entry.response_headers = headers
                if body:
                    entry.response_body = str(body)[:20000]  # Limit size
                
                # Update the tree item
                self._update_traffic_entry_in_tree(entry)
                print(f"[+] Response added: {status_code} for {request_id}")  # Debug
                break
    
    def add_vulnerability(self, request_id, vulnerability):
        """Add vulnerability information to a request"""
        for entry in self.traffic_entries:
            if entry.request_id == request_id:
                entry.vulnerability = vulnerability
                self._update_traffic_entry_in_tree(entry)
                print(f"[+] Vulnerability added: {vulnerability.get('name')}")  # Debug
                break
    
    def _add_traffic_entry_to_tree(self, entry):
        """Add traffic entry to the tree widget"""
        # Create tree item
        item = self._create_tree_item(entry)
        
        # Add to tree
        self.traffic_tree.addTopLevelItem(item)
        
        # Auto-scroll
        if self.auto_scroll:
            self.traffic_tree.scrollToBottom()
    
    def _update_traffic_entry_in_tree(self, entry):
        """Update existing tree item for an entry"""
        for i in range(self.traffic_tree.topLevelItemCount()):
            item = self.traffic_tree.topLevelItem(i)
            stored_entry = item.data(0, Qt.UserRole)
            if stored_entry and stored_entry.request_id == entry.request_id:
                # Update the item
                new_item = self._create_tree_item(entry)
                for col in range(6):
                    item.setText(col, new_item.text(col))
                    item.setForeground(col, new_item.foreground(col))
                item.setData(0, Qt.UserRole, entry)
                break
    
    def _create_tree_item(self, entry):
        """Create a tree item for an entry"""
        # Color coding based on status code
        color = None
        if entry.status_code:
            if entry.status_code < 300:
                color = QColor(0, 255, 0)  # Green
            elif entry.status_code < 400:
                color = QColor(255, 255, 0)  # Yellow
            elif entry.status_code < 500:
                color = QColor(255, 165, 0)  # Orange
            else:
                color = QColor(255, 0, 0)  # Red
        
        # Format size
        size_str = ""
        if entry.size:
            if entry.size < 1024:
                size_str = f"{entry.size} B"
            elif entry.size < 1024 * 1024:
                size_str = f"{entry.size / 1024:.1f} KB"
            else:
                size_str = f"{entry.size / (1024 * 1024):.1f} MB"
        
        # Format response time
        time_str = f"{int(entry.response_time * 1000)}ms" if entry.response_time else "-"
        
        # Truncate URL for display
        display_url = entry.url[:100] + "..." if len(entry.url) > 100 else entry.url
        
        # Create tree item
        item = QTreeWidgetItem([
            entry.datetime,
            entry.method,
            str(entry.status_code) if entry.status_code else "-",
            display_url,
            size_str,
            time_str
        ])
        
        # Store entry in item
        item.setData(0, Qt.UserRole, entry)
        
        # Apply color
        if color:
            for i in range(6):
                item.setForeground(i, color)
        
        # Add vulnerability indicator
        if entry.vulnerability:
            severity = entry.vulnerability.get('severity', '').upper()
            item.setText(3, f"{display_url} [VULN: {severity}]")
            for i in range(6):
                item.setForeground(i, QColor(255, 0, 255))  # Magenta for vulnerabilities
        
        return item
    
    def _show_traffic_details(self):
        """Show details for selected traffic entry"""
        selected = self.traffic_tree.selectedItems()
        if not selected:
            return
        
        item = selected[0]
        entry = item.data(0, Qt.UserRole)
        if not entry:
            return
        
        # Request tab
        headers_str = json.dumps(entry.request_headers, indent=2) if entry.request_headers else ""
        self.request_headers.setText(headers_str)
        self.request_body.setText(entry.request_body)
        
        # Response tab
        headers_str = json.dumps(entry.response_headers, indent=2) if entry.response_headers else ""
        self.response_headers.setText(headers_str)
        
        # Try to pretty print JSON response
        if entry.response_body:
            try:
                # Try to parse as JSON
                if entry.response_body.strip().startswith('{') or entry.response_body.strip().startswith('['):
                    body_json = json.loads(entry.response_body)
                    body_str = json.dumps(body_json, indent=2)
                else:
                    body_str = entry.response_body
            except:
                body_str = entry.response_body
            self.response_body.setText(body_str)
        else:
            self.response_body.clear()
        
        # Vulnerability tab
        if entry.vulnerability:
            vuln = entry.vulnerability
            vuln_str = f"""
═══════════════════════════════════════════════════════════
                    🔥 VULNERABILITY DETECTED 🔥
═══════════════════════════════════════════════════════════

Name: {vuln.get('name')}
Severity: {vuln.get('severity', '').upper()}
Confidence: {vuln.get('confidence', 100)}%

Description:
{vuln.get('description')}

Evidence:
{vuln.get('evidence')}

Recommendation:
{vuln.get('recommendation')}
═══════════════════════════════════════════════════════════
            """
            self.vuln_details.setText(vuln_str)
        else:
            self.vuln_details.clear()
    
    def _apply_filters(self):
        """Apply filters to traffic list"""
        search_text = self.search_input.text().lower()
        
        for i in range(self.traffic_tree.topLevelItemCount()):
            item = self.traffic_tree.topLevelItem(i)
            entry = item.data(0, Qt.UserRole)
            
            show = True
            
            # Method filter
            if hasattr(self, 'method_actions') and entry:
                method_match = False
                for method, action in self.method_actions.items():
                    if entry.method == method and action.isChecked():
                        method_match = True
                        break
                if not method_match:
                    show = False
            
            # Status filter
            if show and entry and entry.status_code and hasattr(self, 'status_actions'):
                status_class = f"{entry.status_code // 100}xx"
                if status_class in self.status_actions:
                    if not self.status_actions[status_class].isChecked():
                        show = False
            
            # Search filter
            if show and entry and search_text:
                if search_text not in entry.url.lower():
                    show = False
            
            item.setHidden(not show)
    
    def _clear_traffic(self):
        """Clear all traffic entries"""
        self.traffic_tree.clear()
        self.traffic_entries.clear()
        self.filtered_entries.clear()
        self.request_counter = 0
        self.request_headers.clear()
        self.request_body.clear()
        self.response_headers.clear()
        self.response_body.clear()
        self.vuln_details.clear()
        self.status_bar.showMessage("Traffic cleared", 3000)
    
    def _export_traffic(self):
        """Export traffic log to file"""
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Export Traffic",
            f"traffic_{int(time.time())}.json",
            "JSON Files (*.json)"
        )
        
        if filename:
            data = []
            for entry in self.traffic_entries:
                data.append({
                    'request_id': entry.request_id,
                    'timestamp': entry.timestamp,
                    'datetime': entry.datetime,
                    'method': entry.method,
                    'url': entry.url,
                    'status_code': entry.status_code,
                    'response_time': entry.response_time,
                    'size': entry.size,
                    'request_headers': entry.request_headers,
                    'request_body': entry.request_body,
                    'response_headers': entry.response_headers,
                    'response_body': entry.response_body,
                    'vulnerability': entry.vulnerability
                })
            
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)
            
            self.status_bar.showMessage(f"Traffic exported to {filename}", 3000)
    
    def closeEvent(self, event):
        """Handle window close event"""
        self.update_timer.stop()
        event.accept()