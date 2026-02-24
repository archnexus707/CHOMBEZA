from PyQt5.QtGui import QColor, QPalette
from PyQt5.QtCore import Qt

class NeonStyles:
    @staticmethod
    def get_neon_palette():
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(5, 5, 5))  # Darker background
        palette.setColor(QPalette.WindowText, QColor(204, 204, 0))  # Dark Yellow
        palette.setColor(QPalette.Base, QColor(10, 10, 10))  # Darker base
        palette.setColor(QPalette.AlternateBase, QColor(15, 15, 15))
        palette.setColor(QPalette.ToolTipBase, QColor(204, 204, 0))
        palette.setColor(QPalette.ToolTipText, QColor(204, 204, 0))
        palette.setColor(QPalette.Text, QColor(204, 204, 0))  # Dark Yellow
        palette.setColor(QPalette.Button, QColor(20, 20, 20))
        palette.setColor(QPalette.ButtonText, QColor(204, 204, 0))  # Dark Yellow
        palette.setColor(QPalette.BrightText, QColor(255, 80, 80))
        palette.setColor(QPalette.Link, QColor(100, 200, 255))
        palette.setColor(QPalette.Highlight, QColor(0, 100, 200))  # Blue highlight
        palette.setColor(QPalette.HighlightedText, QColor(255, 255, 255))
        return palette

    @staticmethod
    def get_dark_palette():
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(20, 20, 20))
        palette.setColor(QPalette.WindowText, QColor(204, 204, 0))
        palette.setColor(QPalette.Base, QColor(25, 25, 25))
        palette.setColor(QPalette.AlternateBase, QColor(30, 30, 30))
        palette.setColor(QPalette.Text, QColor(204, 204, 0))
        palette.setColor(QPalette.Button, QColor(30, 30, 30))
        palette.setColor(QPalette.ButtonText, QColor(204, 204, 0))
        palette.setColor(QPalette.Highlight, QColor(0, 100, 200))
        palette.setColor(QPalette.HighlightedText, Qt.white)
        return palette

    @staticmethod
    def get_color_blind_palette():
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(240, 240, 240))
        palette.setColor(QPalette.WindowText, QColor(0, 0, 0))
        palette.setColor(QPalette.Base, Qt.white)
        palette.setColor(QPalette.AlternateBase, QColor(230, 230, 230))
        palette.setColor(QPalette.Text, QColor(0, 0, 0))
        palette.setColor(QPalette.Button, QColor(210, 210, 210))
        palette.setColor(QPalette.ButtonText, Qt.black)
        palette.setColor(QPalette.Highlight, QColor(0, 100, 200))
        palette.setColor(QPalette.HighlightedText, Qt.white)
        return palette

    @staticmethod
    def get_neon_stylesheet():
        return """
        /* Main window - Dark background */
        QMainWindow {
            background-color: #050505;
            color: #cccc00;
        }
        
        /* Central widget - Dark background */
        QMainWindow > QWidget {
            background-color: #050505;
        }
        
        /* All widgets default background */
        QWidget {
            background-color: transparent;
            color: #cccc00;
        }
        
        /* Labels */
        QLabel {
            color: #cccc00;
            padding: 2px 5px;
            font-size: 13px;
            background-color: transparent;
        }
        
        /* Group boxes - Dark with yellow border */
        QGroupBox {
            background-color: #0a0a0a;
            color: #cccc00;
            border: 2px solid #ffff00;
            border-radius: 8px;
            margin-top: 15px;
            font-weight: bold;
            font-size: 14px;
            padding-top: 10px;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 15px;
            padding: 0 10px 0 10px;
            color: #cccc00;
            background-color: transparent;
        }
        
        /* Target group box specific */
        QGroupBox#targetGroup, QGroupBox[title="🎯 TARGET"] {
            background-color: #0a0a0a;
        }
        
        /* Vulnerability group box specific */
        QGroupBox#vulnGroup, QGroupBox[title="🔬 VULNERABILITY TYPES"] {
            background-color: #0a0a0a;
        }
        
        /* Line edits - Dark with yellow border */
        QLineEdit, QTextEdit, QPlainTextEdit {
            background-color: #0f0f0f;
            color: #cccc00;
            border: 2px solid #ffff00;
            padding: 8px 12px;
            border-radius: 6px;
            font-family: 'Courier New';
            font-size: 13px;
            selection-background-color: #003366;
        }
        QLineEdit:focus, QTextEdit:focus {
            border: 2px solid #ffff00;
            background-color: #1a1a1a;
        }
        
        /* Combo boxes - Dark with yellow border */
        QComboBox {
            background-color: #0f0f0f;
            color: #cccc00;
            border: 2px solid #ffff00;
            padding: 8px 12px;
            border-radius: 6px;
            font-size: 13px;
            min-width: 150px;
        }
        QComboBox:hover {
            border: 2px solid #cccc00;
            background-color: #1a1a1a;
        }
        QComboBox::drop-down {
            border: none;
            width: 30px;
        }
        QComboBox::down-arrow {
            image: none;
            border-left: 5px solid transparent;
            border-right: 5px solid transparent;
            border-top: 5px solid #cccc00;
            margin-right: 5px;
        }
        QComboBox QAbstractItemView {
            background-color: #0f0f0f;
            color: #cccc00;
            selection-background-color: #003366;
            border: 2px solid #ffff00;
            border-radius: 6px;
            padding: 4px;
            outline: none;
        }
        QComboBox QAbstractItemView::item {
            padding: 8px;
            border-radius: 4px;
            background-color: transparent;
        }
        QComboBox QAbstractItemView::item:selected {
            background-color: #003366;
            color: #ffffff;
        }
        QComboBox QAbstractItemView::item:hover {
            background-color: #1a1a1a;
        }
        
        /* Checkboxes - Dark with yellow border */
        QCheckBox {
            color: #cccc00;
            spacing: 8px;
            font-size: 13px;
            padding: 3px;
            background-color: transparent;
        }
        QCheckBox::indicator {
            width: 20px;
            height: 20px;
            background-color: transparent;
        }
        QCheckBox::indicator:unchecked {
            border: 2px solid #ffff00;
            background-color: #0f0f0f;
            border-radius: 4px;
        }
        QCheckBox::indicator:checked {
            border: 2px solid #00ff66;
            background-color: #003300;
            border-radius: 4px;
            image: url(data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='18' height='18' viewBox='0 0 24 24'><path fill='white' d='M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z'/></svg>);
        }
        QCheckBox::indicator:hover {
            border: 2px solid #cccc00;
            background-color: #1a1a1a;
        }
        
        /* Radio buttons */
        QRadioButton {
            color: #cccc00;
            spacing: 8px;
            font-size: 13px;
            padding: 3px;
            background-color: transparent;
        }
        QRadioButton::indicator {
            width: 20px;
            height: 20px;
        }
        QRadioButton::indicator:unchecked {
            border: 2px solid #ffff00;
            background-color: #0f0f0f;
            border-radius: 10px;
        }
        QRadioButton::indicator:checked {
            border: 2px solid #0066cc;
            background-color: #003366;
            border-radius: 10px;
        }
        QRadioButton::indicator:hover {
            border: 2px solid #cccc00;
        }
        
        /* Push buttons */
        QPushButton {
            background-color: #0f0f0f;
            color: #cccc00;
            border: 2px solid #ffff00;
            padding: 8px 16px;
            border-radius: 6px;
            font-weight: bold;
            font-size: 13px;
            min-width: 80px;
        }
        QPushButton:hover {
            background-color: #1a1a1a;
            border: 2px solid #cccc00;
        }
        QPushButton:pressed {
            background-color: #2a2a00;
        }
        QPushButton:disabled {
            background-color: #1a1a1a;
            color: #666666;
            border: 2px solid #444444;
        }
        
        /* Progress bars */
        QProgressBar {
            border: 2px solid #ffff00;
            border-radius: 6px;
            text-align: center;
            color: #cccc00;
            background-color: #0f0f0f;
            font-size: 12px;
            font-weight: bold;
        }
        QProgressBar::chunk {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                stop:0 #0066cc, stop:1 #003366);
            border-radius: 4px;
        }
        
        /* Tab widget */
        QTabWidget::pane {
            border: 2px solid #ffff00;
            border-radius: 8px;
            background-color: #0a0a0a;
        }
        QTabBar::tab {
            background-color: #0f0f0f;
            color: #cccc00;
            padding: 10px 20px;
            border: 2px solid #ffff00;
            border-bottom: none;
            border-top-left-radius: 8px;
            border-top-right-radius: 8px;
            margin-right: 2px;
            font-weight: bold;
            font-size: 13px;
            min-width: 100px;
        }
        QTabBar::tab:selected {
            background-color: #003366;
            border: 2px solid #0066cc;
            border-bottom: none;
            color: #ffffff;
        }
        QTabBar::tab:hover {
            background-color: #1a1a1a;
        }
        
        /* List and Tree widgets */
        QListWidget, QTreeWidget {
            background-color: #0a0a0a;
            color: #cccc00;
            border: 2px solid #ffff00;
            border-radius: 8px;
            outline: none;
            font-size: 13px;
            padding: 5px;
        }
        QListWidget::item, QTreeWidget::item {
            padding: 8px;
            border-bottom: 1px solid #333300;
            border-radius: 4px;
            background-color: transparent;
        }
        QListWidget::item:selected, QTreeWidget::item:selected {
            background-color: #003366;
            color: #ffffff;
            border: 1px solid #0066cc;
        }
        QListWidget::item:hover, QTreeWidget::item:hover {
            background-color: #1a1a1a;
        }
        
        /* Header sections */
        QHeaderView::section {
            background-color: #0f0f0f;
            color: #cccc00;
            padding: 10px;
            border: 1px solid #333300;
            font-weight: bold;
            font-size: 13px;
        }
        
        /* Scroll bars */
        QScrollBar:vertical {
            background-color: #0a0a0a;
            width: 16px;
            border: 1px solid #333300;
            border-radius: 8px;
        }
        QScrollBar::handle:vertical {
            background-color: #0066cc;
            min-height: 30px;
            border-radius: 7px;
            margin: 2px;
        }
        QScrollBar::handle:vertical:hover {
            background-color: #003366;
        }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
            border: none;
            background: none;
            height: 0px;
        }
        
        /* Menu bar */
        QMenuBar {
            background-color: #0a0a0a;
            color: #cccc00;
            border-bottom: 2px solid #333300;
            padding: 5px;
            font-size: 13px;
        }
        QMenuBar::item {
            padding: 8px 15px;
            border-radius: 4px;
            background-color: transparent;
        }
        QMenuBar::item:selected {
            background-color: #003366;
        }
        
        /* Menu */
        QMenu {
            background-color: #0a0a0a;
            color: #cccc00;
            border: 2px solid #333300;
            border-radius: 6px;
            padding: 5px;
        }
        QMenu::item {
            padding: 8px 25px;
            border-radius: 4px;
            font-size: 13px;
            background-color: transparent;
        }
        QMenu::item:selected {
            background-color: #003366;
        }
        
        /* Status bar */
        QStatusBar {
            background-color: #0a0a0a;
            color: #cccc00;
            border-top: 2px solid #333300;
            font-size: 13px;
            padding: 5px;
        }
        
        /* Spin boxes */
        QSpinBox {
            background-color: #0f0f0f;
            color: #cccc00;
            border: 2px solid #ffff00;
            padding: 6px 10px;
            border-radius: 6px;
            font-size: 13px;
            min-width: 80px;
        }
        QSpinBox:hover {
            border: 2px solid #cccc00;
            background-color: #1a1a1a;
        }
        QSpinBox::up-button, QSpinBox::down-button {
            background-color: #0f0f0f;
            border: 1px solid #666600;
            border-radius: 3px;
            width: 20px;
        }
        QSpinBox::up-button:hover, QSpinBox::down-button:hover {
            background-color: #003366;
        }
        
        /* Frames */
        QFrame {
            background-color: transparent;
            border-radius: 6px;
        }
        
        /* Scroll areas */
        QScrollArea {
            background-color: transparent;
            border: none;
        }
        QScrollArea > QWidget > QWidget {
            background-color: transparent;
        }
        
        /* Sliders */
        QSlider::groove:horizontal {
            border: 2px solid #ffff00;
            height: 8px;
            background-color: #0f0f0f;
            border-radius: 4px;
        }
        QSlider::handle:horizontal {
            background-color: #0066cc;
            width: 20px;
            margin: -6px 0;
            border-radius: 10px;
        }
        QSlider::handle:horizontal:hover {
            background-color: #003366;
            width: 22px;
        }
        QSlider::sub-page:horizontal {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                stop:0 #0066cc, stop:1 #003366);
            border-radius: 4px;
        }
        
        /* Container widgets */
        QWidget#scanTabContainer, QWidget#resultsTabContainer {
            background-color: transparent;
        }
        
        /* Category labels */
        QLabel[category="true"] {
            color: #ffff00;
            font-weight: bold;
            font-size: 14px;
            padding: 5px 0;
            background-color: transparent;
        }
        """

class CyberStyles:
    @staticmethod
    def get_cyberpunk_palette():
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(10, 0, 10))
        palette.setColor(QPalette.WindowText, QColor(204, 204, 0))
        palette.setColor(QPalette.Base, QColor(20, 0, 20))
        palette.setColor(QPalette.AlternateBase, QColor(25, 0, 25))
        palette.setColor(QPalette.Text, QColor(204, 204, 0))
        palette.setColor(QPalette.Button, QColor(20, 0, 20))
        palette.setColor(QPalette.ButtonText, QColor(204, 204, 0))
        palette.setColor(QPalette.Highlight, QColor(0, 100, 200))
        palette.setColor(QPalette.HighlightedText, QColor(255, 255, 255))
        return palette

    @staticmethod
    def get_cyberpunk_stylesheet():
        return """
        QMainWindow {
            background-color: #0a000a;
            color: #cccc00;
        }
        QWidget {
            background-color: transparent;
            color: #cccc00;
        }
        QGroupBox {
            background-color: #0f000f;
            color: #cccc00;
            border: 2px solid #660066;
            border-radius: 8px;
            margin-top: 15px;
            font-weight: bold;
        }
        QGroupBox::title {
            color: #cccc00;
        }
        QLineEdit, QTextEdit, QPlainTextEdit {
            background-color: #150015;
            color: #cccc00;
            border: 2px solid #660066;
            padding: 8px 12px;
            border-radius: 6px;
        }
        QCheckBox {
            color: #cccc00;
            spacing: 8px;
            font-size: 13px;
            background-color: transparent;
        }
        QCheckBox::indicator:unchecked {
            border: 2px solid #cc00cc;
            background-color: #150015;
            border-radius: 4px;
        }
        QCheckBox::indicator:checked {
            border: 2px solid #00ff66;
            background-color: #003300;
            border-radius: 4px;
            image: url(data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='18' height='18' viewBox='0 0 24 24'><path fill='white' d='M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z'/></svg>);
        }
        QPushButton {
            background-color: #150015;
            color: #cccc00;
            border: 2px solid #660066;
            padding: 8px 16px;
            border-radius: 6px;
            font-weight: bold;
        }
        QPushButton:hover {
            background-color: #250025;
            border: 2px solid #cccc00;
        }
        QComboBox {
            background-color: #150015;
            color: #cccc00;
            border: 2px solid #660066;
            padding: 8px 12px;
            border-radius: 6px;
        }
        QComboBox:hover {
            border: 2px solid #cccc00;
        }
        QComboBox QAbstractItemView {
            background-color: #150015;
            color: #cccc00;
            selection-background-color: #003366;
            border: 2px solid #660066;
        }
        QTabWidget::pane {
            border: 2px solid #660066;
            border-radius: 8px;
            background-color: #0a000a;
        }
        QTabBar::tab {
            background-color: #150015;
            color: #cccc00;
            padding: 10px 20px;
            border: 2px solid #660066;
            border-top-left-radius: 8px;
            border-top-right-radius: 8px;
        }
        QTabBar::tab:selected {
            background-color: #003366;
            border: 2px solid #0066cc;
            color: #ffffff;
        }
        """

class MatrixStyles:
    @staticmethod
    def get_matrix_palette():
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(0, 8, 0))
        palette.setColor(QPalette.WindowText, QColor(204, 204, 0))
        palette.setColor(QPalette.Base, QColor(0, 12, 0))
        palette.setColor(QPalette.AlternateBase, QColor(0, 15, 0))
        palette.setColor(QPalette.Text, QColor(204, 204, 0))
        palette.setColor(QPalette.Button, QColor(0, 15, 0))
        palette.setColor(QPalette.ButtonText, QColor(204, 204, 0))
        palette.setColor(QPalette.Highlight, QColor(0, 100, 200))
        palette.setColor(QPalette.HighlightedText, QColor(255, 255, 255))
        return palette

    @staticmethod
    def get_matrix_stylesheet():
        return """
        QMainWindow {
            background-color: #000800;
            color: #cccc00;
        }
        QWidget {
            background-color: transparent;
            color: #cccc00;
        }
        QGroupBox {
            background-color: #001000;
            color: #cccc00;
            border: 2px solid #006600;
            border-radius: 8px;
            margin-top: 15px;
            font-weight: bold;
        }
        QGroupBox::title {
            color: #cccc00;
        }
        QLineEdit, QTextEdit, QPlainTextEdit {
            background-color: #001500;
            color: #cccc00;
            border: 2px solid #006600;
            padding: 8px 12px;
            border-radius: 6px;
        }
        QCheckBox {
            color: #cccc00;
            spacing: 8px;
            font-size: 13px;
            background-color: transparent;
        }
        QCheckBox::indicator:unchecked {
            border: 2px solid #00cc66;
            background-color: #001500;
            border-radius: 4px;
        }
        QCheckBox::indicator:checked {
            border: 2px solid #00ff66;
            background-color: #003300;
            border-radius: 4px;
            image: url(data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='18' height='18' viewBox='0 0 24 24'><path fill='white' d='M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z'/></svg>);
        }
        QPushButton {
            background-color: #001500;
            color: #cccc00;
            border: 2px solid #006600;
            padding: 8px 16px;
            border-radius: 6px;
            font-weight: bold;
        }
        QPushButton:hover {
            background-color: #002500;
            border: 2px solid #cccc00;
        }
        QComboBox {
            background-color: #001500;
            color: #cccc00;
            border: 2px solid #006600;
            padding: 8px 12px;
            border-radius: 6px;
        }
        QComboBox:hover {
            border: 2px solid #cccc00;
        }
        QComboBox QAbstractItemView {
            background-color: #001500;
            color: #cccc00;
            selection-background-color: #003366;
            border: 2px solid #006600;
        }
        QTabWidget::pane {
            border: 2px solid #006600;
            border-radius: 8px;
            background-color: #000800;
        }
        QTabBar::tab {
            background-color: #001500;
            color: #cccc00;
            padding: 10px 20px;
            border: 2px solid #006600;
            border-top-left-radius: 8px;
            border-top-right-radius: 8px;
        }
        QTabBar::tab:selected {
            background-color: #003366;
            border: 2px solid #0066cc;
            color: #ffffff;
        }
        """