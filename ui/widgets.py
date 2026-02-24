from PyQt5.QtWidgets import (
    QWidget, QLabel, QPushButton, QVBoxLayout, QHBoxLayout,
    QGraphicsDropShadowEffect, QProgressBar, QTextEdit, QCheckBox,
    QSlider, QFrame, QLineEdit, QTabBar
)
from PyQt5.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve, QRect, pyqtSignal, QPoint, QSize
from PyQt5.QtGui import QColor, QFont, QPainter, QPen, QLinearGradient, QBrush, QPalette, QPixmap, QFontMetrics
import random
import math
import time
import base64

class GlitchLabel(QLabel):
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setFont(QFont("Courier New", 20, QFont.Bold))
        self.setStyleSheet("color: #cccc00; padding: 5px;")  # Dark Yellow
        self.setMinimumHeight(50)
        self.glitch_timer = QTimer(self)
        self.glitch_timer.timeout.connect(self.glitch_effect)
        self.glitch_timer.start(3000)
        self.original_text = text

    def glitch_effect(self):
        if random.random() < 0.3:
            glitch_chars = ["|", "/", "-", "\\", "#", "$", "%", "&", "*"]
            glitch = random.choice(glitch_chars)
            self.setText(self.original_text + glitch)
            QTimer.singleShot(100, lambda: self.setText(self.original_text))

    def paintEvent(self, event):
        super().paintEvent(event)
        if random.random() < 0.1:
            painter = QPainter(self)
            painter.setPen(QPen(QColor(255, 0, 0, 100), 2))
            for _ in range(3):
                x1 = random.randint(0, self.width())
                x2 = random.randint(0, self.width())
                y = random.randint(0, self.height())
                painter.drawLine(x1, y, x2, y)

class NeonButton(QPushButton):
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setMinimumHeight(40)
        self.setMinimumWidth(100)
        self.setFont(QFont("Courier New", 12, QFont.Bold))
        self.setStyleSheet("""
            QPushButton {
                background: #1a1a1a;
                color: #cccc00;
                border: 2px solid #666600;
                padding: 8px 20px;
                border-radius: 6px;
                font-family: 'Courier New';
                font-weight: bold;
            }
            QPushButton:hover {
                background: #333300;
                border: 2px solid #cccc00;
            }
            QPushButton:pressed {
                background: #4d4d00;
            }
            QPushButton:disabled {
                background: #2a2a2a;
                color: #666666;
                border: 2px solid #444444;
            }
        """)
        self.shadow = QGraphicsDropShadowEffect()
        self.shadow.setBlurRadius(20)
        self.shadow.setXOffset(0)
        self.shadow.setYOffset(0)
        self.shadow.setColor(QColor(204, 204, 0, 150))  # Dark Yellow shadow
        self.setGraphicsEffect(self.shadow)

        self.anim = QPropertyAnimation(self, b"geometry")
        self.anim.setDuration(100)
        self.anim.setEasingCurve(QEasingCurve.OutQuad)

    def enterEvent(self, event):
        self.anim.setStartValue(self.geometry())
        self.anim.setEndValue(self.geometry().adjusted(-2, -2, 4, 4))
        self.anim.start()

    def leaveEvent(self, event):
        self.anim.setStartValue(self.geometry())
        self.anim.setEndValue(self.geometry().adjusted(2, 2, -4, -4))
        self.anim.start()

class PulseButton(QPushButton):
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setFixedSize(45, 45)
        self.setFont(QFont("Courier New", 18, QFont.Bold))
        self.setStyleSheet("""
            QPushButton {
                background: #1a1a1a;
                color: #cccc00;
                border: 2px solid #cccc00;
                border-radius: 22px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #333300;
            }
        """)
        self.pulse_timer = QTimer()
        self.pulse_timer.timeout.connect(self.update)
        self.pulse_timer.start(1000)

    def paintEvent(self, event):
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setPen(QPen(QColor(204, 204, 0, 50), 2))  # Dark Yellow pulse
        painter.drawEllipse(self.rect().center(), 22, 22)

class RainbowBorder(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(3)
        self.setAttribute(Qt.WA_TransparentForMouseEvents)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update)
        self.timer.start(50)
        self.angle = 0

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        rect = self.rect()
        
        colors = [
            QColor(255, 0, 0),
            QColor(255, 127, 0),
            QColor(255, 255, 0),
            QColor(0, 255, 0),
            QColor(0, 0, 255),
            QColor(75, 0, 130),
            QColor(148, 0, 211)
        ]
        
        segment_width = rect.width() / len(colors)
        for i, color in enumerate(colors):
            painter.fillRect(int(i * segment_width), 0, 
                           int(segment_width) + 1, rect.height(), color)

class GradientProgress(QProgressBar):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(25)
        self.setTextVisible(True)
        self.setFormat("%p%")
        self.setStyleSheet("""
            QProgressBar {
                border: 2px solid #666600;
                border-radius: 6px;
                text-align: center;
                color: #cccc00;
                background: #1a1a1a;
                font-weight: bold;
                font-size: 12px;
            }
        """)

    def paintEvent(self, event):
        super().paintEvent(event)
        painter = QPainter(self)
        rect = self.rect()
        progress_rect = QRect(rect.x(), rect.y(), 
                             int(rect.width() * self.value() / 100), rect.height())
        
        gradient = QLinearGradient(0, 0, rect.width(), 0)
        gradient.setColorAt(0, QColor(0, 102, 204))  # Blue
        gradient.setColorAt(0.5, QColor(0, 82, 164))  # Darker Blue
        gradient.setColorAt(1, QColor(0, 51, 102))  # Dark Blue
        
        painter.fillRect(progress_rect, QBrush(gradient))

class ScanProgress(QProgressBar):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setRange(0, 100)
        self.setValue(0)
        self.setTextVisible(True)
        self.setFixedHeight(20)
        self.setStyleSheet("""
            QProgressBar {
                border: 2px solid #666600;
                border-radius: 6px;
                text-align: center;
                color: #cccc00;
                background: #1a1a1a;
                font-weight: bold;
                font-size: 11px;
            }
            QProgressBar::chunk {
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 #0066cc, stop:1 #003366
                );
                border-radius: 4px;
            }
        """)

class ConsoleOutput(QTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setMinimumHeight(120)
        self.setMaximumHeight(200)
        self.setStyleSheet("""
            QTextEdit {
                background: #0a0a0a;
                color: #cccc00;
                font-family: 'Courier New';
                font-size: 12px;
                border: 2px solid #666600;
                border-radius: 6px;
                padding: 8px;
                line-height: 1.4;
            }
        """)
        self.setLineWrapMode(QTextEdit.WidgetWidth)

    def append_log(self, text):
        timestamp = time.strftime("%H:%M:%S")
        self.append(f"[{timestamp}] {text}")
        self.verticalScrollBar().setValue(self.verticalScrollBar().maximum())

class AnimatedCheckBox(QCheckBox):
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setFont(QFont("Courier New", 12))
        self.setMinimumHeight(25)
        self.setStyleSheet("""
            QCheckBox {
                color: #cccc00;
                spacing: 8px;
            }
            QCheckBox::indicator {
                width: 20px;
                height: 20px;
            }
            QCheckBox::indicator:unchecked {
                border: 2px solid #666600;
                background: #1a1a1a;
                border-radius: 4px;
            }
            QCheckBox::indicator:checked {
                border: 2px solid #0066cc;
                background: #003366;
                border-radius: 4px;
                image: url(data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='18' height='18' viewBox='0 0 24 24'><path fill='white' d='M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z'/></svg>);
            }
            QCheckBox::indicator:hover {
                border: 2px solid #cccc00;
            }
        """)

    def nextCheckState(self):
        super().nextCheckState()

class AnimatedToggle(QCheckBox):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(50, 24)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        rect = self.rect()
        if self.isChecked():
            color = QColor(0, 102, 204)  # Blue when checked
            handle_pos = rect.width() - rect.height() + 2
        else:
            color = QColor(100, 100, 100)
            handle_pos = 2
        
        painter.setPen(Qt.NoPen)
        painter.setBrush(QBrush(color))
        painter.drawRoundedRect(rect, 12, 12)
        
        painter.setBrush(QBrush(Qt.white))
        painter.drawEllipse(handle_pos, 2, rect.height() - 4, rect.height() - 4)

class ParticleBackground(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.particles = []
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_particles)
        self.timer.start(50)

    def resizeEvent(self, event):
        self.particles = []
        for _ in range(30):
            self.particles.append({
                'x': random.randint(0, self.width()),
                'y': random.randint(0, self.height()),
                'vx': random.uniform(-0.5, 0.5),
                'vy': random.uniform(-0.5, 0.5),
                'size': random.randint(1, 3)
            })

    def update_particles(self):
        for p in self.particles:
            p['x'] += p['vx']
            p['y'] += p['vy']
            
            if p['x'] < 0 or p['x'] > self.width():
                p['vx'] *= -1
            if p['y'] < 0 or p['y'] > self.height():
                p['vy'] *= -1
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setPen(QPen(QColor(204, 204, 0, 30), 1))  # Dark Yellow particles
        
        for p in self.particles:
            painter.drawPoint(int(p['x']), int(p['y']))

class MatrixRain(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.chars = "01アイウエオカキクケコ"
        self.columns = []
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_rain)
        self.timer.start(100)

    def resizeEvent(self, event):
        if self.width() > 0:
            self.columns = [{'y': random.randint(-self.height(), 0), 'speed': random.randint(3, 8)} 
                           for _ in range(self.width() // 25)]

    def update_rain(self):
        for col in self.columns:
            col['y'] += col['speed']
            if col['y'] > self.height():
                col['y'] = -random.randint(20, 100)
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setFont(QFont("Courier New", 10))
        
        for i, col in enumerate(self.columns):
            x = i * 25
            y = col['y']
            
            for j in range(5):
                char_y = y - j * 20
                if 0 <= char_y <= self.height():
                    alpha = max(0, 100 - j * 20)
                    painter.setPen(QColor(204, 204, 0, alpha))  # Dark Yellow rain
                    painter.drawText(x, char_y, random.choice(self.chars))

class TypeWriter(QLabel):
    def __init__(self, text, parent=None):
        super().__init__(parent)
        self.full_text = text
        self.current_text = ""
        self.index = 0
        self.setFont(QFont("Courier New", 11))
        self.setStyleSheet("color: #cccc00; padding: 2px 5px;")  # Dark Yellow
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.type_next)
        self.timer.start(30)

    def type_next(self):
        if self.index < len(self.full_text):
            self.current_text += self.full_text[self.index]
            self.setText(self.current_text)
            self.index += 1
        else:
            self.timer.stop()

class GlowingLineEdit(QLineEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(40)
        self.setFont(QFont("Courier New", 13))
        self.setStyleSheet("""
            QLineEdit {
                background: #1a1a1a;
                color: #cccc00;
                border: 2px solid #666600;
                padding: 8px 12px;
                border-radius: 6px;
            }
            QLineEdit:focus {
                border: 2px solid #cccc00;
                background: #002200;
            }
        """)
        self.glow_intensity = 0
        self.glow_timer = QTimer(self)
        self.glow_timer.timeout.connect(self.update_glow)
        self.glow_timer.start(50)

    def update_glow(self):
        if self.hasFocus():
            self.glow_intensity = min(20, self.glow_intensity + 1)
        else:
            self.glow_intensity = max(0, self.glow_intensity - 1)
        self.update()

    def paintEvent(self, event):
        super().paintEvent(event)
        if self.glow_intensity > 0:
            painter = QPainter(self)
            painter.setPen(QPen(QColor(204, 204, 0, self.glow_intensity * 10), 2))
            painter.drawRect(self.rect().adjusted(1, 1, -2, -2))

class CyberpunkSlider(QSlider):
    def __init__(self, parent=None):
        super().__init__(Qt.Horizontal, parent)
        self.setMinimumHeight(30)
        self.setTickPosition(QSlider.TicksBelow)
        self.setTickInterval(5)
        self.setStyleSheet("""
            QSlider::groove:horizontal {
                border: 2px solid #666600;
                height: 8px;
                background: #1a1a1a;
                border-radius: 4px;
            }
            QSlider::handle:horizontal {
                background: #0066cc;
                width: 20px;
                margin: -6px 0;
                border-radius: 10px;
            }
            QSlider::handle:horizontal:hover {
                background: #003366;
                width: 22px;
            }
            QSlider::sub-page:horizontal {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #0066cc, stop:1 #003366);
                border-radius: 4px;
            }
        """)

class HoverSlider(CyberpunkSlider):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.value_label = QLabel(self)
        self.value_label.setStyleSheet("""
            QLabel {
                color: #cccc00;
                background: #1a1a1a;
                border: 2px solid #cccc00;
                border-radius: 4px;
                padding: 4px 8px;
                font-family: 'Courier New';
                font-size: 11px;
            }
        """)
        self.value_label.hide()

    def enterEvent(self, event):
        self.value_label.show()
        self.value_label.setText(str(self.value()))
        self.value_label.move(self.width() // 2 - 20, -30)

    def leaveEvent(self, event):
        self.value_label.hide()

    def mouseMoveEvent(self, event):
        super().mouseMoveEvent(event)
        self.value_label.setText(str(self.value()))

class RotatingIcon(QLabel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.angle = 0
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.rotate)
        self.timer.start(50)

    def rotate(self):
        self.angle = (self.angle + 5) % 360
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.translate(self.width() // 2, self.height() // 2)
        painter.rotate(self.angle)
        painter.translate(-self.width() // 2, -self.height() // 2)
        super().paintEvent(event)

class NeonTabBar(QTabBar):
    """Readable, spaced tabs that keep full names + icons visible (no clipping)."""

    def __init__(self, parent=None):
        super().__init__(parent)

        # Don't force all tabs to squeeze; allow scrolling if window is narrow
        self.setExpanding(False)
        self.setUsesScrollButtons(True)
        self.setElideMode(Qt.ElideNone)
        self.setDrawBase(False)

        # Hover feedback
        self.setMouseTracking(True)
        self.hover_index = -1

        # Visual/readability tuning
        self._font = QFont("Courier New", 12, QFont.Bold)
        self._pad_x = 28      # inner left/right padding
        self._gap_x = 22      # visible space between tab boxes
        self._min_w = 260     # enough to fit 'PAYLOAD LAB' + icon
        self._min_h = 54      # taller tabs for readability
        self.setIconSize(QSize(18, 18))

    def tabSizeHint(self, index):
        text = self.tabText(index)
        fm = QFontMetrics(self._font)
        text_w = fm.horizontalAdvance(text)

        icon_w = 0
        icon = self.tabIcon(index)
        if icon is not None and not icon.isNull():
            icon_w = self.iconSize().width() + 10  # icon + spacing

        w = max(self._min_w, text_w + icon_w + (self._pad_x * 2))
        h = max(self._min_h, fm.height() + 24)
        return QSize(w, h)

    def enterEvent(self, event):
        self.hover_index = self.tabAt(event.pos())
        self.update()
        super().enterEvent(event)

    def leaveEvent(self, event):
        self.hover_index = -1
        self.update()
        super().leaveEvent(event)

    def mouseMoveEvent(self, event):
        idx = self.tabAt(event.pos())
        if idx != self.hover_index:
            self.hover_index = idx
            self.update()
        super().mouseMoveEvent(event)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setFont(self._font)

        count = self.count()
        for i in range(count):
            base = self.tabRect(i)

            # Create visible gaps between tabs (paint smaller than the real rect)
            left_gap = self._gap_x // 2 if i > 0 else 0
            right_gap = self._gap_x // 2 if i < (count - 1) else 0
            rect = base.adjusted(left_gap, 6, -right_gap, -6)

            # Colors
            if i == self.currentIndex():
                bg = QColor(0, 51, 102)              # selected
                border = QColor(0, 102, 204)
                text_color = QColor(255, 255, 255)
            elif i == self.hover_index:
                bg = QColor(45, 45, 0)               # hover
                border = QColor(204, 204, 0)
                text_color = QColor(204, 204, 0)
            else:
                bg = QColor(20, 20, 20)              # normal
                border = QColor(102, 102, 0)
                text_color = QColor(204, 204, 0)

            painter.setPen(QPen(border, 2))
            painter.setBrush(QBrush(bg))
            painter.drawRoundedRect(rect, 10, 10)

            # Content area
            content = rect.adjusted(self._pad_x, 0, -self._pad_x, 0)
            x = content.left()

            icon = self.tabIcon(i)
            if icon is not None and not icon.isNull():
                pix = icon.pixmap(self.iconSize())
                painter.drawPixmap(x, content.center().y() - pix.height() // 2, pix)
                x += pix.width() + 10

            text_rect = QRect(x, content.top(), content.right() - x, content.height())
            painter.setPen(text_color)
            painter.drawText(text_rect, Qt.AlignVCenter | Qt.AlignLeft, self.tabText(i))


class FloatingWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.ToolTip)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.animation = QPropertyAnimation(self, b"pos")
        self.animation.setDuration(300)
        self.animation.setEasingCurve(QEasingCurve.OutQuad)

    def show_at(self, pos):
        self.animation.setStartValue(self.pos())
        self.animation.setEndValue(pos)
        self.animation.start()
        self.show()