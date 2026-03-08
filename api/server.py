#!/usr/bin/env python3
"""
CHOMBEZA - REST API Server
Allows remote control and integration of CHOMBEZA scanner
"""

import os
import json
import time
import logging
import threading
import hashlib
import hmac
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify, make_response, send_file
from flask_cors import CORS

from core.scanner_enhanced import EnhancedScanner
from core.state import get_state_manager
from core.report import ReportGenerator

logger = logging.getLogger("CHOMBEZA.API")

class APIServer:
    """
    Flask-based REST API server for CHOMBEZA
    """
    
    def __init__(self, host: str = "127.0.0.1", port: int = 5001, 
                 api_key: Optional[str] = None, enable_cors: bool = True):
        self.host = host
        self.port = port
        self.api_key = api_key or self._generate_api_key()
        self.app = Flask(__name__)
        self.scanner = None
        self.scan_thread = None
        self.scan_results = {}
        self.active_scans = {}
        self.report_generator = ReportGenerator()
        
        if enable_cors:
            CORS(self.app)
        
        self._setup_routes()
        self._setup_auth()
        
        # Write API key to file for easy access
        self._save_api_key()
        
        logger.info(f"API Server initialized with API key: {self.api_key[:8]}...")
    
    def _generate_api_key(self) -> str:
        """Generate a random API key"""
        import secrets
        return secrets.token_hex(32)
    
    def _save_api_key(self):
        """Save API key to file for client use"""
        try:
            with open('.api_key', 'w') as f:
                f.write(self.api_key)
            logger.info("API key saved to .api_key")
        except Exception as e:
            logger.error(f"Failed to save API key: {e}")
    
    def _setup_auth(self):
        """Setup authentication decorator"""
        def require_api_key(f):
            @wraps(f)
            def decorated(*args, **kwargs):
                auth_header = request.headers.get('Authorization', '')
                
                if auth_header.startswith('Bearer '):
                    token = auth_header[7:]
                else:
                    token = request.args.get('api_key', '')
                
                # Constant-time comparison to prevent timing attacks
                if not hmac.compare_digest(token, self.api_key):
                    return jsonify({"error": "Invalid or missing API key"}), 401
                
                return f(*args, **kwargs)
            return decorated
        
        self.require_api_key = require_api_key
    
    def _setup_routes(self):
        """Setup API routes"""
        
        @self.app.route('/api/v1/status', methods=['GET'])
        def status():
            """Get server status"""
            return jsonify({
                "status": "running",
                "version": "2.0",
                "timestamp": datetime.now().isoformat(),
                "active_scans": len(self.active_scans),
                "api_version": "v1",
                "endpoints": [
                    "/api/v1/status",
                    "/api/v1/scans",
                    "/api/v1/scans/<scan_id>",
                    "/api/v1/scans/<scan_id>/stop",
                    "/api/v1/scans/<scan_id>/report",
                    "/api/v1/payloads",
                    "/api/v1/payloads/<vuln_type>",
                    "/api/v1/config",
                    "/api/v1/plugins"
                ]
            })
        
        @self.app.route('/api/v1/scans', methods=['POST'])
        @self.require_api_key
        def start_scan():
            """Start a new scan"""
            data = request.get_json()
            
            if not data or 'target' not in data:
                return jsonify({"error": "Missing target"}), 400
            
            target = data['target']
            scan_type = data.get('scan_type', 'quick')
            
            # Generate scan ID
            scan_id = hashlib.md5(f"{target}{time.time()}".encode()).hexdigest()[:12]
            
            # Initialize scanner
            scanner = EnhancedScanner()
            scanner.set_target(target)
            scanner.set_scan_type(scan_type)
            
            # Apply custom config
            if 'config' in data:
                scanner.config.update(data['config'])
            
            # Apply vulnerability selection
            if 'vuln_types' in data:
                features = {v: False for v in scanner.config.get("features", {})}
                for v in data['vuln_types']:
                    features[v] = True
                scanner.config["features"] = features
            
            # Start scan in background thread
            def run_scan():
                try:
                    scanner.start_scan()
                    report = scanner.generate_report()
                    self.scan_results[scan_id] = {
                        "target": target,
                        "status": "completed",
                        "report": report,
                        "vulnerabilities": [v.to_dict() for v in scanner.vulnerabilities],
                        "stats": scanner.stats,
                        "duration": scanner.get_duration(),
                        "completed_at": datetime.now().isoformat()
                    }
                except Exception as e:
                    self.scan_results[scan_id] = {
                        "target": target,
                        "status": "failed",
                        "error": str(e),
                        "completed_at": datetime.now().isoformat()
                    }
                finally:
                    if scan_id in self.active_scans:
                        del self.active_scans[scan_id]
            
            self.active_scans[scan_id] = {
                "target": target,
                "status": "running",
                "start_time": time.time(),
                "scanner": scanner
            }
            
            thread = threading.Thread(target=run_scan)
            thread.daemon = True
            thread.start()
            
            return jsonify({
                "scan_id": scan_id,
                "target": target,
                "scan_type": scan_type,
                "status": "started",
                "message": f"Scan started with ID: {scan_id}",
                "api_key": self.api_key[:8] + "..."  # Return partial for reference
            }), 202
        
        @self.app.route('/api/v1/scans', methods=['GET'])
        @self.require_api_key
        def list_scans():
            """List all scans"""
            scans = []
            
            # Active scans
            for scan_id, info in self.active_scans.items():
                scanner = info.get('scanner')
                scans.append({
                    "scan_id": scan_id,
                    "target": info['target'],
                    "status": "running",
                    "start_time": datetime.fromtimestamp(info['start_time']).isoformat(),
                    "progress": scanner.get_progress() if scanner else 0,
                    "vulnerabilities_found": len(scanner.vulnerabilities) if scanner else 0,
                    "duration": time.time() - info['start_time']
                })
            
            # Completed scans
            for scan_id, info in self.scan_results.items():
                scans.append({
                    "scan_id": scan_id,
                    "target": info['target'],
                    "status": info['status'],
                    "completed_at": info.get('completed_at', ''),
                    "vulnerabilities_found": info.get('stats', {}).get('total', 0),
                    "duration": info.get('duration', 0)
                })
            
            return jsonify({
                "total": len(scans),
                "scans": scans
            })
        
        @self.app.route('/api/v1/scans/<scan_id>', methods=['GET'])
        @self.require_api_key
        def get_scan(scan_id):
            """Get scan details"""
            # Check active scans
            if scan_id in self.active_scans:
                info = self.active_scans[scan_id]
                scanner = info.get('scanner')
                return jsonify({
                    "scan_id": scan_id,
                    "target": info['target'],
                    "status": "running",
                    "start_time": datetime.fromtimestamp(info['start_time']).isoformat(),
                    "progress": scanner.get_progress() if scanner else 0,
                    "vulnerabilities": [v.to_dict() for v in scanner.vulnerabilities] if scanner else [],
                    "stats": scanner.stats if scanner else {},
                    "duration": time.time() - info['start_time']
                })
            
            # Check completed scans
            if scan_id in self.scan_results:
                info = self.scan_results[scan_id]
                return jsonify({
                    "scan_id": scan_id,
                    "target": info['target'],
                    "status": info['status'],
                    "completed_at": info.get('completed_at', ''),
                    "vulnerabilities": info.get('vulnerabilities', []),
                    "stats": info.get('stats', {}),
                    "duration": info.get('duration', 0),
                    "error": info.get('error')
                })
            
            return jsonify({"error": "Scan not found"}), 404
        
        @self.app.route('/api/v1/scans/<scan_id>/stop', methods=['POST'])
        @self.require_api_key
        def stop_scan(scan_id):
            """Stop a running scan"""
            if scan_id not in self.active_scans:
                return jsonify({"error": "Scan not found or already completed"}), 404
            
            scanner = self.active_scans[scan_id]['scanner']
            scanner.stop_scan()
            
            # Move to results
            self.scan_results[scan_id] = {
                "target": self.active_scans[scan_id]['target'],
                "status": "stopped",
                "vulnerabilities": [v.to_dict() for v in scanner.vulnerabilities],
                "stats": scanner.stats,
                "duration": scanner.get_duration(),
                "completed_at": datetime.now().isoformat()
            }
            
            del self.active_scans[scan_id]
            
            return jsonify({
                "scan_id": scan_id,
                "status": "stopped",
                "message": "Scan stopped successfully"
            })
        
        @self.app.route('/api/v1/scans/<scan_id>/report', methods=['GET'])
        @self.require_api_key
        def get_report(scan_id):
            """Get scan report in specified format"""
            format = request.args.get('format', 'json').lower()
            
            # Find scan
            info = None
            scanner = None
            
            if scan_id in self.active_scans:
                scanner = self.active_scans[scan_id]['scanner']
                info = self.active_scans[scan_id]
            elif scan_id in self.scan_results:
                info = self.scan_results[scan_id]
            
            if not info:
                return jsonify({"error": "Scan not found"}), 404
            
            # Generate report based on format
            if format == 'json':
                report_data = {
                    "scan_id": scan_id,
                    "target": info['target'],
                    "status": info['status'],
                    "vulnerabilities": info.get('vulnerabilities', []),
                    "stats": info.get('stats', {}),
                    "duration": info.get('duration', 0)
                }
                return jsonify(report_data)
            
            elif format == 'html':
                if scanner:
                    report_data = scanner.generate_report()
                else:
                    # Create report generator
                    report_data = {
                        "target": info['target'],
                        "vulnerabilities": info.get('vulnerabilities', []),
                        "stats": info.get('stats', {})
                    }
                
                html_path = self.report_generator.generate_html(report_data, report_id=scan_id)
                if html_path and os.path.exists(html_path):
                    return send_file(html_path, as_attachment=True, 
                                   download_name=f"chombeza_report_{scan_id}.html")
            
            elif format == 'pdf':
                if scanner:
                    report_data = scanner.generate_report()
                else:
                    report_data = {
                        "target": info['target'],
                        "vulnerabilities": info.get('vulnerabilities', []),
                        "stats": info.get('stats', {})
                    }
                
                html_path = self.report_generator.generate_html(report_data, report_id=scan_id)
                if html_path:
                    pdf_path = self.report_generator.generate_pdf(html_path, report_data, report_id=scan_id)
                    if pdf_path and os.path.exists(pdf_path):
                        return send_file(pdf_path, as_attachment=True,
                                       download_name=f"chombeza_report_{scan_id}.pdf")
            
            elif format == 'csv':
                if scanner:
                    report_data = scanner.generate_report()
                else:
                    report_data = {
                        "target": info['target'],
                        "vulnerabilities": info.get('vulnerabilities', []),
                        "stats": info.get('stats', {})
                    }
                
                csv_path = self.report_generator.generate_csv(report_data, report_id=scan_id)
                if csv_path and os.path.exists(csv_path):
                    return send_file(csv_path, as_attachment=True,
                                   download_name=f"chombeza_report_{scan_id}.csv")
            
            return jsonify({"error": f"Unsupported format: {format}"}), 400
        
        @self.app.route('/api/v1/payloads', methods=['GET'])
        @self.require_api_key
        def list_payload_types():
            """List available payload types"""
            from core.payloads import payload_db
            return jsonify({
                "types": payload_db.get_all_types(),
                "counts": payload_db.get_stats()
            })
        
        @self.app.route('/api/v1/payloads/<vuln_type>', methods=['GET'])
        @self.require_api_key
        def get_payloads(vuln_type):
            """Get payloads for a vulnerability type"""
            from core.payloads import payload_db
            payloads = payload_db.get_payloads(vuln_type)
            return jsonify({
                "vuln_type": vuln_type,
                "count": len(payloads),
                "payloads": payloads[:100]  # Limit to 100
            })
        
        @self.app.route('/api/v1/payloads/<vuln_type>', methods=['POST'])
        @self.require_api_key
        def add_payload(vuln_type):
            """Add a new payload"""
            data = request.get_json()
            if not data or 'payload' not in data:
                return jsonify({"error": "Missing payload"}), 400
            
            from core.payloads import payload_db
            payload_db.add_payload(vuln_type, data['payload'])
            
            return jsonify({
                "message": "Payload added successfully",
                "vuln_type": vuln_type,
                "payload": data['payload'][:50] + "..." if len(data['payload']) > 50 else data['payload']
            })
        
        @self.app.route('/api/v1/config', methods=['GET'])
        @self.require_api_key
        def get_config():
            """Get current configuration"""
            if os.path.exists('config.json'):
                with open('config.json', 'r') as f:
                    config = json.load(f)
                return jsonify(config)
            return jsonify({"error": "Config not found"}), 404
        
        @self.app.route('/api/v1/config', methods=['POST'])
        @self.require_api_key
        def update_config():
            """Update configuration"""
            data = request.get_json()
            if not data:
                return jsonify({"error": "Missing config data"}), 400
            
            # Merge with existing config
            if os.path.exists('config.json'):
                with open('config.json', 'r') as f:
                    current = json.load(f)
                current.update(data)
            else:
                current = data
            
            # Save config
            with open('config.json', 'w') as f:
                json.dump(current, f, indent=2)
            
            return jsonify({
                "message": "Configuration updated successfully",
                "config": current
            })
        
        @self.app.route('/api/v1/plugins', methods=['GET'])
        @self.require_api_key
        def list_plugins():
            """List available plugins"""
            from core.scanner_enhanced import PluginManager
            plugin_manager = PluginManager()
            return jsonify({
                "plugins": list(plugin_manager.plugins.keys()),
                "hooks": list(plugin_manager.hooks.keys())
            })
        
        @self.app.errorhandler(404)
        def not_found(error):
            return jsonify({"error": "Endpoint not found"}), 404
        
        @self.app.errorhandler(500)
        def internal_error(error):
            return jsonify({"error": "Internal server error"}), 500
    
    def start(self):
        """Start the API server"""
        logger.info(f"Starting API server on {self.host}:{self.port}")
        logger.info(f"API Key: {self.api_key}")
        logger.info(f"Access API at: http://{self.host}:{self.port}/api/v1/status")
        
        # Run in a separate thread
        self.server_thread = threading.Thread(
            target=self.app.run,
            kwargs={
                "host": self.host,
                "port": self.port,
                "debug": False,
                "use_reloader": False
            }
        )
        self.server_thread.daemon = True
        self.server_thread.start()
    
    def stop(self):
        """Stop the API server"""
        # Flask doesn't have a built-in stop method in development server
        # For production, use Gunicorn or similar
        logger.info("API server stopping...")
        # Can't easily stop Flask dev server, will exit when main process ends

# API Client for easy integration
class APIClient:
    """
    Client for CHOMBEZA API
    """
    
    def __init__(self, base_url: str = "http://127.0.0.1:5001", api_key: Optional[str] = None):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key or self._load_api_key()
        self.session = None
        self._init_session()
    
    def _load_api_key(self) -> Optional[str]:
        """Load API key from file"""
        try:
            if os.path.exists('.api_key'):
                with open('.api_key', 'r') as f:
                    return f.read().strip()
        except:
            pass
        return None
    
    def _init_session(self):
        """Initialize requests session"""
        import requests
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        })
    
    def status(self) -> Dict:
        """Get server status"""
        response = self.session.get(f"{self.base_url}/api/v1/status")
        response.raise_for_status()
        return response.json()
    
    def start_scan(self, target: str, scan_type: str = "quick", 
                   config: Optional[Dict] = None, vuln_types: Optional[List[str]] = None) -> Dict:
        """Start a new scan"""
        data = {
            "target": target,
            "scan_type": scan_type
        }
        if config:
            data["config"] = config
        if vuln_types:
            data["vuln_types"] = vuln_types
        
        response = self.session.post(f"{self.base_url}/api/v1/scans", json=data)
        response.raise_for_status()
        return response.json()
    
    def list_scans(self) -> List[Dict]:
        """List all scans"""
        response = self.session.get(f"{self.base_url}/api/v1/scans")
        response.raise_for_status()
        return response.json().get('scans', [])
    
    def get_scan(self, scan_id: str) -> Dict:
        """Get scan details"""
        response = self.session.get(f"{self.base_url}/api/v1/scans/{scan_id}")
        response.raise_for_status()
        return response.json()
    
    def stop_scan(self, scan_id: str) -> Dict:
        """Stop a running scan"""
        response = self.session.post(f"{self.base_url}/api/v1/scans/{scan_id}/stop")
        response.raise_for_status()
        return response.json()
    
    def get_report(self, scan_id: str, format: str = "json") -> Any:
        """Get scan report"""
        response = self.session.get(
            f"{self.base_url}/api/v1/scans/{scan_id}/report",
            params={"format": format}
        )
        response.raise_for_status()
        
        if format == "json":
            return response.json()
        else:
            # Return raw content for files
            return response.content
    
    def get_payloads(self, vuln_type: Optional[str] = None) -> Dict:
        """Get payloads"""
        if vuln_type:
            response = self.session.get(f"{self.base_url}/api/v1/payloads/{vuln_type}")
        else:
            response = self.session.get(f"{self.base_url}/api/v1/payloads")
        response.raise_for_status()
        return response.json()
    
    def add_payload(self, vuln_type: str, payload: str) -> Dict:
        """Add a new payload"""
        response = self.session.post(
            f"{self.base_url}/api/v1/payloads/{vuln_type}",
            json={"payload": payload}
        )
        response.raise_for_status()
        return response.json()
    
    def get_config(self) -> Dict:
        """Get current configuration"""
        response = self.session.get(f"{self.base_url}/api/v1/config")
        response.raise_for_status()
        return response.json()
    
    def update_config(self, config: Dict) -> Dict:
        """Update configuration"""
        response = self.session.post(f"{self.base_url}/api/v1/config", json=config)
        response.raise_for_status()
        return response.json()

# Example usage
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="CHOMBEZA API Server")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--port", type=int, default=5001, help="Port to bind to")
    parser.add_argument("--api-key", help="API key (auto-generated if not provided)")
    parser.add_argument("--no-cors", action="store_true", help="Disable CORS")
    
    args = parser.parse_args()
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='[%(levelname)s] %(asctime)s - %(name)s: %(message)s'
    )
    
    # Start server
    server = APIServer(
        host=args.host,
        port=args.port,
        api_key=args.api_key,
        enable_cors=not args.no_cors
    )
    
    server.start()
    
    print(f"\n{'='*60}")
    print(f"CHOMBEZA API Server running on http://{args.host}:{args.port}")
    print(f"API Key: {server.api_key}")
    print(f"{'='*60}\n")
    
    try:
        # Keep main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down API server...")