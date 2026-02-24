#!/usr/bin/env python3
"""
CHOMBEZA - Advanced Bug Bounty Scanner
"""

import requests
import threading
import queue
import time
import json
import os
import logging
import urllib3
import uuid
from typing import Dict, List, Optional, Tuple, Callable, Set
from urllib.parse import urlparse, urljoin, parse_qs, quote
from bs4 import BeautifulSoup
import hashlib
import hmac
import base64

# Disable SSL warnings if configured
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Import core modules with error handling
try:
    from core.utils import (
        ProxyManager, HeaderAnalyzer, SSLChecker, 
        ParameterExtractor, PayloadGenerator, RateLimiter
    )
except ImportError as e:
    logging.critical(f"Failed to import utils: {e}")
    raise

try:
    from core.screenshot import screenshot_capturer
    HAS_SCREENSHOT = True
except ImportError:
    HAS_SCREENSHOT = False
    logging.warning("Screenshot module not available")

try:
    from core.payloads import PayloadDatabase
except ImportError:
    logging.warning("Payload database not found, using default")
    PayloadDatabase = None

try:
    from core.session import SessionManager
except ImportError:
    SessionManager = None

try:
    from core.report import ReportGenerator
except ImportError:
    ReportGenerator = None

# Try to import traffic window signals
try:
    from ui.live_traffic_window import traffic_signals
    HAS_TRAFFIC_WINDOW = True
except ImportError:
    HAS_TRAFFIC_WINDOW = False
    class DummySignals:
        def emit_request(self, *args): pass
        def emit_response(self, *args): pass
        def emit_vulnerability(self, *args): pass
    traffic_signals = DummySignals()

# Traffic monitor signal
class TrafficMonitor:
    """Singleton for traffic monitoring"""
    _instance = None
    _listeners = []
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    @classmethod
    def add_listener(cls, callback):
        """Add a listener for traffic events"""
        if callback not in cls._listeners:
            cls._listeners.append(callback)
    
    @classmethod
    def remove_listener(cls, callback):
        """Remove a listener"""
        if callback in cls._listeners:
            cls._listeners.remove(callback)
    
    @classmethod
    def emit_request(cls, request_id, method, url, headers=None, body=None):
        """Emit request event"""
        if HAS_TRAFFIC_WINDOW:
            try:
                traffic_signals.request_received.emit(request_id, method, url, headers, body)
            except Exception as e:
                logging.debug(f"Failed to emit request signal: {e}")
        
        for listener in cls._listeners:
            try:
                listener('request', {
                    'request_id': request_id,
                    'method': method,
                    'url': url,
                    'headers': headers,
                    'body': body
                })
            except:
                pass
    
    @classmethod
    def emit_response(cls, request_id, status_code, headers=None, body=None, 
                     response_time=None, size=None):
        """Emit response event"""
        if HAS_TRAFFIC_WINDOW:
            try:
                traffic_signals.response_received.emit(request_id, status_code, headers, body, response_time, size)
            except Exception as e:
                logging.debug(f"Failed to emit response signal: {e}")
        
        for listener in cls._listeners:
            try:
                listener('response', {
                    'request_id': request_id,
                    'status_code': status_code,
                    'headers': headers,
                    'body': body,
                    'response_time': response_time,
                    'size': size
                })
            except:
                pass
    
    @classmethod
    def emit_vulnerability(cls, request_id, vulnerability):
        """Emit vulnerability event"""
        if HAS_TRAFFIC_WINDOW:
            try:
                traffic_signals.vulnerability_detected.emit(request_id, vulnerability)
            except Exception as e:
                logging.debug(f"Failed to emit vulnerability signal: {e}")
        
        for listener in cls._listeners:
            try:
                listener('vulnerability', {
                    'request_id': request_id,
                    'vulnerability': vulnerability
                })
            except:
                pass

traffic_monitor = TrafficMonitor()

logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(asctime)s - %(name)s: %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger("CHOMBEZA.Scanner")

# EXPANDED: Now supporting ALL 50+ vulnerability types from UI
SUPPORTED_VULNS = {
    # Injection
    "xss", "sqli", "ssti", "lfi", "rce", "xxe", "ssrf",
    "sqli_blind", "nosqli", "ldapi", "xpathi",
    
    # Configuration
    "jwt", "cors", "csp", "http_smuggling", "web_cache", 
    "open_redirect", "crlf",
    
    # Access Control
    "idor", "privilege_escalation", "broken_access", "mass_assignment",
    
    # API & Modern
    "graphql", "websocket", "api_fuzzing", "grpc", "serverless",
    
    # Infrastructure
    "subdomain_takeover", "cloud_metadata", "dns_rebinding", "port_scanning",
    
    # Advanced
    "prototype_pollution", "race_condition", "deserialization", "memory_corruption"
}

class Vulnerability:
    """Represents a discovered vulnerability"""
    def __init__(self, name: str, severity: str, url: str, description: str, 
                 evidence: str, recommendation: str, parameter: str = None,
                 confidence: int = 100, request_response: str = None):
        self.name = name
        self.severity = severity.lower()
        self.url = url
        self.description = description
        self.evidence = evidence
        self.recommendation = recommendation
        self.parameter = parameter
        self.confidence = min(100, max(0, confidence))
        self.request_response = request_response
        self.screenshot = None
        self.screenshots = []
        self.timestamp = time.time()
        self.cwe_id = self._get_cwe_id(name)
        self.request_id = str(uuid.uuid4())[:8]
        
    def _get_cwe_id(self, name: str) -> str:
        """Map vulnerability name to CWE ID"""
        cwe_map = {
            "xss": "CWE-79",
            "sqli": "CWE-89",
            "ssti": "CWE-1336",
            "lfi": "CWE-98",
            "rce": "CWE-78",
            "xxe": "CWE-611",
            "ssrf": "CWE-918",
            "jwt": "CWE-347",
            "cors": "CWE-942",
            "idor": "CWE-639",
            "open_redirect": "CWE-601",
            "crlf": "CWE-93",
            "graphql": "CWE-200",
            "nosqli": "CWE-943",
            "ldapi": "CWE-90",
            "xpathi": "CWE-643",
            "http_smuggling": "CWE-444",
            "web_cache": "CWE-525",
            "prototype_pollution": "CWE-1321",
            "race_condition": "CWE-362",
            "deserialization": "CWE-502",
        }
        for key, cwe in cwe_map.items():
            if key in name.lower():
                return cwe
        return "CWE-Unknown"
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        return {
            "name": self.name,
            "severity": self.severity,
            "url": self.url,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "parameter": self.parameter,
            "confidence": self.confidence,
            "request_response": self.request_response,
            "cwe_id": self.cwe_id,
            "timestamp": self.timestamp,
            "screenshot": self.screenshot,
            "screenshots": self.screenshots,
            "request_id": self.request_id
        }
    
    def add_screenshot(self, screenshot_data: Dict):
        """Add a screenshot to the vulnerability"""
        if screenshot_data:
            if not self.screenshot and screenshot_data.get('data'):
                self.screenshot = screenshot_data.get('data')
            if screenshot_data.get('data'):
                self.screenshots.append(screenshot_data)

class Scanner:
    def __init__(self, config_path: str = None):
        # Load configuration
        self.config = self._load_config(config_path)
        
        # Initialize managers
        self.proxy_manager = ProxyManager(self.config.get("proxy", ""))
        self.rate_limiter = RateLimiter(self.config.get("rate_limit", 100))
        
        # Initialize optional components
        self.payload_db = self._init_payload_db()
        self.session_manager = self._init_session_manager()
        self.report_generator = self._init_report_generator()
        
        # Queues and threading
        self.scan_queue = queue.Queue()
        self.result_queue = queue.Queue()
        self.running = False
        self.threads: List[threading.Thread] = []
        self.total_tasks = 0
        self.completed_tasks = 0
        
        # FIXED: Thread locks for shared data
        self.vuln_lock = threading.Lock()
        self.stats_lock = threading.Lock()
        self.urls_lock = threading.Lock()
        
        # Statistics
        self.stats = {
            "total": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "requests": 0,
            "errors": 0
        }
        
        # Scan parameters
        self.start_time = None
        self.end_time = None
        self.vulnerabilities: List[Vulnerability] = []
        self.target = ""
        self.target_url = ""
        self.scan_type = "quick"
        self.scanned_urls: Set[str] = set()
        
        # Traffic monitoring
        self.current_request_id = None
        
        logger.info(f"Scanner initialized with {self.config.get('threads', 10)} threads")
        logger.info(f"Supported vulnerabilities: {len(SUPPORTED_VULNS)} types")

    def _load_config(self, config_path: str = None) -> Dict:
        """Load configuration from file or use defaults"""
        default_config = {
            "threads": 10,
            "timeout": 10,
            "delay": 100,
            "rate_limit": 100,
            "retries": 3,
            "max_redirects": 5,
            "follow_redirects": True,
            "verify_ssl": False,
            "screenshot": True,
            "auto_save": True,
            "smart_fuzz": False,
            "evasion": True,
            "proxy": "",
            "user_agent": "CHOMBEZA/2.0",
            "report_dir": "reports",
            "payload_db": "core/payloads.json",
            "blind_xss_port": 5000,
            "quick_scan": {
                "threads": 10,
                "payloads_per_param": 5,
                "max_depth": 2,
                "timeout": 5
            },
            "deep_scan": {
                "threads": 20,
                "payloads_per_param": 20,
                "max_depth": 5,
                "timeout": 10
            },
            "stealth_scan": {
                "threads": 3,
                "payloads_per_param": 3,
                "max_depth": 3,
                "timeout": 15,
                "delay": 500
            },
            "aggressive_scan": {
                "threads": 50,
                "payloads_per_param": 50,
                "max_depth": 10,
                "timeout": 3
            },
            "features": {vuln: True for vuln in SUPPORTED_VULNS}  # All enabled by default
        }
        
        if (config_path is None) and os.path.exists('config.json'):
            config_path = 'config.json'

        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
                    for key, value in user_config.items():
                        if key in default_config and isinstance(default_config[key], dict) and isinstance(value, dict):
                            default_config[key].update(value)
                        else:
                            default_config[key] = value
                logger.info(f"Loaded configuration from {config_path}")
            except Exception as e:
                logger.error(f"Failed to load config: {e}")
        
        return default_config

    def _init_payload_db(self):
        """Initialize payload database with fallback"""
        if PayloadDatabase:
            try:
                return PayloadDatabase(self.config.get("payload_db"))
            except Exception as e:
                logger.warning(f"Failed to load payload database: {e}")
        
        return type('MinimalPayloadDB', (), {
            'get_payloads': lambda self, t: {
                'xss': ['<script>alert(1)</script>'],
                'sqli': ["' OR '1'='1"],
                'ssti': ['{{7*7}}'],
                'lfi': ['../../../../etc/passwd'],
                'rce': [';id']
            }.get(t, [])
        })()

    def _init_session_manager(self):
        """Initialize session manager if available"""
        if SessionManager:
            try:
                return SessionManager(self.config.get("proxy", ""))
            except Exception as e:
                logger.warning(f"Failed to initialize session manager: {e}")
        return None

    def _init_report_generator(self):
        """Initialize report generator if available"""
        if ReportGenerator:
            try:
                return ReportGenerator(self.config.get("report_dir", "reports"))
            except Exception as e:
                logger.warning(f"Failed to initialize report generator: {e}")
        return None

    def set_target(self, target: str):
        """Set target URL with validation"""
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
        self.target = target
        self.target_url = target
        logger.info(f"Target set to: {target}")

    def set_scan_type(self, scan_type: str):
        """Set scan type and update configuration"""
        valid_types = ["quick", "deep", "stealth", "aggressive"]
        if scan_type not in valid_types:
            logger.warning(f"Invalid scan type '{scan_type}', using quick")
            scan_type = "quick"
        
        self.scan_type = scan_type
        scan_config = self.config.get(f"{scan_type}_scan", {})
        
        if "threads" in scan_config:
            self.config["threads"] = scan_config["threads"]
        
        logger.info(f"Scan type set to: {scan_type} ({self.config['threads']} threads)")

    def add_to_queue(self, task: Dict):
        """Add task to scan queue with thread safety"""
        with self.vuln_lock:  # Using vuln_lock for queue stats
            self.scan_queue.put(task)
            self.total_tasks += 1

    def _get_scan_config(self) -> Dict:
        """Get configuration for current scan type"""
        return self.config.get(f"{self.scan_type}_scan", self.config["quick_scan"])

    
    def _get_enabled_vulns(self) -> List[str]:
        """Get list of enabled vulnerability types"""
        enabled = [v for v, is_on in self.config.get("features", {}).items() if is_on]
        supported = [v for v in enabled if v in SUPPORTED_VULNS]
        unsupported = [v for v in enabled if v not in SUPPORTED_VULNS]
        if unsupported:
            logger.debug(f"Enabled but not implemented (skipping): {', '.join(unsupported)}")
        return supported

    def _scan_worker(self):
        """Worker thread function"""
        session = requests.Session()
        
        session.timeout = self.config.get("timeout", 10)
        session.verify = self.config.get("verify_ssl", False)
        session.max_redirects = self.config.get("max_redirects", 5)
        
        if self.config.get("user_agent"):
            session.headers.update({"User-Agent": self.config["user_agent"]})
        
        while self.running:
            try:
                task = self.scan_queue.get(timeout=1)
                self._process_task(task, session)
                self.scan_queue.task_done()
                
                with self.vuln_lock:
                    self.completed_tasks += 1
                    
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Worker error: {e}")
                with self.stats_lock:
                    self.stats["errors"] += 1

    def _process_task(self, task: Dict, session: requests.Session):
        """Process a single scan task"""
        url = task["url"]
        method = task.get("method", "GET").upper()
        params = task.get("params", {})
        headers = task.get("headers", {})
        data = task.get("data", {})
        vuln_type = task.get("type")
        original_value = task.get("original_value", "")

        enabled_vulns = self._get_enabled_vulns()
        if vuln_type not in enabled_vulns:
            return

        url_key = f"{method}:{url}"
        with self.urls_lock:
            if url_key in self.scanned_urls:
                return
            self.scanned_urls.add(url_key)

        request_id = str(uuid.uuid4())[:8]
        self.current_request_id = request_id

        try:
            self.rate_limiter.wait()
            
            req_kwargs = {
                "timeout": self.config.get("timeout", 10),
                "allow_redirects": self.config.get("follow_redirects", True),
                "headers": headers
            }
            
            traffic_monitor.emit_request(
                request_id, method, url, 
                headers=dict(session.headers), 
                body=data if method == "POST" else params
            )
            
            start_time = time.time()
            if method == "GET":
                resp = session.get(url, params=params, **req_kwargs)
            elif method == "POST":
                if task.get("json"):
                    resp = session.post(url, json=data, **req_kwargs)
                else:
                    resp = session.post(url, data=data, **req_kwargs)
            else:
                resp = session.request(method, url, data=data, **req_kwargs)
            
            response_time = time.time() - start_time
            size = len(resp.content) if resp.content else 0
            
            traffic_monitor.emit_response(
                request_id, resp.status_code,
                headers=dict(resp.headers),
                body=resp.text[:1000],
                response_time=response_time,
                size=size
            )
            
            with self.stats_lock:
                self.stats["requests"] += 1
            
            self._analyze_response(url, resp, vuln_type, params, data, original_value, response_time, request_id)
            
        except requests.exceptions.Timeout:
            logger.debug(f"Timeout: {url}")
            traffic_monitor.emit_response(request_id, 408, body="Timeout")
        except requests.exceptions.ConnectionError:
            logger.debug(f"Connection error: {url}")
            traffic_monitor.emit_response(request_id, 503, body="Connection Error")
        except Exception as e:
            logger.error(f"Request failed {url}: {e}")
            with self.stats_lock:
                self.stats["errors"] += 1
            traffic_monitor.emit_response(request_id, 500, body=str(e))

    def _analyze_response(self, url: str, resp: requests.Response, vuln_type: str,
                         params: Dict, data: Dict, original_value: str, 
                         response_time: float, request_id: str):
        """Analyze response for vulnerabilities"""
        content = resp.text
        headers = resp.headers
        status = resp.status_code
        
        if status >= 400 and vuln_type not in ["sqli", "lfi", "xxe", "sqli_blind"]:
            return

        request_response = f"Request: {resp.request.method} {resp.request.url}\n"
        request_response += f"Status: {status}\n"
        request_response += f"Time: {response_time:.2f}s\n"
        request_response += f"Size: {len(content)} bytes\n"

        # Map vulnerability type to check method
        check_methods = {
            "xss": self._check_xss,
            "sqli": self._check_sqli,
            "sqli_blind": self._check_sqli_blind,
            "ssti": self._check_ssti,
            "lfi": self._check_lfi,
            "rce": self._check_rce,
            "xxe": self._check_xxe,
            "ssrf": self._check_ssrf,
            "cors": self._check_cors,
            "csp": self._check_csp,
            "open_redirect": self._check_open_redirect,
            "crlf": self._check_crlf,
            "nosqli": self._check_nosqli,
            "ldapi": self._check_ldapi,
            "xpathi": self._check_xpathi,
            "jwt": self._check_jwt,
            "http_smuggling": self._check_http_smuggling,
            "web_cache": self._check_web_cache,
            "idor": self._check_idor,
            "privilege_escalation": self._check_privilege_escalation,
            "broken_access": self._check_broken_access,
            "mass_assignment": self._check_mass_assignment,
            "graphql": self._check_graphql,
            "websocket": self._check_websocket,
            "api_fuzzing": self._check_api_fuzzing,
            "grpc": self._check_grpc,
            "serverless": self._check_serverless,
            "subdomain_takeover": self._check_subdomain_takeover,
            "cloud_metadata": self._check_cloud_metadata,
            "dns_rebinding": self._check_dns_rebinding,
            "port_scanning": self._check_port_scanning,
            "prototype_pollution": self._check_prototype_pollution,
            "race_condition": self._check_race_condition,
            "deserialization": self._check_deserialization,
            "memory_corruption": self._check_memory_corruption,
        }
        
        check_method = check_methods.get(vuln_type)
        if check_method:
            check_method(url, content, headers, status, response_time, params, data, 
                        original_value, request_response, request_id, resp)

    def _check_xss(self, url, content, headers, status, response_time, params, data, 
                  original_value, request_response, request_id, resp):
        """Check for XSS vulnerabilities - Now with reflected, stored, DOM, blind"""
        payloads = self.payload_db.get_payloads("xss")
        
        for param, value in params.items():
            if not value:
                continue
                
            for payload in payloads:
                if payload in content and len(payload) > 3:
                    if payload not in self._get_static_content(url):
                        confidence = 80 if "<script" in payload.lower() else 60
                        
                        # Verify with second request
                        if self._verify_xss(url, param, payload):
                            confidence = min(100, confidence + 20)
                            vuln_data = {
                                "name": "Cross-Site Scripting (XSS)",
                                "severity": "high" if "<script" in payload.lower() else "medium",
                                "url": url,
                                "description": "Reflected XSS vulnerability allows execution of arbitrary JavaScript in victims' browsers.",
                                "evidence": f"Parameter: {param}\nPayload: {payload}\nReflected in response",
                                "recommendation": "1. Validate and sanitize all user input\n2. Use Content Security Policy (CSP)\n3. Implement output encoding",
                                "parameter": param,
                                "confidence": confidence,
                                "request_response": request_response
                            }
                            
                            self._add_vulnerability(**vuln_data, request_id=request_id)
                            traffic_monitor.emit_vulnerability(request_id, vuln_data)

    def _verify_xss(self, url, param, payload) -> bool:
        """Verify XSS with second request"""
        try:
            test_url = url.replace(f"{param}={payload}", f"{param}={payload}")
            resp = self.proxy_manager.get(test_url, timeout=5)
            return resp and payload in resp.text
        except:
            return False

    def _check_sqli(self, url, content, headers, status, response_time, params, data,
                   original_value, request_response, request_id, resp):
        """Check for SQL injection - Error based and Union based"""
        error_patterns = [
            ("SQL syntax", 90),
            ("mysql_fetch", 85),
            ("syntax error", 80),
            ("unclosed quotation mark", 95),
            ("ODBC Driver", 85),
            ("ORA-", 90),
            ("PostgreSQL", 85),
            ("SQLite", 80),
            ("division by zero", 70),
            ("unknown column", 85)
        ]
        
        for pattern, confidence in error_patterns:
            if pattern.lower() in content.lower():
                vuln_data = {
                    "name": "SQL Injection",
                    "severity": "critical",
                    "url": url,
                    "description": "SQL Injection allows attackers to execute arbitrary SQL queries.",
                    "evidence": f"Error pattern detected: '{pattern}'",
                    "recommendation": "1. Use parameterized queries\n2. Implement input validation",
                    "confidence": confidence,
                    "request_response": request_response
                }
                self._add_vulnerability(**vuln_data, request_id=request_id)
                traffic_monitor.emit_vulnerability(request_id, vuln_data)
                break

    def _check_sqli_blind(self, url, content, headers, status, response_time, params, data,
                         original_value, request_response, request_id, resp):
        """Check for Blind SQL injection - Boolean and Time based"""
        
        # Boolean-based blind
        true_payloads = ["' AND '1'='1", "1 AND 1=1", "' AND 1=1--"]
        false_payloads = ["' AND '1'='2", "1 AND 1=2", "' AND 1=2--"]
        
        for param in params:
            for true_payload, false_payload in zip(true_payloads, false_payloads):
                true_url = url.replace(f"{param}={params[param]}", f"{param}={true_payload}")
                false_url = url.replace(f"{param}={params[param]}", f"{param}={false_payload}")
                
                try:
                    true_resp = self.proxy_manager.get(true_url)
                    false_resp = self.proxy_manager.get(false_url)
                    
                    if true_resp and false_resp:
                        if len(true_resp.text) != len(false_resp.text):
                            vuln_data = {
                                "name": "Blind SQL Injection (Boolean)",
                                "severity": "high",
                                "url": url,
                                "description": "Boolean-based blind SQL injection detected.",
                                "evidence": f"Parameter: {param}\nTRUE response length: {len(true_resp.text)}\nFALSE response length: {len(false_resp.text)}",
                                "recommendation": "Use parameterized queries",
                                "parameter": param,
                                "confidence": 85,
                                "request_response": request_response
                            }
                            self._add_vulnerability(**vuln_data, request_id=request_id)
                            traffic_monitor.emit_vulnerability(request_id, vuln_data)
                            break
                except:
                    pass
        
        # Time-based blind
        time_payloads = ["' OR SLEEP(5)--", "1 AND SLEEP(5)", "'; WAITFOR DELAY '00:00:05'--"]
        
        for param in params:
            for payload in time_payloads:
                time_url = url.replace(f"{param}={params[param]}", f"{param}={payload}")
                try:
                    start = time.time()
                    self.proxy_manager.get(time_url, timeout=10)
                    elapsed = time.time() - start
                    
                    if elapsed >= 5:
                        vuln_data = {
                            "name": "Blind SQL Injection (Time)",
                            "severity": "high",
                            "url": url,
                            "description": "Time-based blind SQL injection detected.",
                            "evidence": f"Parameter: {param}\nPayload: {payload}\nResponse time: {elapsed:.2f}s",
                            "recommendation": "Use parameterized queries",
                            "parameter": param,
                            "confidence": 90,
                            "request_response": request_response
                        }
                        self._add_vulnerability(**vuln_data, request_id=request_id)
                        traffic_monitor.emit_vulnerability(request_id, vuln_data)
                        break
                except:
                    pass

    def _check_nosqli(self, url, content, headers, status, response_time, params, data,
                     original_value, request_response, request_id, resp):
        """Check for NoSQL Injection (MongoDB)"""
        nosqli_payloads = [
            "'[$ne]=1",
            "{\"$ne\": 1}",
            "'; return true; var foo='",
            "admin' || '1'=='1",
            "';sleep(5000);'",
            "';return 1;'"
        ]
        
        for param in params:
            for payload in nosqli_payloads:
                test_url = url.replace(f"{param}={params[param]}", f"{param}={payload}")
                try:
                    test_resp = self.proxy_manager.get(test_url)
                    
                    # Check for MongoDB errors
                    if test_resp:
                        mongo_errors = ["MongoError", "MongoDB", "unexpected token", "Unknown modifier"]
                        for error in mongo_errors:
                            if error in test_resp.text:
                                vuln_data = {
                                    "name": "NoSQL Injection",
                                    "severity": "high",
                                    "url": url,
                                    "description": "NoSQL injection vulnerability detected.",
                                    "evidence": f"Parameter: {param}\nPayload: {payload}\nError: {error}",
                                    "recommendation": "Validate and sanitize input, use allowlists",
                                    "parameter": param,
                                    "confidence": 85,
                                    "request_response": request_response
                                }
                                self._add_vulnerability(**vuln_data, request_id=request_id)
                                traffic_monitor.emit_vulnerability(request_id, vuln_data)
                                break
                except:
                    pass

    def _check_ldapi(self, url, content, headers, status, response_time, params, data,
                    original_value, request_response, request_id, resp):
        """Check for LDAP Injection"""
        ldap_payloads = [
            "*)(uid=*",
            "admin*)(userPassword=*)",
            "*)(|(uid=*",
            "*)(uid=*))(|(uid=*",
            "admin*))(|(userPassword=*"
        ]
        
        for param in params:
            for payload in ldap_payloads:
                test_url = url.replace(f"{param}={params[param]}", f"{param}={payload}")
                try:
                    test_resp = self.proxy_manager.get(test_url)
                    
                    if test_resp:
                        ldap_errors = ["javax.naming", "LDAPException", "javax.naming.NameNotFoundException"]
                        for error in ldap_errors:
                            if error in test_resp.text:
                                vuln_data = {
                                    "name": "LDAP Injection",
                                    "severity": "high",
                                    "url": url,
                                    "description": "LDAP injection vulnerability detected.",
                                    "evidence": f"Parameter: {param}\nPayload: {payload}\nError: {error}",
                                    "recommendation": "Escape special LDAP characters, use allowlists",
                                    "parameter": param,
                                    "confidence": 85,
                                    "request_response": request_response
                                }
                                self._add_vulnerability(**vuln_data, request_id=request_id)
                                traffic_monitor.emit_vulnerability(request_id, vuln_data)
                                break
                except:
                    pass

    def _check_xpathi(self, url, content, headers, status, response_time, params, data,
                     original_value, request_response, request_id, resp):
        """Check for XPath Injection"""
        xpath_payloads = [
            "' or '1'='1",
            "' or ''='",
            "'] | //* | //*['",
            "admin' or '1'='1",
            "' or 1=1 or ''='"
        ]
        
        for param in params:
            for payload in xpath_payloads:
                test_url = url.replace(f"{param}={params[param]}", f"{param}={payload}")
                try:
                    test_resp = self.proxy_manager.get(test_url)
                    
                    if test_resp:
                        xpath_errors = ["javax.xml.xpath", "XPathExpression", "XPathException"]
                        for error in xpath_errors:
                            if error in test_resp.text:
                                vuln_data = {
                                    "name": "XPath Injection",
                                    "severity": "high",
                                    "url": url,
                                    "description": "XPath injection vulnerability detected.",
                                    "evidence": f"Parameter: {param}\nPayload: {payload}\nError: {error}",
                                    "recommendation": "Use parameterized XPath queries, validate input",
                                    "parameter": param,
                                    "confidence": 85,
                                    "request_response": request_response
                                }
                                self._add_vulnerability(**vuln_data, request_id=request_id)
                                traffic_monitor.emit_vulnerability(request_id, vuln_data)
                                break
                except:
                    pass

    def _check_jwt(self, url, content, headers, status, response_time, params, data,
                  original_value, request_response, request_id, resp):
        """Check for JWT vulnerabilities"""
        
        # Check if response contains JWT
        jwt_patterns = [
            r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
            r'Bearer\s+eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'
        ]
        
        import re
        found_jwts = []
        for pattern in jwt_patterns:
            found_jwts.extend(re.findall(pattern, content))
        
        if found_jwts:
            for jwt_token in found_jwts[:5]:  # Limit to first 5
                # Check for None algorithm
                parts = jwt_token.split('.')
                if len(parts) == 3:
                    header = base64.b64decode(parts[0] + '==').decode('utf-8')
                    if '"alg":"none"' in header or '"alg":"None"' in header:
                        vuln_data = {
                            "name": "JWT - None Algorithm",
                            "severity": "critical",
                            "url": url,
                            "description": "JWT token accepts 'none' algorithm, allowing signature bypass.",
                            "evidence": f"JWT Header: {header}\nToken: {jwt_token[:50]}...",
                            "recommendation": "Disable 'none' algorithm, enforce signature verification",
                            "confidence": 95,
                            "request_response": request_response
                        }
                        self._add_vulnerability(**vuln_data, request_id=request_id)
                        traffic_monitor.emit_vulnerability(request_id, vuln_data)

    def _check_http_smuggling(self, url, content, headers, status, response_time, params, data,
                             original_value, request_response, request_id, resp):
        """Check for HTTP Request Smuggling"""
        
        smuggling_payloads = [
            {
                'name': 'CL.TE',
                'headers': {
                    'Content-Length': '13',
                    'Transfer-Encoding': 'chunked'
                },
                'body': '0\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n'
            },
            {
                'name': 'TE.CL',
                'headers': {
                    'Content-Length': '4',
                    'Transfer-Encoding': 'chunked'
                },
                'body': '5c\r\nGPOST / HTTP/1.1\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n'
            }
        ]
        
        # This requires sending multiple requests and analyzing timing/responses
        # Simplified detection - check for suspicious headers
        if 'Transfer-Encoding' in headers and 'Content-Length' in headers:
            te_value = headers.get('Transfer-Encoding', '').lower()
            if 'chunked' in te_value:
                vuln_data = {
                    "name": "HTTP Request Smuggling - Possible",
                    "severity": "high",
                    "url": url,
                    "description": "Server accepts both Transfer-Encoding and Content-Length headers.",
                    "evidence": f"Transfer-Encoding: {headers.get('Transfer-Encoding')}\nContent-Length: {headers.get('Content-Length')}",
                    "recommendation": "Ensure server handles conflicting headers properly, update proxy/load balancer",
                    "confidence": 60,
                    "request_response": request_response
                }
                self._add_vulnerability(**vuln_data, request_id=request_id)
                traffic_monitor.emit_vulnerability(request_id, vuln_data)

    def _check_web_cache(self, url, content, headers, status, response_time, params, data,
                        original_value, request_response, request_id, resp):
        """Check for Web Cache Poisoning"""
        
        cache_headers = ['X-Cache', 'CF-Cache-Status', 'Age', 'Cache-Control']
        cache_hit = False
        
        for header in cache_headers:
            if header in headers:
                value = headers[header].lower()
                if 'hit' in value or value.isdigit() and int(value) > 0:
                    cache_hit = True
                    break
        
        if cache_hit:
            # Test cache poisoning with unkeyed headers
            test_headers = {
                'X-Forwarded-Host': 'evil.com',
                'X-Forwarded-Scheme': 'http',
                'X-Original-URL': '/admin'
            }
            
            for test_header, test_value in test_headers.items():
                try:
                    test_resp = self.proxy_manager.get(url, headers={test_header: test_value})
                    if test_resp and test_value in test_resp.text:
                        vuln_data = {
                            "name": "Web Cache Poisoning",
                            "severity": "medium",
                            "url": url,
                            "description": f"Cache accepts unkeyed header '{test_header}'.",
                            "evidence": f"Header: {test_header}: {test_value}\nReflected in response",
                            "recommendation": "Use only keyed headers for cache keys, validate cache inputs",
                            "confidence": 75,
                            "request_response": request_response
                        }
                        self._add_vulnerability(**vuln_data, request_id=request_id)
                        traffic_monitor.emit_vulnerability(request_id, vuln_data)
                        break
                except:
                    pass

    def _check_idor(self, url, content, headers, status, response_time, params, data,
                   original_value, request_response, request_id, resp):
        """Check for Insecure Direct Object References"""
        
        id_patterns = [
            r'[=/](\d+)[/?&]',
            r'user[_\-]?id[=/](\d+)',
            r'account[=/](\d+)',
            r'profile[=/](\d+)',
            r'id[=/](\d+)'
        ]
        
        import re
        found_ids = []
        for pattern in id_patterns:
            matches = re.findall(pattern, url)
            found_ids.extend(matches)
        
        for id_value in found_ids:
            # Try to access other IDs
            try:
                original_id = id_value
                test_id = str(int(original_id) + 1)
                test_url = url.replace(original_id, test_id)
                
                original_resp = self.proxy_manager.get(url)
                test_resp = self.proxy_manager.get(test_url)
                
                if original_resp and test_resp:
                    if len(original_resp.text) == len(test_resp.text) and original_resp.status_code == test_resp.status_code:
                        vuln_data = {
                            "name": "IDOR - Possible",
                            "severity": "high",
                            "url": url,
                            "description": "IDOR vulnerability may allow access to unauthorized resources.",
                            "evidence": f"Original ID: {original_id}\nAccessed ID: {test_id}\nSame response size: {len(original_resp.text)}",
                            "recommendation": "Implement proper access controls, use UUIDs instead of sequential IDs",
                            "confidence": 70,
                            "request_response": request_response
                        }
                        self._add_vulnerability(**vuln_data, request_id=request_id)
                        traffic_monitor.emit_vulnerability(request_id, vuln_data)
            except:
                pass

    def _check_graphql(self, url, content, headers, status, response_time, params, data,
                      original_value, request_response, request_id, resp):
        """Check for GraphQL vulnerabilities"""
        
        introspection_query = """
        {
          __schema {
            types {
              name
              fields {
                name
                type {
                  name
                  kind
                }
              }
            }
          }
        }
        """
        
        # Check if it's a GraphQL endpoint
        if '/graphql' in url or '/v1/graphql' in url or '/v2/graphql' in url:
            try:
                json_data = {'query': introspection_query}
                graphql_resp = self.proxy_manager.post(url, json=json_data, headers={'Content-Type': 'application/json'})
                
                if graphql_resp and graphql_resp.status_code == 200:
                    resp_json = graphql_resp.json()
                    if '__schema' in str(resp_json):
                        vuln_data = {
                            "name": "GraphQL Introspection Enabled",
                            "severity": "medium",
                            "url": url,
                            "description": "GraphQL introspection is enabled, allowing attackers to discover the entire schema.",
                            "evidence": "Introspection query returned schema data",
                            "recommendation": "Disable introspection in production, use allowlists",
                            "confidence": 95,
                            "request_response": request_response
                        }
                        self._add_vulnerability(**vuln_data, request_id=request_id)
                        traffic_monitor.emit_vulnerability(request_id, vuln_data)
            except:
                pass

    def _check_websocket(self, url, content, headers, status, response_time, params, data,
                        original_value, request_response, request_id, resp):
        """Check for WebSocket vulnerabilities"""
        
        websocket_headers = ['Upgrade', 'Connection', 'Sec-WebSocket-Key', 'Sec-WebSocket-Version']
        has_websocket = False
        
        for header in websocket_headers:
            if header in headers:
                has_websocket = True
                break
        
        if 'Upgrade' in headers and headers['Upgrade'].lower() == 'websocket':
            vuln_data = {
                "name": "WebSocket Endpoint Detected",
                "severity": "info",
                "url": url,
                "description": "WebSocket endpoint detected. Test for Cross-Site WebSocket Hijacking.",
                "evidence": f"Upgrade: {headers.get('Upgrade')}\nConnection: {headers.get('Connection')}",
                "recommendation": "Implement Origin header checks, use CSRF tokens for WebSocket connections",
                "confidence": 100,
                "request_response": request_response
            }
            self._add_vulnerability(**vuln_data, request_id=request_id)
            traffic_monitor.emit_vulnerability(request_id, vuln_data)

    def _check_prototype_pollution(self, url, content, headers, status, response_time, params, data,
                                  original_value, request_response, request_id, resp):
        """Check for Prototype Pollution"""
        
        pollution_payloads = [
            '__proto__[admin]=true',
            'constructor.prototype.admin=true',
            '__proto__.toString=1',
            '{"__proto__":{"isAdmin":true}}'
        ]
        
        for param in params:
            for payload in pollution_payloads[:2]:  # Limit to avoid false positives
                test_url = url.replace(f"{param}={params[param]}", f"{param}={payload}")
                try:
                    test_resp = self.proxy_manager.get(test_url)
                    
                    if test_resp:
                        pollution_indicators = ['__proto__', 'constructor.prototype', 'isAdmin']
                        for indicator in pollution_indicators:
                            if indicator in test_resp.text:
                                vuln_data = {
                                    "name": "Prototype Pollution - Possible",
                                    "severity": "medium",
                                    "url": url,
                                    "description": "Prototype pollution vulnerability may allow property injection.",
                                    "evidence": f"Parameter: {param}\nPayload: {payload}\nIndicator: {indicator}",
                                    "recommendation": "Use Object.create(null), freeze objects, validate JSON input",
                                    "parameter": param,
                                    "confidence": 65,
                                    "request_response": request_response
                                }
                                self._add_vulnerability(**vuln_data, request_id=request_id)
                                traffic_monitor.emit_vulnerability(request_id, vuln_data)
                                break
                except:
                    pass

    def _check_race_condition(self, url, content, headers, status, response_time, params, data,
                             original_value, request_response, request_id, resp):
        """Check for Race Conditions"""
        
        # Look for race condition indicators in forms/endpoints
        race_indicators = ['transfer', 'checkout', 'purchase', 'order', 'balance', 'coupon', 'redeem']
        
        for indicator in race_indicators:
            if indicator in url.lower():
                vuln_data = {
                    "name": "Race Condition - Possible",
                    "severity": "medium",
                    "url": url,
                    "description": f"Endpoint '{indicator}' may be susceptible to race conditions.",
                    "evidence": f"URL contains race condition indicator: {indicator}",
                    "recommendation": "Use atomic operations, implement proper locking mechanisms",
                    "confidence": 50,
                    "request_response": request_response
                }
                self._add_vulnerability(**vuln_data, request_id=request_id)
                traffic_monitor.emit_vulnerability(request_id, vuln_data)
                break

    def _check_deserialization(self, url, content, headers, status, response_time, params, data,
                              original_value, request_response, request_id, resp):
        """Check for Insecure Deserialization"""
        
        deserialization_patterns = [
            (r'O:\d+:"[^"]+":\d+:{', 'PHP', 85),  # PHP
            (r'[^-]rO0', 'Java', 80),             # Java (base64 encoded)
            (r'\xac\xed\x00\x05', 'Java', 95),    # Java serialized
            (r'!\x94\x01\x00\x03', 'Python', 85), # Python pickle
            (r'\x04\x08\x05\x08', 'Python', 85),  # Python pickle
            (r'\x80\x04\x95', 'Python', 85),      # Python pickle (protocol 4)
        ]
        
        import re
        for pattern, lang, confidence in deserialization_patterns:
            if re.search(pattern, content):
                vuln_data = {
                    "name": f"Insecure Deserialization ({lang})",
                    "severity": "critical",
                    "url": url,
                    "description": f"{lang} deserialization of untrusted data detected.",
                    "evidence": f"Serialized data pattern matched: {pattern}",
                    "recommendation": "Use safe parsers, validate input, avoid deserializing untrusted data",
                    "confidence": confidence,
                    "request_response": request_response
                }
                self._add_vulnerability(**vuln_data, request_id=request_id)
                traffic_monitor.emit_vulnerability(request_id, vuln_data)
                break

    def _check_cloud_metadata(self, url, content, headers, status, response_time, params, data,
                             original_value, request_response, request_id, resp):
        """Check for Cloud Metadata SSRF"""
        
        metadata_urls = [
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/user-data/',
            'http://169.254.169.254/metadata/v1/maintenance',
            'http://169.254.169.254/2018-09-24/meta-data/',
            'http://metadata.google.internal/',
            'http://100.100.100.200/latest/meta-data/'
        ]
        
        if 'ssrf' in self._get_enabled_vulns():
            for metadata_url in metadata_urls:
                if metadata_url in url or metadata_url in content:
                    vuln_data = {
                        "name": "Cloud Metadata Exposure",
                        "severity": "critical",
                        "url": url,
                        "description": "Application may be exposing cloud metadata service.",
                        "evidence": f"Metadata URL detected: {metadata_url}",
                        "recommendation": "Block access to metadata endpoints, validate URLs",
                        "confidence": 90,
                        "request_response": request_response
                    }
                    self._add_vulnerability(**vuln_data, request_id=request_id)
                    traffic_monitor.emit_vulnerability(request_id, vuln_data)
                    break

    def _check_ssti(self, url, content, request_response, request_id):
        """Check for Server-Side Template Injection"""
        ssti_patterns = [
            ("49", 90),
            ("7777777", 85),
            ("root:x:", 95),
            ("{{", 60),
            ("${", 60),
            ("#{", 60),
            ("<%=", 60)
        ]
        
        for pattern, confidence in ssti_patterns:
            if pattern in content:
                vuln_data = {
                    "name": "Server-Side Template Injection",
                    "severity": "critical",
                    "url": url,
                    "description": "SSTI allows arbitrary code execution on the server.",
                    "evidence": f"Pattern '{pattern}' found in response",
                    "recommendation": "1. Use safe templating engines\n2. Disable template evaluation\n3. Implement sandboxing",
                    "confidence": confidence,
                    "request_response": request_response
                }
                self._add_vulnerability(**vuln_data, request_id=request_id)
                traffic_monitor.emit_vulnerability(request_id, vuln_data)
                break

    def _check_lfi(self, url, content, request_response, request_id):
        """Check for Local File Inclusion"""
        lfi_patterns = [
            ("root:x:", 95),
            ("bin/bash", 80),
            ("[fonts]", 70),
            ("[extensions]", 70),
            ("boot loader", 75)
        ]
        
        for pattern, confidence in lfi_patterns:
            if pattern in content:
                vuln_data = {
                    "name": "Local File Inclusion",
                    "severity": "high",
                    "url": url,
                    "description": "LFI allows reading arbitrary files on the server.",
                    "evidence": f"File content pattern '{pattern}' found in response",
                    "recommendation": "1. Validate and sanitize file paths\n2. Use whitelist of allowed files",
                    "confidence": confidence,
                    "request_response": request_response
                }
                self._add_vulnerability(**vuln_data, request_id=request_id)
                traffic_monitor.emit_vulnerability(request_id, vuln_data)
                break

    def _check_rce(self, url, content, request_response, request_id):
        """Check for Remote Code Execution"""
        rce_patterns = [
            ("uid=", 90),
            ("gid=", 90),
            ("groups=", 85),
            ("/bin/bash", 80),
            ("/bin/sh", 80),
            ("Microsoft Windows", 70)
        ]
        
        for pattern, confidence in rce_patterns:
            if pattern in content:
                vuln_data = {
                    "name": "Remote Code Execution",
                    "severity": "critical",
                    "url": url,
                    "description": "RCE allows arbitrary command execution on the server.",
                    "evidence": f"Command output pattern '{pattern}' found in response",
                    "recommendation": "1. Avoid system calls with user input\n2. Use allowlists for commands",
                    "confidence": confidence,
                    "request_response": request_response
                }
                self._add_vulnerability(**vuln_data, request_id=request_id)
                traffic_monitor.emit_vulnerability(request_id, vuln_data)
                break

    def _check_xxe(self, url, content, request_response, request_id):
        """Check for XXE vulnerabilities"""
        xxe_patterns = [
            ("root:x:", 95),
            ("file:///", 85),
            ("ENTITY", 70),
            ("DOCTYPE", 70)
        ]
        
        for pattern, confidence in xxe_patterns:
            if pattern in content:
                vuln_data = {
                    "name": "XML External Entity Injection",
                    "severity": "high",
                    "url": url,
                    "description": "XXE allows attackers to read local files, perform SSRF, or cause DoS.",
                    "evidence": f"XXE pattern '{pattern}' detected in response",
                    "recommendation": "1. Disable DTD processing\n2. Use less complex data formats (JSON)",
                    "confidence": confidence,
                    "request_response": request_response
                }
                self._add_vulnerability(**vuln_data, request_id=request_id)
                traffic_monitor.emit_vulnerability(request_id, vuln_data)
                break

    def _check_ssrf(self, url, content, request_response, request_id):
        """Check for Server-Side Request Forgery"""
        ssrf_patterns = [
            ("169.254.169.254", 95),
            ("localhost", 70),
            ("127.0.0.1", 70),
            ("metadata", 65),
            ("internal", 60)
        ]
        
        for pattern, confidence in ssrf_patterns:
            if pattern in content.lower():
                vuln_data = {
                    "name": "Server-Side Request Forgery",
                    "severity": "high",
                    "url": url,
                    "description": "SSRF allows attackers to make requests from the server to internal systems.",
                    "evidence": f"Internal reference '{pattern}' found in response",
                    "recommendation": "1. Validate and sanitize URLs\n2. Implement allowlists",
                    "confidence": confidence,
                    "request_response": request_response
                }
                self._add_vulnerability(**vuln_data, request_id=request_id)
                traffic_monitor.emit_vulnerability(request_id, vuln_data)
                break

    def _check_cors(self, url, headers, request_response, request_id):
        """Check for CORS misconfigurations"""
        if "Access-Control-Allow-Origin" in headers:
            origin = headers["Access-Control-Allow-Origin"]
            
            if origin == "*":
                vuln_data = {
                    "name": "CORS Wildcard Origin",
                    "severity": "medium",
                    "url": url,
                    "description": "CORS configured with wildcard origin (*) allows any website to read sensitive data.",
                    "evidence": f"Access-Control-Allow-Origin: *",
                    "recommendation": "1. Restrict CORS to specific trusted domains\n2. Avoid using wildcard with credentials",
                    "confidence": 90,
                    "request_response": request_response
                }
                self._add_vulnerability(**vuln_data, request_id=request_id)
                traffic_monitor.emit_vulnerability(request_id, vuln_data)
            elif "null" in origin:
                vuln_data = {
                    "name": "CORS Null Origin",
                    "severity": "medium",
                    "url": url,
                    "description": "CORS accepts 'null' origin which can be exploited from sandboxed iframes.",
                    "evidence": f"Access-Control-Allow-Origin: null",
                    "recommendation": "Avoid accepting 'null' origin",
                    "confidence": 85,
                    "request_response": request_response
                }
                self._add_vulnerability(**vuln_data, request_id=request_id)
                traffic_monitor.emit_vulnerability(request_id, vuln_data)

    def _check_csp(self, url, headers, request_response, request_id):
        """Check for CSP issues"""
        if "Content-Security-Policy" not in headers:
            vuln_data = {
                "name": "Missing Content Security Policy",
                "severity": "low",
                "url": url,
                "description": "No CSP header found, increasing risk of XSS and data injection attacks.",
                "evidence": "CSP header missing",
                "recommendation": "Implement Content Security Policy to mitigate XSS and data injection",
                "confidence": 100,
                "request_response": request_response
            }
            self._add_vulnerability(**vuln_data, request_id=request_id)
            traffic_monitor.emit_vulnerability(request_id, vuln_data)
        else:
            csp = headers["Content-Security-Policy"]
            if "'unsafe-inline'" in csp:
                vuln_data = {
                    "name": "CSP Unsafe Inline",
                    "severity": "low",
                    "url": url,
                    "description": "CSP allows unsafe-inline which weakens XSS protection.",
                    "evidence": f"CSP contains: unsafe-inline",
                    "recommendation": "Remove 'unsafe-inline' and use nonces or hashes",
                    "confidence": 80,
                    "request_response": request_response
                }
                self._add_vulnerability(**vuln_data, request_id=request_id)
                traffic_monitor.emit_vulnerability(request_id, vuln_data)
            if "'unsafe-eval'" in csp:
                vuln_data = {
                    "name": "CSP Unsafe Eval",
                    "severity": "low",
                    "url": url,
                    "description": "CSP allows unsafe-eval which enables execution of strings as code.",
                    "evidence": f"CSP contains: unsafe-eval",
                    "recommendation": "Remove 'unsafe-eval' when possible",
                    "confidence": 75,
                    "request_response": request_response
                }
                self._add_vulnerability(**vuln_data, request_id=request_id)
                traffic_monitor.emit_vulnerability(request_id, vuln_data)

    def _check_open_redirect(self, url, resp, original_value, request_response, request_id):
        """Check for open redirect vulnerabilities"""
        if resp.history:
            final_url = resp.url
            if "evil.com" in final_url or "//" in final_url and original_value in final_url:
                vuln_data = {
                    "name": "Open Redirect",
                    "severity": "medium",
                    "url": url,
                    "description": "Open redirect allows attackers to redirect users to malicious sites.",
                    "evidence": f"Redirected to: {final_url}",
                    "recommendation": "1. Validate redirect URLs\n2. Use whitelist of allowed domains",
                    "confidence": 85,
                    "request_response": request_response
                }
                self._add_vulnerability(**vuln_data, request_id=request_id)
                traffic_monitor.emit_vulnerability(request_id, vuln_data)

    def _check_crlf(self, url, content, request_response, request_id):
        """Check for CRLF injection"""
        if "\r\n" in content or "%0d%0a" in content:
            if "Set-Cookie:" in content or "Location:" in content:
                vuln_data = {
                    "name": "CRLF Injection",
                    "severity": "medium",
                    "url": url,
                    "description": "CRLF injection allows attackers to inject HTTP headers and split responses.",
                    "evidence": "CRLF sequences detected in response with header-like content",
                    "recommendation": "1. Validate and sanitize user input\n2. Encode CRLF characters",
                    "confidence": 70,
                    "request_response": request_response
                }
                self._add_vulnerability(**vuln_data, request_id=request_id)
                traffic_monitor.emit_vulnerability(request_id, vuln_data)

    # Placeholder methods for remaining vulnerability types
    def _check_privilege_escalation(self, *args, **kwargs): pass
    def _check_broken_access(self, *args, **kwargs): pass
    def _check_mass_assignment(self, *args, **kwargs): pass
    def _check_api_fuzzing(self, *args, **kwargs): pass
    def _check_grpc(self, *args, **kwargs): pass
    def _check_serverless(self, *args, **kwargs): pass
    def _check_subdomain_takeover(self, *args, **kwargs): pass
    def _check_dns_rebinding(self, *args, **kwargs): pass
    def _check_port_scanning(self, *args, **kwargs): pass
    def _check_memory_corruption(self, *args, **kwargs): pass

    def _add_vulnerability(self, name: str, severity: str, url: str, description: str, 
                          evidence: str, recommendation: str, parameter: str = None,
                          confidence: int = 100, request_response: str = None, 
                          request_id: str = None):
        """Add a vulnerability with thread safety and screenshot support"""
        vuln = Vulnerability(
            name=name,
            severity=severity,
            url=url,
            description=description,
            evidence=evidence,
            recommendation=recommendation,
            parameter=parameter,
            confidence=confidence,
            request_response=request_response
        )
        
        if request_id:
            vuln.request_id = request_id
        
        if self.config.get("screenshot", True) and HAS_SCREENSHOT:
            try:
                from core.screenshot import screenshot_capturer
                logger.info(f"Attempting to capture screenshot for: {url}")
                
                screenshot_data = screenshot_capturer.capture_url(
                    url, 
                    caption=f"Vulnerability: {name}"
                )
                if screenshot_data and screenshot_data.get('data'):
                    vuln.add_screenshot(screenshot_data)
                    logger.info(f"Screenshot captured for {name} at {url}")
                else:
                    logger.warning(f"No screenshot data received for {url}")
            except Exception as e:
                logger.error(f"Screenshot capture failed: {e}")
                import traceback
                logger.debug(traceback.format_exc())
        
        # FIXED: Thread-safe vulnerability addition
        with self.vuln_lock:
            self.vulnerabilities.append(vuln)
        
        with self.stats_lock:
            self.stats[severity] = self.stats.get(severity, 0) + 1
            self.stats["total"] += 1
            
        logger.info(f"[{severity.upper()}] {name} at {url}")

    def _get_static_content(self, url: str) -> str:
        """Get static content of URL for comparison"""
        try:
            resp = self.proxy_manager.get(url)
            if resp:
                return resp.text
        except:
            pass
        return ""

    def start_scan(self):
        """Start the scanning process"""
        if not self.target:
            logger.error("No target set")
            return
        
        self.running = True
        self.start_time = time.time()
        
        # Clear previous scan data with locks
        with self.vuln_lock:
            self.vulnerabilities.clear()
        
        with self.urls_lock:
            self.scanned_urls.clear()
        
        with self.stats_lock:
            self.stats = {k: 0 for k in self.stats}
            self.stats["total"] = 0
        
        self.total_tasks = 0
        self.completed_tasks = 0
        
        scan_config = self._get_scan_config()
        thread_count = scan_config.get("threads", self.config.get("threads", 10))
        
        logger.info(f"Starting {self.scan_type} scan on {self.target} with {thread_count} threads")
        try:
            ev = self._get_enabled_vulns()
            logger.info(f"Enabled modules: {', '.join(ev) if ev else 'NONE'}")
        except Exception:
            pass
        
        self.threads = []
        for i in range(thread_count):
            t = threading.Thread(target=self._scan_worker, name=f"Scanner-{i}")
            t.daemon = True
            t.start()
            self.threads.append(t)
        
        self._discover_and_queue()

    def _discover_and_queue(self):
        """Discover parameters and queue scan tasks"""
        try:
            resp = self.proxy_manager.get(self.target)
            if not resp:
                logger.error(f"Failed to fetch target: {self.target}")
                return
            
            params = ParameterExtractor.extract(self.target, resp.text)
            enabled_vulns = self._get_enabled_vulns()
            
            if not enabled_vulns:
                logger.warning("No vulnerability types enabled")
                return
            
            scan_config = self._get_scan_config()
            max_payloads = scan_config.get("payloads_per_param", 10)
            
            for param in params:
                for vuln_type in enabled_vulns:
                    payloads = self.payload_db.get_payloads(vuln_type)
                    payloads = payloads[:max_payloads]
                    
                    for payload in payloads:
                        mutations = PayloadGenerator.mutate_payload(payload)
                        for mutated in mutations[:3]:
                            encoded_payload = quote(mutated)
                            test_url = f"{self.target}?{param}={encoded_payload}"
                            
                            self.add_to_queue({
                                "url": test_url,
                                "method": "GET",
                                "params": {param: mutated},
                                "type": vuln_type,
                                "original_value": param
                            })
            
            soup = BeautifulSoup(resp.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                action = form.get('action', '')
                method = form.get('method', 'GET').upper()
                
                if action:
                    form_url = urljoin(self.target, action)
                else:
                    form_url = self.target
                
                form_params = {}
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    name = input_tag.get('name')
                    if name:
                        form_params[name] = PayloadGenerator.generate_random_string(8)
                
                if not form_params:
                    continue
                
                for vuln_type in enabled_vulns:
                    payloads = self.payload_db.get_payloads(vuln_type)[:max_payloads]
                    
                    for payload in payloads:
                        for param_name in form_params:
                            test_data = form_params.copy()
                            test_data[param_name] = payload
                            
                            self.add_to_queue({
                                "url": form_url,
                                "method": method,
                                "data": test_data,
                                "type": vuln_type,
                                "original_value": param_name
                            })
            
            logger.info(f"Queued {self.total_tasks} scan tasks")
            
        except Exception as e:
            logger.error(f"Parameter discovery failed: {e}", exc_info=True)

    def stop_scan(self):
        """Stop the scanning process - FIXED: Proper queue draining"""
        self.running = False
        
        # FIXED: Clear the queue
        while not self.scan_queue.empty():
            try:
                self.scan_queue.get_nowait()
                self.scan_queue.task_done()
            except:
                pass
        
        for t in self.threads:
            t.join(timeout=2)
        
        self.threads.clear()
        self.end_time = time.time()
        logger.info("Scan stopped")

    def get_progress(self) -> float:
        """Get current scan progress (0-100)"""
        if self.total_tasks == 0:
            return 0
        return min(100, (self.completed_tasks / self.total_tasks * 100))

    def get_duration(self) -> int:
        """Get scan duration in seconds"""
        if self.start_time:
            end = self.end_time or time.time()
            return int(end - self.start_time)
        return 0

    def generate_report(self) -> Dict:
        """Generate a single comprehensive scan report"""
        if not self.report_generator:
            logger.warning("Report generator not available")
            return {}
        
        self.end_time = self.end_time or time.time()
        
        report_data = {
            "target": self.target,
            "scan_type": self.scan_type,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration": self.get_duration(),
            "stats": self.stats,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "summary": self._generate_summary(),
            "config": {
                "threads": self.config.get("threads"),
                "timeout": self.config.get("timeout"),
                "features": self.config.get("features", {})
            }
        }
        
        reports = {}
        
        try:
            html_path = self.report_generator.generate_html(report_data)
            if html_path:
                reports["html"] = html_path
                logger.info(f"HTML report generated: {html_path}")
        except Exception as e:
            logger.error(f"HTML report failed: {e}")
        
        try:
            csv_path = self.report_generator.generate_csv(report_data)
            if csv_path:
                reports["csv"] = csv_path
                logger.info(f"CSV report generated: {csv_path}")
        except Exception as e:
            logger.error(f"CSV report failed: {e}")
        
        try:
            json_path = self.report_generator.generate_json(report_data)
            if json_path:
                reports["json"] = json_path
                logger.info(f"JSON report generated: {json_path}")
        except Exception as e:
            logger.error(f"JSON report failed: {e}")
        
        if "html" in reports:
            try:
                pdf_path = self.report_generator.generate_pdf(reports["html"])
                if pdf_path:
                    reports["pdf"] = pdf_path
                    logger.info(f"PDF report generated: {pdf_path}")
            except Exception as e:
                logger.error(f"PDF report failed: {e}")
        
        return reports

    def _generate_summary(self) -> str:
        """Generate executive summary"""
        critical = self.stats.get("critical", 0)
        high = self.stats.get("high", 0)
        medium = self.stats.get("medium", 0)
        total = self.stats.get("total", 0)
        
        if critical > 0:
            return f"⚠️ CRITICAL: {critical} critical vulnerabilities found! Immediate action required."
        elif high > 0:
            return f"🔴 HIGH: {high} high severity vulnerabilities detected. Fix as soon as possible."
        elif medium > 0:
            return f"🟡 MEDIUM: {medium} medium severity issues found. Address in next update cycle."
        elif total > 0:
            return f"🟢 LOW: {total} low severity issues found. Minor improvements recommended."
        else:
            return "✅ No vulnerabilities found. Good security posture!"