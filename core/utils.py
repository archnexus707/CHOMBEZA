import requests
import socket
import json
import os
import time
import random
import string
import base64
import re
import threading
import logging
logger = logging.getLogger("CHOMBEZA.Utils")
import urllib.parse
from typing import Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse, urljoin, parse_qs, quote
from bs4 import BeautifulSoup

# Try to import optional dependencies
try:
    from PIL import ImageGrab
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

try:
    import pyautogui
    HAS_PYAUTOGUI = True
except Exception as e:
    # pyautogui can raise runtime errors on headless systems (no display)
    HAS_PYAUTOGUI = False
    logger.debug(f"PyAutoGUI not available: {e}")

try:
    import socks
    HAS_SOCKS = True
except ImportError:
    HAS_SOCKS = False

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.common.exceptions import WebDriverException
    HAS_SELENIUM = True
except ImportError:
    HAS_SELENIUM = False

logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(asctime)s - %(name)s: %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger("NeonReaper.Utils")

class ProxyManager:
    """Manages HTTP/HTTPS/SOCKS proxies for requests"""
    
    def __init__(self, proxy: str = ""):
        self.proxy = proxy
        self.session = requests.Session()
        self._configure_session()
        
    def _configure_session(self):
        """Configure session with proxy settings"""
        if self.proxy:
            # Handle SOCKS proxies
            if self.proxy.startswith("socks"):
                if HAS_SOCKS:
                    # Configure SOCKS for socket level
                    try:
                        proxy_parts = urllib.parse.urlparse(self.proxy)
                        proxy_type = socks.SOCKS5 if "5" in proxy_parts.scheme else socks.SOCKS4
                        proxy_host = proxy_parts.hostname
                        proxy_port = proxy_parts.port or 1080
                        
                        socks.set_default_proxy(proxy_type, proxy_host, proxy_port)
                        socket.socket = socks.socksocket
                        logger.info(f"SOCKS proxy configured: {self.proxy}")
                    except Exception as e:
                        logger.error(f"Failed to configure SOCKS proxy: {e}")
                else:
                    logger.warning("SOCKS support not installed. Install PySocks: pip install PySocks")
            
            # Configure HTTP/HTTPS proxies
            self.session.proxies = {
                "http": self.proxy,
                "https": self.proxy
            }
    
    def set_proxy(self, proxy: str):
        """Change proxy configuration"""
        self.proxy = proxy
        self._configure_session()
    
    def get(self, url: str, headers: Dict = None, timeout: int = 10, 
            allow_redirects: bool = True, verify: bool = False) -> Optional[requests.Response]:
        """Perform GET request with error handling"""
        try:
            response = self.session.get(
                url,
                headers=headers or {},
                timeout=timeout,
                allow_redirects=allow_redirects,
                verify=verify
            )
            return response
        except requests.exceptions.Timeout:
            logger.debug(f"GET timeout: {url}")
        except requests.exceptions.ConnectionError:
            logger.debug(f"GET connection error: {url}")
        except requests.exceptions.RequestException as e:
            logger.debug(f"GET failed: {url} - {e}")
        except Exception as e:
            logger.error(f"Unexpected GET error: {e}")
        return None
    
    def post(self, url: str, data: Dict = None, json_data: Dict = None, 
             headers: Dict = None, timeout: int = 10, allow_redirects: bool = True,
             verify: bool = False) -> Optional[requests.Response]:
        """Perform POST request with error handling"""
        try:
            response = self.session.post(
                url,
                data=data,
                json=json_data,
                headers=headers or {},
                timeout=timeout,
                allow_redirects=allow_redirects,
                verify=verify
            )
            return response
        except requests.exceptions.Timeout:
            logger.debug(f"POST timeout: {url}")
        except requests.exceptions.ConnectionError:
            logger.debug(f"POST connection error: {url}")
        except requests.exceptions.RequestException as e:
            logger.debug(f"POST failed: {url} - {e}")
        except Exception as e:
            logger.error(f"Unexpected POST error: {e}")
        return None
    
    def request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """Generic request method"""
        try:
            response = self.session.request(method, url, **kwargs)
            return response
        except Exception as e:
            logger.debug(f"Request failed: {method} {url} - {e}")
        return None

class HeaderAnalyzer:
    """Analyzes HTTP headers for security issues"""
    
    SECURITY_HEADERS = {
        "Content-Security-Policy": "Mitigates XSS and data injection attacks",
        "X-Content-Type-Options": "Prevents MIME type sniffing",
        "X-Frame-Options": "Prevents clickjacking attacks",
        "X-XSS-Protection": "Enables browser XSS filter",
        "Strict-Transport-Security": "Enforces HTTPS connections",
        "Referrer-Policy": "Controls referrer information leakage",
        "Permissions-Policy": "Controls browser features access",
        "Feature-Policy": "Legacy permissions policy",
        "Cache-Control": "Prevents caching of sensitive data",
        "Pragma": "Legacy cache control"
    }
    
    @staticmethod
    def analyze(headers: Dict) -> Dict:
        """Analyze headers for security best practices"""
        results = {
            "security_headers": {},
            "missing_headers": [],
            "present_headers": [],
            "recommendations": [],
            "score": 0
        }
        
        total_headers = len(HeaderAnalyzer.SECURITY_HEADERS)
        present_count = 0
        
        for header, description in HeaderAnalyzer.SECURITY_HEADERS.items():
            if header in headers:
                results["security_headers"][header] = headers[header]
                results["present_headers"].append(header)
                present_count += 1
                
                # Check for common misconfigurations
                if header == "X-Frame-Options" and headers[header] not in ["DENY", "SAMEORIGIN"]:
                    results["recommendations"].append(f"X-Frame-Options should be DENY or SAMEORIGIN, got: {headers[header]}")
                
                if header == "X-Content-Type-Options" and headers[header].upper() != "NOSNIFF":
                    results["recommendations"].append(f"X-Content-Type-Options should be 'nosniff', got: {headers[header]}")
                
                if header == "Strict-Transport-Security" and "max-age=" not in headers[header]:
                    results["recommendations"].append("HSTS should include max-age directive")
            else:
                results["missing_headers"].append(header)
                results["recommendations"].append(f"Add {header} header: {description}")
        
        # Calculate security score (0-100)
        if total_headers > 0:
            results["score"] = int((present_count / total_headers) * 100)
        
        return results

class SSLChecker:
    """Checks SSL/TLS configuration"""
    
    @staticmethod
    def check(host: str, port: int = 443) -> Dict:
        """Check SSL certificate and configuration"""
        result = {
            "valid": False,
            "issuer": "Unknown",
            "subject": "Unknown",
            "expires": None,
            "protocol": None,
            "cipher": None,
            "error": None
        }
        
        try:
            import ssl
            import socket
            from datetime import datetime
            
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    # Get certificate
                    cert = ssock.getpeercert()
                    
                    if cert:
                        # Extract issuer
                        issuer = dict(x[0] for x in cert['issuer'])
                        result["issuer"] = issuer.get('organizationName', 'Unknown')
                        
                        # Extract subject
                        subject = dict(x[0] for x in cert['subject'])
                        result["subject"] = subject.get('commonName', 'Unknown')
                        
                        # Extract expiration
                        if 'notAfter' in cert:
                            expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                            result["expires"] = expiry_date.isoformat()
                            result["valid"] = expiry_date > datetime.now()
                        
                        # Get protocol and cipher
                        result["protocol"] = ssock.version()
                        result["cipher"] = ssock.cipher()[0] if ssock.cipher() else None
                        
        except socket.timeout:
            result["error"] = "Connection timeout"
        except socket.error as e:
            result["error"] = f"Socket error: {e}"
        except ssl.SSLError as e:
            result["error"] = f"SSL error: {e}"
        except Exception as e:
            result["error"] = str(e)
        
        return result

class ScreenshotTaker:
    """Takes screenshots of web pages"""
    
    @staticmethod
    def capture(url: str, output: str, timeout: int = 10) -> bool:
        """Capture screenshot of URL using available method"""
        
        # Try Selenium first (best results)
        if HAS_SELENIUM:
            try:
                options = Options()
                options.add_argument("--headless")
                options.add_argument("--disable-gpu")
                options.add_argument("--no-sandbox")
                options.add_argument("--disable-dev-shm-usage")
                options.add_argument("--window-size=1280,720")
                
                driver = webdriver.Chrome(options=options)
                driver.set_page_load_timeout(timeout)
                driver.get(url)
                time.sleep(2)  # Wait for page to render
                driver.save_screenshot(output)
                driver.quit()
                logger.debug(f"Screenshot saved: {output}")
                return True
                
            except WebDriverException as e:
                logger.debug(f"Selenium screenshot failed: {e}")
            except Exception as e:
                logger.debug(f"Screenshot error: {e}")
        
        # Try PIL/PyAutoGUI fallback (only works on local pages)
        if HAS_PIL and HAS_PYAUTOGUI:
            try:
                import pygetwindow as gw
                
                # Open browser (simplified - would need more robust implementation)
                import webbrowser
                webbrowser.open(url)
                time.sleep(3)
                
                # Take screenshot of active window
                screenshot = pyautogui.screenshot()
                screenshot.save(output)
                logger.debug(f"Fallback screenshot saved: {output}")
                return True
                
            except Exception as e:
                logger.debug(f"Fallback screenshot failed: {e}")
        
        return False

class ParameterExtractor:
    """Extracts parameters from URLs and HTML forms"""
    
    @staticmethod
    def extract(url: str, html: str) -> List[str]:
        """Extract all parameter names from URL and forms"""
        params = set()
        
        # Extract from URL query string
        try:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            for key in query_params:
                params.add(key)
        except Exception:
            pass
        
        # Extract from HTML forms
        if html:
            try:
                soup = BeautifulSoup(html, 'html.parser')
                
                # Form inputs
                for form in soup.find_all('form'):
                    for input_tag in form.find_all(['input', 'textarea', 'select']):
                        name = input_tag.get('name')
                        if name:
                            params.add(name)
                    
                    # Hidden inputs
                    for hidden in form.find_all('input', type='hidden'):
                        name = hidden.get('name')
                        if name:
                            params.add(name)
                
                # URL parameters in links
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    if '?' in href:
                        try:
                            link_parsed = urlparse(href)
                            link_params = parse_qs(link_parsed.query)
                            for key in link_params:
                                params.add(key)
                        except Exception:
                            pass
                            
            except Exception as e:
                logger.debug(f"HTML parsing error: {e}")
        
        return list(params)
    
    @staticmethod
    def extract_from_forms(html: str, base_url: str) -> List[Dict]:
        """Extract form details (action, method, fields)"""
        forms = []
        
        if not html:
            return forms
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            for form in soup.find_all('form'):
                form_data = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'GET').upper(),
                    'fields': [],
                    'enctype': form.get('enctype', 'application/x-www-form-urlencoded')
                }
                
                # Build full action URL
                if form_data['action']:
                    form_data['full_url'] = urljoin(base_url, form_data['action'])
                else:
                    form_data['full_url'] = base_url
                
                # Extract fields
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    field = {
                        'name': input_tag.get('name'),
                        'type': input_tag.get('type', 'text'),
                        'value': input_tag.get('value', '')
                    }
                    if field['name']:  # Only add named fields
                        form_data['fields'].append(field)
                
                if form_data['fields']:
                    forms.append(form_data)
                    
        except Exception as e:
            logger.debug(f"Form extraction error: {e}")
        
        return forms

class PayloadGenerator:
    """Generates and mutates payloads for testing"""
    
    COMMON_PAYLOADS = {
        "xss": [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "\"><script>alert(1)</script>",
            "'><script>alert(1)</script>"
        ],
        "sqli": [
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "1' ORDER BY 1--",
            "1' UNION SELECT 1,2,3--",
            "1' AND SLEEP(5)--"
        ],
        "ssti": [
            "{{7*7}}",
            "${7*7}",
            "#{7*7}",
            "<%= 7*7 %>"
        ],
        "lfi": [
            "../../../../etc/passwd",
            "....//....//etc/passwd",
            "%2e%2e%2fetc%2fpasswd"
        ],
        "rce": [
            ";id",
            "|id",
            "`id`",
            "$(id)",
            "&& id"
        ]
    }
    
    @staticmethod
    def generate_random_string(length: int = 8) -> str:
        """Generate random alphanumeric string"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    
    @staticmethod
    def generate_random_number(min_val: int = 1, max_val: int = 9999) -> int:
        """Generate random number"""
        return random.randint(min_val, max_val)
    
    @staticmethod
    def mutate_payload(payload: str) -> List[str]:
        """Generate common mutations of a payload"""
        mutations = set()  # Use set to avoid duplicates
        mutations.add(payload)
        
        # Add common suffixes/prefixes
        mutations.add(payload + "'")
        mutations.add(payload + "\"")
        mutations.add(payload + "`")
        mutations.add(payload + ")")
        mutations.add(payload + "(")
        mutations.add(payload + "}}")
        mutations.add(payload + "{{")
        
        # URL encode variants
        encoded = quote(payload)
        mutations.add(encoded)
        
        # Double URL encode
        double_encoded = quote(quote(payload))
        mutations.add(double_encoded)
        
        # Add whitespace variants
        mutations.add(" " + payload)
        mutations.add(payload + " ")
        mutations.add("\t" + payload)
        mutations.add(payload + "\t")
        
        # Case variations for alphanumeric
        if any(c.isalpha() for c in payload):
            mutations.add(payload.upper())
            mutations.add(payload.lower())
            mutations.add(''.join(c.upper() if i%2 else c.lower() for i, c in enumerate(payload)))
        
        # Limit to prevent explosion
        return list(mutations)[:20]
    
    @staticmethod
    def get_payloads_for_type(vuln_type: str) -> List[str]:
        """Get default payloads for vulnerability type"""
        return PayloadGenerator.COMMON_PAYLOADS.get(vuln_type, [])

class RateLimiter:
    """Token bucket rate limiter"""
    
    def __init__(self, rate: int):
        """
        Initialize rate limiter
        Args:
            rate: Maximum requests per second
        """
        self.rate = max(1, rate)  # Ensure at least 1 req/sec
        self.tokens = float(rate)
        self.last_update = time.time()
        self.lock = threading.Lock()
    
    def wait(self):
        """Wait if necessary to maintain rate limit"""
        with self.lock:
            now = time.time()
            elapsed = now - self.last_update
            
            # Add new tokens based on elapsed time
            self.tokens = min(self.rate, self.tokens + elapsed * self.rate)
            self.last_update = now
            
            if self.tokens < 1:
                # Need to wait for more tokens
                wait_time = (1 - self.tokens) / self.rate
                time.sleep(wait_time)
                self.tokens = 0
            else:
                # Consume one token
                self.tokens -= 1

class URLUtils:
    """URL manipulation utilities"""
    
    @staticmethod
    def normalize_url(url: str) -> str:
        """Normalize URL by adding scheme if missing"""
        if not url:
            return url
        
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        return url
    
    @staticmethod
    def is_valid_url(url: str) -> bool:
        """Check if URL is valid"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
    
    @staticmethod
    def extract_domain(url: str) -> str:
        """Extract domain from URL"""
        try:
            parsed = urlparse(url)
            return parsed.netloc
        except Exception:
            return url
    
    @staticmethod
    def build_url(base: str, path: str = "", params: Dict = None) -> str:
        """Build URL from components"""
        url = base.rstrip('/')
        if path:
            url += '/' + path.lstrip('/')
        
        if params:
            query = '&'.join([f"{k}={quote(str(v))}" for k, v in params.items()])
            url += '?' + query
        
        return url

class ColorFormatter(logging.Formatter):
    """Colored log formatter for console output"""
    
    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[35m',   # Magenta
        'RESET': '\033[0m'        # Reset
    }
    
    def format(self, record):
        levelname = record.levelname
        if levelname in self.COLORS:
            record.levelname = f"{self.COLORS[levelname]}{levelname}{self.COLORS['RESET']}"
        return super().format(record)