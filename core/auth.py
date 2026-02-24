#!/usr/bin/env python3
"""
CHOMBEZA - Authentication Manager
FIXED: Better login detection, session persistence
Created by: archnexus707 (Dickson Massawe)
"""

import re
import time
import logging
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple, Any, List
from urllib.parse import urljoin, urlparse
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger("CHOMBEZA.Auth")


@dataclass
class AuthConfig:
    enabled: bool = False

    # Static auth
    cookie: str = ""              # "a=b; c=d"
    bearer_token: str = ""        # raw token, without "Bearer "
    headers: Dict[str, str] = field(default_factory=dict)

    # Login workflow
    login_url: str = ""
    username: str = ""
    password: str = ""
    username_field: str = ""
    password_field: str = ""
    extra_fields: Dict[str, str] = field(default_factory=dict)

    # Behavior
    success_statuses: Tuple[int, ...] = (200, 204, 302, 303)
    timeout: int = 15
    max_redirects: int = 5
    verify_ssl: bool = False
    retries: int = 3


class SimpleHTMLFormParser:
    """
    FIXED: Better form parsing with CSRF token detection
    """
    
    # Compiled regex patterns
    FORM_RE = re.compile(r"<form\b[^>]*>", re.I)
    FORM_END_RE = re.compile(r"</form\s*>", re.I)
    ACTION_RE = re.compile(r'action\s*=\s*["\']([^"\']+)["\']', re.I)
    METHOD_RE = re.compile(r'method\s*=\s*["\']([^"\']+)["\']', re.I)
    INPUT_RE = re.compile(r"<input\b[^>]*>", re.I)
    ATTR_RE = re.compile(r'(\w+)\s*=\s*["\']([^"\']*)["\']')

    # CSRF token patterns
    CSRF_PATTERNS = [
        'csrf', 'token', '_token', 'authenticity_token',
        'csrf_token', 'csrfmiddlewaretoken', '__csrf'
    ]

    def parse(self, html_text: str) -> Optional[Dict[str, Any]]:
        """Parse HTML form with better error handling"""
        if not html_text:
            return None

        m = self.FORM_RE.search(html_text)
        if not m:
            return None

        form_start = m.start()
        m_end = self.FORM_END_RE.search(html_text, m.end())
        form_block = html_text[m.end(): m_end.start()] if m_end else html_text[m.end():]

        form_tag = html_text[m.start(): m.end()]
        action = self._get_attr(self.ACTION_RE, form_tag) or ""
        method = (self._get_attr(self.METHOD_RE, form_tag) or "POST").upper()

        inputs = []
        csrf_tokens = []
        
        for inp in self.INPUT_RE.finditer(form_block):
            attrs = dict((k.lower(), v) for k, v in self.ATTR_RE.findall(inp.group(0)))
            name = attrs.get("name", "")
            if not name:
                continue
                
            input_type = (attrs.get("type", "text") or "text").lower()
            value = attrs.get("value", "")
            
            input_data = {
                "name": name,
                "value": value,
                "type": input_type
            }
            inputs.append(input_data)
            
            # Check if this might be a CSRF token
            if any(pattern in name.lower() for pattern in self.CSRF_PATTERNS):
                csrf_tokens.append({
                    "name": name,
                    "value": value
                })

        return {
            "action": action,
            "method": method,
            "inputs": inputs,
            "csrf_tokens": csrf_tokens
        }

    @staticmethod
    def _get_attr(rx: re.Pattern, tag: str) -> str:
        m = rx.search(tag)
        return m.group(1).strip() if m else ""


class AuthManager:
    """
    FIXED: Handles authentication with better login detection
    """
    
    def __init__(self, config: Dict[str, Any], proxy: str = "", verify_ssl: bool = False, user_agent: str = ""):
        auth_cfg = (config or {}).get("auth", {}) if isinstance(config, dict) else {}
        
        self.cfg = AuthConfig(
            enabled=bool(auth_cfg.get("enabled", False)),
            cookie=auth_cfg.get("cookie", "") or "",
            bearer_token=auth_cfg.get("bearer_token", "") or "",
            headers=dict(auth_cfg.get("headers", {}) or {}),
            login_url=auth_cfg.get("login_url", "") or "",
            username=auth_cfg.get("username", "") or "",
            password=auth_cfg.get("password", "") or "",
            username_field=auth_cfg.get("username_field", "") or "",
            password_field=auth_cfg.get("password_field", "") or "",
            extra_fields=dict(auth_cfg.get("extra_fields", {}) or {}),
            timeout=int(auth_cfg.get("timeout", 15) or 15),
            max_redirects=int(auth_cfg.get("max_redirects", 5) or 5),
            verify_ssl=bool(auth_cfg.get("verify_ssl", False)),
            retries=int(auth_cfg.get("retries", 3) or 3)
        )

        self.proxy = proxy
        self.verify_ssl = verify_ssl
        self.user_agent = user_agent

        # Captured state after bootstrap/login
        self._bootstrapped = False
        self._cookie_jar = requests.cookies.RequestsCookieJar()
        self._extra_headers: Dict[str, str] = {}
        self._session = self._create_session()
        self._login_successful = False
        self._auth_type = None  # 'cookie', 'bearer', 'form', or None

    def _create_session(self) -> requests.Session:
        """Create a configured session with retries"""
        session = requests.Session()
        
        # Configure retries
        retry_strategy = Retry(
            total=self.cfg.retries,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Proxy configuration
        if self.proxy:
            session.proxies = {"http": self.proxy, "https": self.proxy}
        
        # SSL verification
        session.verify = self.verify_ssl or self.cfg.verify_ssl
        
        # User-Agent
        if self.user_agent:
            session.headers.update({"User-Agent": self.user_agent})
        
        # Timeout settings
        session.timeout = self.cfg.timeout
        session.max_redirects = self.cfg.max_redirects
        
        return session

    def is_enabled(self) -> bool:
        """Check if authentication is enabled and configured"""
        return self.cfg.enabled and (
            self.cfg.cookie or 
            self.cfg.bearer_token or 
            (self.cfg.login_url and self.cfg.username and self.cfg.password)
        )

    def bootstrap(self) -> bool:
        """
        FIXED: Perform login and build reusable auth state
        Returns True if authentication successful
        """
        if not self.is_enabled():
            self._bootstrapped = True
            return False

        if self._bootstrapped:
            return self._login_successful

        logger.info("Bootstrapping authentication...")

        # Base headers
        if self.user_agent:
            self._extra_headers["User-Agent"] = self.user_agent

        # Static token/header auth
        if self.cfg.bearer_token:
            self._extra_headers["Authorization"] = f"Bearer {self.cfg.bearer_token.strip()}"
            self._auth_type = 'bearer'
            logger.info("Using Bearer token authentication")

        if self.cfg.headers:
            self._extra_headers.update(self.cfg.headers)

        # Cookie string auth
        if self.cfg.cookie:
            self._apply_cookie_string(self._cookie_jar, self.cfg.cookie)
            self._auth_type = 'cookie'
            logger.info("Using Cookie authentication")
            self._login_successful = True

        # Auto-login (form-based)
        if self.cfg.login_url and self.cfg.username and self.cfg.password:
            try:
                self._login_successful = self._auto_login()
                if self._login_successful:
                    self._auth_type = 'form'
                    logger.info("Form-based login successful")
                else:
                    logger.warning("Form-based login failed")
            except Exception as e:
                logger.error(f"Auto-login failed: {e}")
                self._login_successful = False

        self._bootstrapped = True
        return self._login_successful

    def prepare_session(self, session: requests.Session) -> None:
        """
        Apply auth headers/cookies to a new session
        Call bootstrap() once before creating workers, then this per worker session
        """
        if not self._bootstrapped:
            self.bootstrap()

        # Apply proxies if not already set
        if self.proxy and not session.proxies:
            session.proxies = {"http": self.proxy, "https": self.proxy}

        session.verify = self.verify_ssl or self.cfg.verify_ssl

        # Apply headers
        if self._extra_headers:
            session.headers.update(self._extra_headers)

        # Apply cookies
        if self._cookie_jar:
            session.cookies.update(self._cookie_jar)

    def get_auth_info(self) -> Dict[str, Any]:
        """Get information about current authentication state"""
        return {
            "enabled": self.cfg.enabled,
            "authenticated": self._login_successful,
            "auth_type": self._auth_type,
            "has_cookies": len(self._cookie_jar) > 0,
            "has_headers": len(self._extra_headers) > 0
        }

    def refresh(self) -> bool:
        """Force refresh of authentication"""
        self._bootstrapped = False
        self._login_successful = False
        return self.bootstrap()

    # -------------------- internals --------------------

    @staticmethod
    def _apply_cookie_string(jar: requests.cookies.RequestsCookieJar, cookie_string: str) -> None:
        """Parse and apply cookie string"""
        for part in cookie_string.split(";"):
            part = part.strip()
            if not part or "=" not in part:
                continue
            k, v = part.split("=", 1)
            jar.set(k.strip(), v.strip())

    def _auto_login(self) -> bool:
        """FIXED: Perform form-based login with better detection"""
        session = self._create_session()
        
        # Apply any existing cookies/headers
        if self._extra_headers:
            session.headers.update(self._extra_headers)
        if self._cookie_jar:
            session.cookies.update(self._cookie_jar)

        logger.info(f"Attempting login to {self.cfg.login_url}")

        # 1) GET login page
        try:
            r = session.get(
                self.cfg.login_url,
                timeout=self.cfg.timeout,
                allow_redirects=True
            )
            r.raise_for_status()
            html_text = r.text or ""
        except Exception as e:
            logger.error(f"Failed to fetch login page: {e}")
            return False

        # 2) Parse form
        parser = SimpleHTMLFormParser()
        form = parser.parse(html_text)
        
        if not form:
            logger.warning("No login form found, attempting direct POST")
            payload = self._build_login_payload(inputs=[])
            login_action = self.cfg.login_url
        else:
            action = form.get("action") or self.cfg.login_url
            login_action = urljoin(self.cfg.login_url, action)
            inputs = form.get("inputs", []) or []
            payload = self._build_login_payload(inputs=inputs, csrf_tokens=form.get("csrf_tokens", []))
            logger.debug(f"Found form with action: {login_action}")

        # 3) Submit login
        method = (form.get("method") if form else "POST").upper()
        
        try:
            start_time = time.time()
            
            if method == "GET":
                resp = session.get(
                    login_action,
                    params=payload,
                    timeout=self.cfg.timeout,
                    allow_redirects=True
                )
            else:
                resp = session.post(
                    login_action,
                    data=payload,
                    timeout=self.cfg.timeout,
                    allow_redirects=True
                )
            
            response_time = time.time() - start_time
            logger.debug(f"Login response time: {response_time:.2f}s")
            
        except Exception as e:
            logger.error(f"Login request failed: {e}")
            return False

        # 4) FIXED: Better login success detection
        return self._finalize_login(session, resp)

    def _build_login_payload(self, inputs: List[Dict], csrf_tokens: List[Dict] = None) -> Dict[str, str]:
        """Build login payload with CSRF tokens and form fields"""
        payload: Dict[str, str] = {}

        # Add CSRF tokens first (important for many frameworks)
        if csrf_tokens:
            for token in csrf_tokens:
                payload[token["name"]] = token.get("value", "")
                logger.debug(f"Added CSRF token: {token['name']}")

        # Add hidden inputs
        for inp in inputs:
            if inp.get("type") == "hidden":
                if inp["name"] not in payload:  # Don't override CSRF tokens
                    payload[inp["name"]] = inp.get("value", "")

        # Add extra fields
        payload.update(self.cfg.extra_fields or {})

        # Determine username/password field names
        user_field = self.cfg.username_field or self._guess_user_field(inputs)
        pass_field = self.cfg.password_field or self._guess_pass_field(inputs)

        if user_field:
            payload[user_field] = self.cfg.username
            logger.debug(f"Using username field: {user_field}")
        if pass_field:
            payload[pass_field] = self.cfg.password
            logger.debug(f"Using password field: {pass_field}")

        # Common fallbacks
        if not user_field:
            for field in ['username', 'email', 'login', 'user', 'log']:
                if field not in payload:
                    payload[field] = self.cfg.username
                    logger.debug(f"Using fallback username field: {field}")
                    break

        if not pass_field:
            for field in ['password', 'pass', 'pwd']:
                if field not in payload:
                    payload[field] = self.cfg.password
                    logger.debug(f"Using fallback password field: {field}")
                    break

        return payload

    @staticmethod
    def _guess_user_field(inputs: List[Dict]) -> str:
        """Guess username field name"""
        candidates = []
        for inp in inputs:
            n = (inp.get("name") or "").lower()
            t = (inp.get("type") or "").lower()
            if t in ("text", "email") and any(k in n for k in ("user", "email", "login", "log")):
                candidates.append(inp["name"])
        return candidates[0] if candidates else ""

    @staticmethod
    def _guess_pass_field(inputs: List[Dict]) -> str:
        """Guess password field name"""
        for inp in inputs:
            if (inp.get("type") or "").lower() == "password":
                return inp.get("name", "")
        for inp in inputs:
            n = (inp.get("name") or "").lower()
            if "pass" in n:
                return inp["name"]
        return ""

    def _finalize_login(self, session: requests.Session, resp: requests.Response) -> bool:
        """FIXED: Better login success detection"""
        
        # Check status code
        status_ok = resp.status_code in self.cfg.success_statuses
        
        # Check if we got new cookies
        has_new_cookies = len(session.cookies) > len(self._cookie_jar)
        
        # Update cookie jar
        self._cookie_jar.update(session.cookies)

        # FIXED: Better heuristics for login detection
        body = (resp.text or "").lower()
        
        # Indicators that login failed
        failure_indicators = [
            "invalid", "incorrect", "wrong", "failed", "error",
            "login again", "try again", "not found", "denied"
        ]
        
        # Indicators that login succeeded
        success_indicators = [
            "welcome", "dashboard", "profile", "logout", "sign out",
            "account", "settings", f"hello {self.cfg.username.lower()}"
        ]

        # Check for password field (still on page)
        has_password_field = any([
            'type="password"' in body,
            "name='password'" in body,
            'name="password"' in body
        ])

        # Check for failure indicators
        has_failure = any(ind in body for ind in failure_indicators)
        
        # Check for success indicators
        has_success = any(ind in body for ind in success_indicators)

        # Decision logic
        if status_ok and has_new_cookies and not has_password_field:
            logged_in = True
        elif status_ok and has_success and not has_failure:
            logged_in = True
        elif has_failure:
            logged_in = False
        elif has_password_field:
            logged_in = False
        else:
            # Conservative default
            logged_in = status_ok and has_new_cookies

        logger.info(
            f"Login result: status={resp.status_code}, "
            f"new_cookies={has_new_cookies}, "
            f"password_field={has_password_field}, "
            f"success={logged_in}"
        )
        
        return logged_in


# Singleton instance
_auth_manager = None

def get_auth_manager(config: Dict = None, proxy: str = "", verify_ssl: bool = False, user_agent: str = ""):
    """Get or create the default auth manager instance"""
    global _auth_manager
    if _auth_manager is None:
        _auth_manager = AuthManager(config or {}, proxy, verify_ssl, user_agent)
    return _auth_manager