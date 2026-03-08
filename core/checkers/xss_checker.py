#!/usr/bin/env python3
"""
CHOMBEZA - XSS Vulnerability Checker Module
"""

import re
import logging
import urllib.parse
from typing import Dict, List, Optional, Any
from bs4 import BeautifulSoup

logger = logging.getLogger("CHOMBEZA.Checker.XSS")

class XSSChecker:
    """
    Comprehensive XSS vulnerability checker
    Detects reflected, stored, DOM-based, and blind XSS
    """
    
    # XSS detection patterns
    XSS_PATTERNS = [
        # Basic script tags
        (r'<script[^>]*>.*?</script>', 70),
        (r'<img[^>]*\s+onerror\s*=', 80),
        (r'<svg[^>]*\s+onload\s*=', 80),
        (r'<body[^>]*\s+onload\s*=', 80),
        (r'<iframe[^>]*\s+src\s*=', 75),
        (r'<link[^>]*\s+href\s*=', 60),
        (r'<object[^>]*\s+data\s*=', 60),
        (r'<embed[^>]*\s+src\s*=', 60),
        (r'<math[^>]*\s+href\s*=', 70),
        
        # JavaScript events
        (r'onerror\s*=', 70),
        (r'onload\s*=', 70),
        (r'onclick\s*=', 65),
        (r'onmouseover\s*=', 65),
        (r'onfocus\s*=', 65),
        (r'onblur\s*=', 65),
        (r'onchange\s*=', 65),
        (r'onsubmit\s*=', 65),
        (r'onreset\s*=', 65),
        (r'onselect\s*=', 65),
        (r'onabort\s*=', 65),
        
        # JavaScript URIs
        (r'javascript\s*:', 85),
        (r'vbscript\s*:', 80),
        (r'data\s*:', 60),
        
        # Encoded variants
        (r'\\x3cscript\\x3e', 90),
        (r'%3Cscript%3E', 85),
        (r'&lt;script&gt;', 75),
        
        # DOM XSS sources
        (r'document\.write\s*\(', 75),
        (r'eval\s*\(', 70),
        (r'setTimeout\s*\(', 65),
        (r'setInterval\s*\(', 65),
        (r'Function\s*\(', 65),
        (r'innerHTML\s*=', 70),
        (r'outerHTML\s*=', 70),
        (r'insertAdjacentHTML', 70),
        (r'location\s*=', 65),
        (r'location\.href', 65),
        (r'location\.replace', 65),
        (r'location\.assign', 65),
        
        # Blind XSS payloads
        (r'src=["\']?http://localhost:5000/xss', 95),
        (r'fetch\(["\']?http://localhost:5000/xss', 95),
        (r'new Image\(\)\.src=["\']?http://localhost:5000/xss', 95),
    ]
    
    # Context indicators
    CONTEXTS = {
        'html': ['<', '>', '&', '"', "'"],
        'attribute': ['"', "'", '=', '>'],
        'script': ['<', '>', '"', "'", '(', ')', '{', '}'],
        'style': ['<', '>', '"', "'", ':', ';'],
        'url': ['/', ':', '?', '&', '=', '#']
    }
    
    @classmethod
    def check(cls, response: Any, task: Dict) -> List[Dict]:
        """
        Main entry point for XSS checking
        Returns list of findings
        """
        findings = []
        
        # Skip if no response
        if not response or not hasattr(response, 'text'):
            return findings
        
        content = response.text
        url = task.get('url', '')
        param_name = task.get('param_name', '')
        payload = task.get('payload', '')
        
        # Check for payload reflection
        if not payload or payload not in content:
            return findings
        
        # Determine context where payload was reflected
        context = cls._determine_context(content, payload)
        
        # Check if payload is executable in this context
        if not cls._is_executable_in_context(payload, context):
            return findings
        
        # Check for XSS patterns
        severity, confidence = cls._analyze_xss_patterns(content, payload)
        
        if confidence >= 50:  # Only report if confidence is reasonable
            finding = cls._create_finding(
                url=url,
                param_name=param_name,
                payload=payload,
                context=context,
                severity=severity,
                confidence=confidence,
                response=response,
                task=task
            )
            findings.append(finding)
            
            # If high confidence, try to verify
            if confidence >= 80:
                verified = cls._verify_xss(response, task)
                if verified:
                    finding['confidence'] = min(100, confidence + 10)
                    finding['verified'] = True
        
        return findings
    
    @classmethod
    def _determine_context(cls, content: str, payload: str) -> str:
        """Determine the HTML context where payload is reflected"""
        # Find the position of payload
        pos = content.find(payload)
        if pos == -1:
            return 'unknown'
        
        # Look at surrounding characters
        start = max(0, pos - 50)
        end = min(len(content), pos + len(payload) + 50)
        context_snippet = content[start:end]
        
        # Check context types
        if cls._is_in_script_tag(context_snippet, payload):
            return 'script'
        elif cls._is_in_style_tag(context_snippet, payload):
            return 'style'
        elif cls._is_in_html_tag(context_snippet, payload):
            return 'attribute'
        elif cls._is_in_comment(context_snippet, payload):
            return 'comment'
        elif cls._is_in_url(context_snippet, payload):
            return 'url'
        else:
            return 'html'
    
    @classmethod
    def _is_in_script_tag(cls, snippet: str, payload: str) -> bool:
        """Check if payload is inside <script> tags"""
        script_pattern = r'<script[^>]*>.*?' + re.escape(payload) + r'.*?</script>'
        return bool(re.search(script_pattern, snippet, re.I | re.S))
    
    @classmethod
    def _is_in_style_tag(cls, snippet: str, payload: str) -> bool:
        """Check if payload is inside <style> tags"""
        style_pattern = r'<style[^>]*>.*?' + re.escape(payload) + r'.*?</style>'
        return bool(re.search(style_pattern, snippet, re.I | re.S))
    
    @classmethod
    def _is_in_html_tag(cls, snippet: str, payload: str) -> bool:
        """Check if payload is inside an HTML tag attribute"""
        # Look for pattern: <tag ... payload ... >
        tag_pattern = r'<[^>]*' + re.escape(payload) + r'[^>]*>'
        return bool(re.search(tag_pattern, snippet, re.I))
    
    @classmethod
    def _is_in_comment(cls, snippet: str, payload: str) -> bool:
        """Check if payload is inside HTML comment"""
        comment_pattern = r'<!--.*?' + re.escape(payload) + r'.*?-->'
        return bool(re.search(comment_pattern, snippet, re.S))
    
    @classmethod
    def _is_in_url(cls, snippet: str, payload: str) -> bool:
        """Check if payload is inside a URL"""
        url_patterns = [
            r'href=["\']?[^"\']*' + re.escape(payload),
            r'src=["\']?[^"\']*' + re.escape(payload),
            r'action=["\']?[^"\']*' + re.escape(payload),
            r'data=["\']?[^"\']*' + re.escape(payload)
        ]
        for pattern in url_patterns:
            if re.search(pattern, snippet, re.I):
                return True
        return False
    
    @classmethod
    def _is_executable_in_context(cls, payload: str, context: str) -> bool:
        """Determine if payload is executable in given context"""
        # If payload contains script tags, it's executable in HTML context
        if '<script' in payload.lower() and context in ['html', 'unknown']:
            return True
        
        # If payload contains event handlers, it's executable in attribute context
        if any(event in payload.lower() for event in ['onerror', 'onload', 'onclick']):
            if context in ['attribute', 'html', 'unknown']:
                return True
        
        # If payload contains javascript: URI, it's executable in URL context
        if 'javascript:' in payload.lower():
            if context in ['url', 'attribute', 'html', 'unknown']:
                return True
        
        # If payload contains JS code and is in script context
        if context == 'script':
            return True
        
        return False
    
    @classmethod
    def _analyze_xss_patterns(cls, content: str, payload: str) -> tuple:
        """Analyze content for XSS patterns and determine severity/confidence"""
        max_confidence = 0
        severity = 'low'
        
        for pattern, base_confidence in cls.XSS_PATTERNS:
            if re.search(pattern, content, re.I):
                confidence = base_confidence
                
                # Boost confidence if payload is directly reflected
                if payload in content:
                    confidence += 10
                
                # Check for dangerous contexts
                if 'script' in pattern.pattern.lower() or 'javascript' in pattern.pattern.lower():
                    severity = 'high'
                elif 'onerror' in pattern.pattern.lower() or 'onload' in pattern.pattern.lower():
                    severity = 'high'
                elif 'document.write' in pattern.pattern.lower() or 'eval' in pattern.pattern.lower():
                    severity = 'high'
                elif 'innerHTML' in pattern.pattern.lower():
                    severity = 'medium'
                else:
                    severity = 'medium' if confidence >= 70 else 'low'
                
                max_confidence = max(max_confidence, confidence)
        
        return severity, max_confidence
    
    @classmethod
    def _verify_xss(cls, response: Any, task: Dict) -> bool:
        """Verify XSS with a second request"""
        try:
            import requests
            
            url = task.get('url', '')
            payload = task.get('payload', '')
            param_name = task.get('param_name', '')
            
            # Make second request
            test_url = url.replace(f"{param_name}={payload}", f"{param_name}={payload}")
            resp = requests.get(test_url, timeout=5, verify=False)
            
            # Check if payload still reflected
            return resp and payload in resp.text
            
        except Exception:
            return False
    
    @classmethod
    def _create_finding(cls, url: str, param_name: str, payload: str, 
                        context: str, severity: str, confidence: int,
                        response: Any, task: Dict) -> Dict:
        """Create a structured finding"""
        
        # Build evidence string
        evidence = f"""
Parameter: {param_name}
Payload: {payload}
Context: {context}
Confidence: {confidence}%

Response Snippet:
{cls._get_response_snippet(response.text, payload)}
        """
        
        # Build recommendation based on context
        if context == 'html':
            recommendation = """
1. Apply HTML entity encoding to user input
2. Use Content Security Policy (CSP) with 'unsafe-inline' disabled
3. Implement context-aware output encoding
4. Validate input against allowlist of safe characters
            """
        elif context == 'attribute':
            recommendation = """
1. Encode attribute values properly (escape quotes)
2. Use JavaScript encoding for event handler attributes
3. Avoid using user input in event handlers when possible
4. Implement Content Security Policy
            """
        elif context == 'script':
            recommendation = """
1. Never insert user input directly into JavaScript code
2. Use JSON serialization and safe APIs like textContent
3. Implement strict CSP with 'unsafe-eval' disabled
4. Validate and sanitize all input
            """
        elif context == 'url':
            recommendation = """
1. Validate and sanitize URLs against allowlist
2. Use URL encoding for parameter values
3. Avoid javascript: URLs entirely
4. Implement Content Security Policy with strict directives
            """
        else:
            recommendation = """
1. Apply output encoding based on context
2. Use Content Security Policy (CSP)
3. Validate and sanitize all user input
4. Consider using a security framework with auto-escaping
            """
        
        # Capture request/response
        request_response = cls._capture_request_response(response, task)
        
        return {
            "name": "Cross-Site Scripting (XSS)",
            "severity": severity,
            "url": url,
            "description": f"Reflected XSS vulnerability detected in parameter '{param_name}'. The payload was reflected in {context} context.",
            "evidence": evidence.strip(),
            "recommendation": recommendation.strip(),
            "parameter": param_name,
            "confidence": confidence,
            "request_response": request_response,
            "cwe_id": "CWE-79",
            "category": "XSS",
            "context": context,
            "verified": False,
            "poc_steps": [
                f"1. Navigate to: {url}",
                f"2. Inject payload in parameter '{param_name}': {payload}",
                f"3. Observe that the payload is reflected and executed in the response",
                f"4. The payload was reflected in {context} context"
            ]
        }
    
    @classmethod
    def _get_response_snippet(cls, content: str, payload: str, context_chars: int = 100) -> str:
        """Get snippet of response around payload"""
        pos = content.find(payload)
        if pos == -1:
            return content[:500] + "..." if len(content) > 500 else content
        
        start = max(0, pos - context_chars)
        end = min(len(content), pos + len(payload) + context_chars)
        
        snippet = content[start:end]
        if start > 0:
            snippet = "..." + snippet
        if end < len(content):
            snippet = snippet + "..."
        
        return snippet
    
    @classmethod
    def _capture_request_response(cls, response: Any, task: Dict) -> str:
        """Capture request and response for evidence"""
        request_str = f"""
Request:
{task.get('method', 'GET')} {task.get('url', '')}
Parameters: {json.dumps(task.get('params', {}), indent=2)}
Data: {json.dumps(task.get('data', {}), indent=2)}
        """
        
        response_str = f"""
Response:
Status: {response.status_code if response else 'N/A'}
Headers: {json.dumps(dict(response.headers if response else {}), indent=2)}
Body Preview: {response.text[:1000] if response and response.text else 'N/A'}
        """
        
        return request_str + "\n" + response_str

# For JSON serialization
import json