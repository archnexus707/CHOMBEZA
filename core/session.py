import requests
import json
import os
from typing import Dict, Optional, List
from core.utils import ProxyManager

class SessionManager:
    def __init__(self, proxy: str = ""):
        self.sessions: Dict[str, requests.Session] = {}
        self.cookies: Dict[str, Dict] = {}
        self.proxy = proxy
        self.proxy_manager = ProxyManager(proxy)

    def create_session(self, name: str) -> requests.Session:
        session = requests.Session()
        if self.proxy:
            session.proxies = {"http": self.proxy, "https": self.proxy}
        self.sessions[name] = session
        return session

    def get_session(self, name: str) -> Optional[requests.Session]:
        return self.sessions.get(name)

    def save_cookies(self, name: str, cookies: Dict):
        self.cookies[name] = cookies

    def load_cookies(self, name: str) -> Optional[Dict]:
        return self.cookies.get(name)

    def save_to_file(self, filename: str = "sessions.json"):
        data = {
            "sessions": {name: session.cookies.get_dict() for name, session in self.sessions.items()},
            "cookies": self.cookies
        }
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)

    def load_from_file(self, filename: str = "sessions.json"):
        if not os.path.exists(filename):
            return
        with open(filename, 'r') as f:
            data = json.load(f)
        for name, cookies in data["sessions"].items():
            session = self.create_session(name)
            session.cookies.update(cookies)
        self.cookies = data.get("cookies", {})

    def clear(self):
        self.sessions.clear()
        self.cookies.clear()