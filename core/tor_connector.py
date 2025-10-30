import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import socket
import os
from typing import Optional, Dict, Any
import time

class TorConnector:
    """Handles Tor proxy connections and validation"""

    def __init__(self):
        self.proxy_host = os.getenv('TOR_PROXY_HOST', '127.0.0.1')
        self.timeout = int(os.getenv('TOR_TIMEOUT', '30'))
        self.control_port = int(os.getenv('TOR_CONTROL_PORT', '9051'))
        self.control_host = os.getenv('TOR_CONTROL_HOST', '127.0.0.1')
        self.verify_ssl = os.getenv('REQUESTS_VERIFY_SSL', 'false').lower() not in ['0', 'false', 'no']
        self._detect_ports = os.getenv('TOR_DETECT_PORTS', 'true').lower() not in ['0', 'false', 'no']
        explicit_proxy_port = os.getenv('TOR_PROXY_PORT')

        # Choose proxy port: explicit via env or auto-detect common ports
        if explicit_proxy_port:
            try:
                self.proxy_port = int(explicit_proxy_port)
            except ValueError:
                raise RuntimeError(f"Invalid TOR_PROXY_PORT: {explicit_proxy_port}")
        elif self._detect_ports:
            # Try both ports: Tor service (9050) and Tor Browser (9150)
            self.proxy_port = self._detect_port()
        else:
            # Default to 9050 if detection disabled and no explicit port provided
            self.proxy_port = 9050

        # Proxy configuration
        self.proxies = {
            'http': f'socks5h://{self.proxy_host}:{self.proxy_port}',
            'https': f'socks5h://{self.proxy_host}:{self.proxy_port}'
        }

    def _detect_port(self) -> int:
        """Detect which Tor port is open (9050 for service, 9150 for browser)"""
        for port in [9050, 9150]:
            if self._check_port_open(self.proxy_host, port):
                print(f"[+] Using Tor proxy at {self.proxy_host}:{port}")
                return port
        raise RuntimeError("No Tor proxy found (checked ports 9050 and 9150)")

    def _check_port_open(self, host: str, port: int) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def check_connection(self) -> bool:
        """Check if Tor proxy is working"""
        try:
            response = requests.get(
                'https://check.torproject.org/api/ip',
                proxies=self.proxies,
                timeout=self.timeout,
                headers=self._get_headers()
            )
            if response.status_code == 200:
                data = response.json()
                print("[+] Tor connection successful:", data)
                return data.get('IsTor', False)
            return False
        except Exception as e:
            print(f"[-] Tor connection check failed: {e}")
            return False

    def get_session(self) -> requests.Session:
        session = requests.Session()
        session.proxies.update(self.proxies)
        session.headers.update(self._get_headers())
        # Robust retry strategy for onion reliability
        retry = Retry(
            total=3,
            read=3,
            connect=3,
            backoff_factor=0.8,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"]
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        # Allow disabling SSL verification (common for onion HTTPS/self-signed)
        session.verify = self.verify_ssl
        return session

    def _get_headers(self) -> Dict[str, str]:
        return {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0',
            'Accept': 'application/json,text/html',
            'Connection': 'keep-alive'
        }

    def get_ip_info(self) -> Optional[Dict[str, Any]]:
        try:
            session = self.get_session()
            response = session.get('https://httpbin.org/ip', timeout=self.timeout)
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            print(f"[-] Failed to get IP info: {e}")
            return None

    def new_identity(self) -> bool:
        try:
            import stem.control
            from stem import Signal

            # Only attempt if control host is reachable (typically local)
            with stem.control.Controller.from_port(address=self.control_host, port=self.control_port) as controller:
                controller.authenticate()  # needs password if set in torrc (or cookie auth)
                controller.signal(Signal.NEWNYM)
                time.sleep(5)
                print("[+] Requested new Tor identity")
                return True
        except Exception as e:
            print(f"[-] Could not get new identity: {e}")
            return False

    def get_proxy_target(self) -> str:
        """Return the current proxy host:port string for diagnostics."""
        return f"{self.proxy_host}:{self.proxy_port}"


if __name__ == "__main__":
    tor = TorConnector()

    if tor.check_connection():
        print("[+] Connected via Tor")

        ip_info = tor.get_ip_info()
        if ip_info:
            print("[+] Current IP:", ip_info)

        tor.new_identity()
    else:
        print("[-] Not connected to Tor. Make sure Tor Browser or Tor Service is running.")
