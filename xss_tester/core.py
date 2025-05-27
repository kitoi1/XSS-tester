
import requests
from requests.exceptions import RequestException, Timeout, ConnectionError
import threading
import time
import re
from urllib.parse import urljoin, urlparse
import json
from datetime import datetime
from bs4 import BeautifulSoup
import html2text
from colorama import Fore, Style
from .utils.helpers import validate_url, normalize_payload
from .utils.validator import is_xss_possible
from .payloads.context_specific import get_context_specific_payloads

class KasauXSSTester:
    def __init__(self, url, params=None, payloads=None, headers=None, 
                 output_file=None, thread_count=10, timeout=15):
        """
        Initialize the XSS tester with target configuration
        
        Args:
            url (str): Target URL to test
            params (list): List of parameters to test
            payloads (list): Custom payloads to use (optional)
            headers (dict): Custom headers to use (optional)
            output_file (str): File to save results (optional)
            thread_count (int): Number of concurrent threads
            timeout (int): Request timeout in seconds
        """
        self.url = validate_url(url)
        self.params = params or []
        self.payloads = payloads or self._load_default_payloads()
        self.headers = headers or self._default_headers()
        self.output_file = output_file
        self.thread_count = thread_count
        self.timeout = timeout
        self.vulnerabilities = []
        self.lock = threading.Lock()
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self.total_tests = 0
        self.completed_tests = 0
        self.stop_flag = False
        self.callbacks = {
            'progress': None,
            'log': None,
            'result': None
        }

    def _default_headers(self):
        """Return default request headers"""
        return {
            "User-Agent": "KasauXSSAdvancedTester/2.0 (+https://kasau.dev)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }

    def _load_default_payloads(self):
        """Load payloads from JSON file and context-specific generators"""
        try:
            with open('kasau_xss_tester/payloads/base_payloads.json') as f:
                payloads = json.load(f)
        except Exception:
            payloads = self._fallback_payloads()
        
        # Add context-specific payloads
        payloads.extend(get_context_specific_payloads())
        return payloads

    def _fallback_payloads(self):
        """Fallback payloads if JSON file can't be loaded"""
        return [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "'\"><script>alert('XSS')</script>"
        ]

    def register_callback(self, callback_type, function):
        """Register a callback function for events"""
        if callback_type in self.callbacks:
            self.callbacks[callback_type] = function

    def _log(self, message, level="info"):
        """Internal logging with callback support"""
        if self.callbacks['log']:
            self.callbacks['log'](message, level)
        else:
            color = {
                "info": Fore.WHITE,
                "warning": Fore.YELLOW,
                "error": Fore.RED,
                "success": Fore.GREEN,
                "critical": Fore.RED + Style.BRIGHT
            }.get(level, Fore.WHITE)
            
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"{color}[{timestamp}] {message}{Style.RESET_ALL}")

    def _update_progress(self):
        """Update progress through callback"""
        if self.callbacks['progress']:
            progress = (self.completed_tests / self.total_tests) * 100
            self.callbacks['progress'](progress)

    def _add_vulnerability(self, vulnerability):
        """Add vulnerability finding with thread safety"""
        with self.lock:
            self.vulnerabilities.append(vulnerability)
            if self.callbacks['result']:
                self.callbacks['result'](vulnerability)

    def _check_reflection(self, payload, response):
        """Advanced reflection detection with context analysis"""
        # Normalize payload and response for comparison
        norm_payload = normalize_payload(payload)
        response_text = response.text.lower()
        
        # Check direct reflection
        if norm_payload.lower() in response_text:
            return True, "direct"
        
        # Check HTML entity encoding
        html_entities = payload.replace("<", "&lt;").replace(">", "&gt;")
        if html_entities.lower() in response_text:
            return True, "html_encoded"
            
        # Check partial reflection
        if any(part.lower() in response_text for part in payload.split() if len(part) > 3):
            return True, "partial"
            
        return False, "none"

    def _analyze_context(self, payload, response):
        """Analyze the context where payload appears"""
        soup = BeautifulSoup(response.text, 'html.parser')
        contexts = []
        
        # Check script tags
        scripts = soup.find_all('script', string=re.compile(re.escape(payload), re.I))
        if scripts:
            contexts.append("script_tag")
            
        # Check attributes
        for tag in soup.find_all(True):
            for attr, value in tag.attrs.items():
                if isinstance(value, str) and payload.lower() in value.lower():
                    contexts.append(f"{tag.name}.{attr}")
                    
        # Check HTML comments
        if f"<!--{payload}" in response.text:
            contexts.append("html_comment")
            
        return contexts if contexts else ["unknown"]

    def _test_parameter(self, param, payload):
        """Test a single parameter with a payload"""
        if self.stop_flag:
            return
            
        try:
            # Test GET request
            response = self.session.get(
                self.url,
                params={param: payload},
                timeout=self.timeout,
                allow_redirects=True
            )
            
            # Check reflection
            reflected, reflection_type = self._check_reflection(payload, response)
            if reflected:
                contexts = self._analyze_context(payload, response)
                
                # Verify XSS potential
                is_vulnerable = is_xss_possible(payload, response.text, contexts)
                
                if is_vulnerable:
                    vuln = {
                        'parameter': param,
                        'payload': payload,
                        'method': 'GET',
                        'reflection': reflection_type,
                        'contexts': contexts,
                        'status_code': response.status_code,
                        'response_length': len(response.text),
                        'content_type': response.headers.get('content-type', 'unknown')
                    }
                    
                    self._add_vulnerability(vuln)
                    self._log(f"Potential XSS found in {param} via {reflection_type} reflection", "success")
            
        except Exception as e:
            self._log(f"Error testing {param}: {str(e)[:100]}", "error")
        finally:
            with self.lock:
                self.completed_tests += 1
                self._update_progress()

    def run(self):
        """Execute the XSS tests"""
        self._log("Starting Kasau XSS Advanced Tester")
        self._log(f"Target URL: {self.url}")
        self._log(f"Parameters: {', '.join(self.params)}")
        self._log(f"Payloads: {len(self.payloads)}")
        
        self.total_tests = len(self.params) * len(self.payloads)
        self.completed_tests = 0
        self.vulnerabilities = []
        self.stop_flag = False
        
        # Create thread pool
        threads = []
        semaphore = threading.Semaphore(self.thread_count)
        
        def worker(param, payload):
            with semaphore:
                self._test_parameter(param, payload)
        
        # Start tests
        for param in self.params:
            for payload in self.payloads:
                if self.stop_flag:
                    break
                    
                t = threading.Thread(target=worker, args=(param, payload))
                t.start()
                threads.append(t)
                time.sleep(0.1)  # Rate limiting
        
        # Wait for completion
        for t in threads:
            t.join()
            
        return self.generate_report()

    def stop(self):
        """Stop the running test"""
        self.stop_flag = True
        self._log("Test stopped by user", "warning")

    def generate_report(self, format='text'):
        """Generate a test report"""
        report = {
            'metadata': {
                'url': self.url,
                'tested_at': datetime.now().isoformat(),
                'total_tests': self.total_tests,
                'vulnerabilities_found': len(self.vulnerabilities)
            },
            'findings': self.vulnerabilities
        }
        
        if format == 'json':
            return json.dumps(report, indent=2)
        elif format == 'html':
            return self._generate_html_report(report)
        else:
            return self._generate_text_report(report)

    def _generate_text_report(self, report):
        """Generate text format report"""
        text = f"Kasau XSS Test Report\n{'='*40}\n"
        text += f"URL: {report['metadata']['url']}\n"
        text += f"Tested at: {report['metadata']['tested_at']}\n"
        text += f"Tests performed: {report['metadata']['total_tests']}\n"
        text += f"Vulnerabilities found: {report['metadata']['vulnerabilities_found']}\n\n"
        
        if report['findings']:
            text += "VULNERABILITIES FOUND:\n"
            for i, vuln in enumerate(report['findings'], 1):
                text += f"\n{i}. Parameter: {vuln['parameter']}\n"
                text += f"   Payload: {vuln['payload'][:100]}{'...' if len(vuln['payload']) > 100 else ''}\n"
                text += f"   Method: {vuln['method']}\n"
                text += f"   Reflection: {vuln['reflection']}\n"
                text += f"   Contexts: {', '.join(vuln['contexts'])}\n"
        else:
            text += "\nNo vulnerabilities found.\n"
            
        return text

    def _generate_html_report(self, report):
        """Generate HTML format report"""
        # Implementation would use Jinja2 templating
        pass
