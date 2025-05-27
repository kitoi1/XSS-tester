import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from .core import KasauXSSTester
import threading
import webbrowser
from pyfiglet import Figlet

class KasauXSSTesterGUI:
    def __init__(self, root):
        self.root = root
        self.tester = None
        self.setup_ui()
        self.setup_menu()
        
    def setup_ui(self):
        # Main window configuration
        self.root.title("Kasau XSS Advanced Tester")
        self.root.geometry("1000x800")
        self.root.minsize(800, 600)
        
        # Configure styles
        self.style = ttk.Style()
        self.style.configure('TFrame', background='#f0f0f0')
        self.style.configure('TLabel', background='#f0f0f0', font=('Helvetica', 10))
        self.style.configure('Title.TLabel', font=('Helvetica', 14, 'bold'))
        self.style.configure('TButton', font=('Helvetica', 10))
        self.style.configure('Red.TButton', foreground='red')
        
        # Header frame
        header_frame = ttk.Frame(self.root)
        header_frame.pack(fill='x', padx=10, pady=10)
        
        # ASCII art title
        try:
            figlet = Figlet(font='small')
            ascii_art = figlet.renderText("Kasau XSS")
            ascii_label = ttk.Label(header_frame, text=ascii_art, font=('Courier', 8))
            ascii_label.pack(side='left')
        except:
            title_label = ttk.Label(header_frame, text="Kasau XSS Advanced Tester", style='Title.TLabel')
            title_label.pack(side='left')
        
        # Control buttons
        control_frame = ttk.Frame(header_frame)
        control_frame.pack(side='right')
        
        self.start_btn = ttk.Button(control_frame, text="Start Test", command=self.start_test)
        self.start_btn.pack(side='left', padx=5)
        
        self.stop_btn = ttk.Button(control_frame, text="Stop", command=self.stop_test, state='disabled')
        self.stop_btn.pack(side='left', padx=5)
        
        # Main notebook
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=(0,10))
        
        # Configuration tab
        config_frame = ttk.Frame(self.notebook)
        self.notebook.add(config_frame, text="Configuration")
        
        # Target URL
        url_frame = ttk.Frame(config_frame)
        url_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Label(url_frame, text="Target URL:").pack(anchor='w')
        self.url_entry = ttk.Entry(url_frame, width=80)
        self.url_entry.pack(fill='x')
        self.url_entry.insert(0, "https://example.com/search")
        
        # Parameters
        params_frame = ttk.Frame(config_frame)
        params_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Label(params_frame, text="Parameters (comma-separated):").pack(anchor='w')
        self.params_entry = ttk.Entry(params_frame)
        self.params_entry.pack(fill='x')
        self.params_entry.insert(0, "q,search,query")
        
        # Payloads
        payloads_frame = ttk.Frame(config_frame)
        payloads_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        ttk.Label(payloads_frame, text="Payloads:").pack(anchor='w')
        
        self.payloads_text = scrolledtext.ScrolledText(payloads_frame, height=15, wrap=tk.WORD)
        self.payloads_text.pack(fill='both', expand=True)
        
        payload_buttons = ttk.Frame(payloads_frame)
        payload_buttons.pack(fill='x', pady=(5,0))
        
        ttk.Button(payload_buttons, text="Load Default", command=self.load_default_payloads).pack(side='left')
        ttk.Button(payload_buttons, text="Load From File", command=self.load_payloads_file).pack(side='left', padx=5)
        ttk.Button(payload_buttons, text="Clear", command=self.clear_payloads).pack(side='left')
        
        # Options
        options_frame = ttk.Frame(config_frame)
        options_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Label(options_frame, text="Threads:").pack(side='left')
        self.threads_spin = ttk.Spinbox(options_frame, from_=1, to=20, width=5)
        self.threads_spin.pack(side='left', padx=5)
        self.threads_spin.set(10)
        
        ttk.Label(options_frame, text="Timeout (s):").pack(side='left', padx=(10,0))
        self.timeout_spin = ttk.Spinbox(options_frame, from_=5, to=60, width=5)
        self.timeout_spin.pack(side='left', padx=5)
        self.timeout_spin.set(15)
        
        # Results tab
        results_frame = ttk.Frame(self.notebook)
        self.notebook.add(results_frame, text="Results")
        
        # Output console
        self.output_text = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD, state='disabled')
        self.output_text.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Progress bar
        self.progress_frame = ttk.Frame(self.root)
        self.progress_frame.pack(fill='x', padx=10, pady=(0,10))
        
        self.progress_var = tk.DoubleVar()
        self.progress = ttk.Progressbar(self.progress_frame, variable=self.progress_var, maximum=100)
        self.progress.pack(fill='x', side='left', expand=True)
        
        self.progress_label = ttk.Label(self.progress_frame, text="0%")
        self.progress_label.pack(side='left', padx=10)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        
        status_bar = ttk.Frame(self.root)
        status_bar.pack(fill='x', padx=10, pady=(0,10))
        
        ttk.Label(status_bar, textvariable=self.status_var).pack(side='left')
        
    def setup_menu(self):
        menubar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Save Results...", command=self.save_results)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Documentation", command=self.show_docs)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)
        
    def log(self, message, level="info"):
        self.output_text.config(state='normal')
        
        # Color coding based on level
        if level == "error":
            self.output_text.tag_config(level, foreground='red')
        elif level == "warning":
            self.output_text.tag_config(level, foreground='orange')
        elif level == "success":
            self.output_text.tag_config(level, foreground='green')
            
        self.output_text.insert('end', message + '\n', level)
        self.output_text.see('end')
        self.output_text.config(state='disabled')
        
    def update_progress(self, value):
        self.progress_var.set(value)
        self.progress_label.config(text=f"{value:.1f}%")
        
    def start_test(self):
        # Validate inputs
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a target URL")
            return
            
        params = [p.strip() for p in self.params_entry.get().split(",") if p.strip()]
        if not params:
            messagebox.showerror("Error", "Please enter at least one parameter")
            return
            
        # Get payloads
        payloads = self.payloads_text.get("1.0", tk.END).strip().split("\n")
        payloads = [p.strip() for p in payloads if p.strip()]
        
        if not payloads:
            if messagebox.askyesno("Confirm", "No custom payloads provided. Use default payloads?"):
                self.load_default_payloads()
                payloads = self.payloads_text.get("1.0", tk.END).strip().split("\n")
                payloads = [p.strip() for p in payloads if p.strip()]
            else:
                return
                
        # Create tester instance
        self.tester = KasauXSSTester(
            url=url,
            params=params,
            payloads=payloads,
            thread_count=int(self.threads_spin.get()),
            timeout=int(self.timeout_spin.get())
        )
        
        # Setup callbacks
        self.tester.register_callback('log', self.log)
        self.tester.register_callback('progress', self.update_progress)
        self.tester.register_callback('result', self.handle_vulnerability)
        
        # Clear previous results
        self.output_text.config(state='normal')
        self.output_text.delete('1.0', tk.END)
        self.output_text.config(state='disabled')
        
        # Update UI
        self.start_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        self.status_var.set("Testing in progress...")
        
        # Run in separate thread
        self.test_thread = threading.Thread(target=self.run_tests, daemon=True)
        self.test_thread.start()
        
    def run_tests(self):
        try:
            self.tester.run()
            self.log("Test completed successfully", "success")
        except Exception as e:
            self.log(f"Error during testing: {str(e)}", "error")
        finally:
            self.root.after(0, self.test_complete)
            
    def test_complete(self):
        self.start_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        self.status_var.set("Test completed")
        
    def stop_test(self):
        if self.tester:
            self.tester.stop()
            self.log("Test stopped by user", "warning")
            self.test_complete()
            
    def handle_vulnerability(self, vulnerability):
        self.log(f"VULNERABILITY FOUND in parameter: {vulnerability['parameter']}", "success")
        self.log(f"  Payload: {vulnerability['payload']}")
        self.log(f"  Context: {', '.join(vulnerability['contexts'])}")
        
    def load_default_payloads(self):
        try:
            with open('kasau_xss_tester/payloads/base_payloads.json') as f:
                payloads = json.load(f)
                self.payloads_text.delete('1.0', tk.END)
                self.payloads_text.insert('1.0', "\n".join(payloads))
        except Exception as e:
            messagebox.showerror("Error", f"Could not load default payloads: {str(e)}")
            
    def load_payloads_file(self):
        file_path = filedialog.askopenfilename(
            title="Select Payloads File",
            filetypes=(("Text files", "*.txt"), ("All files", "*.*"))
        )
        
        if file_path:
            try:
                with open(file_path) as f:
                    self.payloads_text.delete('1.0', tk.END)
                    self.payloads_text.insert('1.0', f.read())
            except Exception as e:
                messagebox.showerror("Error", f"Could not load file: {str(e)}")
                
    def clear_payloads(self):
        self.payloads_text.delete('1.0', tk.END)
        
    def save_results(self):
        if not self.tester or not self.tester.vulnerabilities:
            messagebox.showwarning("Warning", "No results to save")
            return
            
        file_path = filedialog.asksaveasfilename(
            title="Save Results",
            defaultextension=".txt",
            filetypes=(("Text files", "*.txt"), ("JSON files", "*.json"), ("All files", "*.*"))
        )
        
        if file_path:
            try:
                if file_path.endswith('.json'):
                    report = self.tester.generate_report('json')
                else:
                    report = self.tester.generate_report('text')
                    
                with open(file_path, 'w') as f:
                    f.write(report)
                    
                messagebox.showinfo("Success", "Results saved successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Could not save file: {str(e)}")
                
    def show_docs(self):
        webbrowser.open("https://github.com/kasau/kasau-xss-tester/docs")
        
    def show_about(self):
        about = """
Kasau XSS Advanced Tester v2.0

A professional XSS vulnerability scanner for authorized penetration testing.

Created by Kasau Security Team
https://kasau.dev

License: MIT
        """
        messagebox.showinfo("About", about.strip())
