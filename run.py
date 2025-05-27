import argparse
from kasau_xss_tester.core import KasauXSSTester
from kasau_xss_tester.gui import KasauXSSTesterGUI
import tkinter as tk
import json

def main():
    parser = argparse.ArgumentParser(description="Kasau XSS Advanced Tester")
    parser.add_argument('--url', help="Target URL to test")
    parser.add_argument('--params', help="Parameters to test (comma-separated)")
    parser.add_argument('--payloads', help="Payloads file (one per line)")
    parser.add_argument('--output', help="Output file for results")
    parser.add_argument('--threads', type=int, default=10, help="Number of threads")
    parser.add_argument('--timeout', type=int, default=15, help="Request timeout in seconds")
    parser.add_argument('--gui', action='store_true', help="Launch GUI interface")
    
    args = parser.parse_args()
    
    if args.gui:
        root = tk.Tk()
        app = KasauXSSTesterGUI(root)
        root.mainloop()
    elif args.url and args.params:
        # CLI mode
        params = [p.strip() for p in args.params.split(",") if p.strip()]
        
        payloads = None
        if args.payloads:
            with open(args.payloads) as f:
                payloads = [line.strip() for line in f if line.strip()]
                
        tester = KasauXSSTester(
            url=args.url,
            params=params,
            payloads=payloads,
            thread_count=args.threads,
            timeout=args.timeout
        )
        
        print("[*] Starting XSS test...")
        tester.run()
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write(tester.generate_report('json' if args.output.endswith('.json') else 'text'))
            print(f"[+] Results saved to {args.output}")
        else:
            print(tester.generate_report())
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
