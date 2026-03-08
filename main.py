#!/usr/bin/env python3
import sys
import argparse
import time
import json
import logging
import os

# --- UI scaling (Windows HiDPI) ---
os.environ.setdefault('QT_AUTO_SCREEN_SCALE_FACTOR', '0')
os.environ.setdefault('QT_SCALE_FACTOR', os.getenv('CHOMBEZA_QT_SCALE', '1'))
os.environ.setdefault('QT_FONT_DPI', '96')

from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import Qt
from ui.main_window import MainWindow
from core.scanner import Scanner
from core.report import ReportGenerator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(asctime)s - %(name)s: %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger("CHOMBEZA")

def main_gui():
    """Launch the GUI application"""
    try:
        # High DPI settings
        if hasattr(Qt, 'AA_DisableHighDpiScaling'):
            QApplication.setAttribute(Qt.AA_DisableHighDpiScaling, True)
        if hasattr(Qt, 'AA_UseHighDpiPixmaps'):
            QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
            
        app = QApplication(sys.argv)
        app.setApplicationName("CHOMBEZA Bug Bounty Pro")
        app.setApplicationVersion("2.0")
        
        window = MainWindow()
        window.show()
        
        exit_code = app.exec_()
        sys.exit(exit_code)
    except Exception as e:
        logger.critical(f"Failed to start GUI: {e}", exc_info=True)
        sys.exit(1)

def main_cli():
    """Command-line interface mode with ML support"""
    parser = argparse.ArgumentParser(
        description="CHOMBEZA - Advanced Bug Bounty Hunting Tool with ML False Positive Reduction",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py https://example.com --scan-type deep --threads 20
  python main.py https://example.com --blind-xss --output report
  python main.py https://example.com --scan-type quick --no-screenshot --ml-enabled
  python main.py https://example.com --load-state scans/scan_state.json --resume
        """
    )
    
    # Required arguments
    parser.add_argument("target", nargs="?", help="Target URL to scan (e.g., https://example.com)")
    
    # Scan options
    parser.add_argument("--scan-type", choices=["quick", "deep", "stealth", "aggressive"], 
                       default="quick", help="Scan intensity (default: quick)")
    parser.add_argument("--threads", type=int, default=10, 
                       help="Number of concurrent threads (default: 10)")
    parser.add_argument("--timeout", type=int, default=10, 
                       help="Request timeout in seconds (default: 10)")
    parser.add_argument("--delay", type=int, default=100, 
                       help="Delay between requests in ms (default: 100)")
    
    # Output options
    parser.add_argument("--output", help="Output report file prefix (without extension)")
    parser.add_argument("--format", choices=["html", "json", "csv", "pdf", "all"], 
                       default="all", help="Report format (default: all)")
    
    # Feature options
    parser.add_argument("--blind-xss", action="store_true", 
                       help="Start blind XSS callback server")
    parser.add_argument("--blind-xss-port", type=int, default=5000,
                       help="Port for blind XSS server (default: 5000)")
    parser.add_argument("--no-screenshot", action="store_true",
                       help="Disable vulnerability screenshots")
    parser.add_argument("--proxy", help="HTTP/SOCKS proxy (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--user-agent", help="Custom User-Agent string")
    
    # ML options
    parser.add_argument("--ml-enabled", action="store_true",
                       help="Enable ML false positive reduction")
    parser.add_argument("--ml-threshold", type=float, default=0.7,
                       help="ML confidence threshold (0.5-0.95, default: 0.7)")
    parser.add_argument("--train-ml", action="store_true",
                       help="Train ML model with existing feedback")
    
    # State management
    parser.add_argument("--save-state", help="Save scan state to file")
    parser.add_argument("--load-state", help="Load scan state from file")
    parser.add_argument("--resume", action="store_true",
                       help="Resume scan from loaded state")
    
    # Vulnerability selection
    parser.add_argument("--vuln-types", nargs="+", 
                       choices=["xss", "sqli", "ssti", "lfi", "rce", "xxe", "ssrf",
                               "jwt", "cors", "idor", "graphql", "all"],
                       default=["all"], help="Vulnerability types to test")
    
    # Config file
    parser.add_argument("--config", help="Path to custom config.json")
    
    args = parser.parse_args()

    # Check if we're just training ML or need target
    if args.train_ml:
        from core.ml_fp_reducer import get_ml_reducer
        ml_reducer = get_ml_reducer()
        if ml_reducer.train():
            print("[+] ML model trained successfully!")
            stats = ml_reducer.get_stats()
            print(f"[+] Training samples: {stats['training_samples']}")
            sys.exit(0)
        else:
            print("[-] Failed to train model. Need at least 10 samples.")
            sys.exit(1)

    # Target is required for scanning
    if not args.target and not args.load_state:
        parser.print_help()
        sys.exit(1)

    # Load configuration
    config_path = args.config if args.config else "config.json"
    config = {}
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load config: {e}")
    
    # Override config with CLI arguments
    config.update({
        "threads": args.threads,
        "timeout": args.timeout,
        "delay": args.delay,
        "screenshot": not args.no_screenshot,
        "proxy": args.proxy or config.get("proxy", ""),
        "user_agent": args.user_agent or config.get("user_agent", "CHOMBEZA/2.0"),
        "ml_enabled": args.ml_enabled,
        "ml_threshold": args.ml_threshold
    })

    # Initialize scanner
    try:
        scanner = Scanner(config_path if os.path.exists(config_path) else None)
        
        # Load state if requested
        if args.load_state:
            if scanner.load_state(args.load_state):
                print(f"[+] Loaded scan state from {args.load_state}")
                if args.resume:
                    print("[+] Resuming scan...")
                else:
                    print("[+] State loaded. Use --resume to continue scanning.")
            else:
                print(f"[-] Failed to load state from {args.load_state}")
                sys.exit(1)
        else:
            scanner.set_target(args.target)
            scanner.set_scan_type(args.scan_type)
            
            # Set vulnerability types
            if "all" not in args.vuln_types:
                features = {v: False for v in scanner.config.get("features", {})}
                for v in args.vuln_types:
                    features[v] = True
                scanner.config["features"] = features
        
    except Exception as e:
        logger.critical(f"Failed to initialize scanner: {e}")
        sys.exit(1)

    # Start blind XSS server if requested
    blind_xss_server = None
    if args.blind_xss:
        try:
            from core.blind_xss import BlindXSSServer
            blind_xss_server = BlindXSSServer(port=args.blind_xss_port)
            blind_xss_server.start()
            print(f"\n[+] Blind XSS server started on port {args.blind_xss_port}")
            print(f"[+] Callback URL: http://<your-ip>:{args.blind_xss_port}/xss")
            print("[+] Press Ctrl+C to stop server\n")
        except Exception as e:
            logger.error(f"Failed to start blind XSS server: {e}")

    # Save state file if requested
    if args.save_state:
        scanner.state_file = args.save_state

    # Start or resume scan
    if args.resume and args.load_state:
        print(f"[+] Resuming scan from state...")
        scanner.running = True
    else:
        print(f"\n[+] Starting {args.scan_type} scan on {args.target}")
        print(f"[+] Threads: {args.threads} | Timeout: {args.timeout}s | Delay: {args.delay}ms")
        if args.ml_enabled:
            print(f"[+] ML False Positive Reduction: Enabled (threshold: {args.ml_threshold})")
    
    print("[+] Scanning... (Ctrl+C to stop)\n")

    # Start scan
    try:
        if args.resume and args.load_state:
            # Resume from state
            scanner.start_scan()  # This will continue from where it left off
        else:
            scanner.start_scan()
        
        # Monitor progress
        total_tasks = scanner.total_tasks
        completed = 0
        last_progress = -1
        
        while scanner.running and (scanner.scan_queue.qsize() > 0 or scanner.completed_tasks < scanner.total_tasks):
            current_size = scanner.scan_queue.qsize()
            completed = scanner.completed_tasks
            progress = (completed / total_tasks * 100) if total_tasks > 0 else 0
            
            # Update progress bar
            if int(progress) != last_progress:
                bar_length = 50
                filled = int(bar_length * progress / 100)
                bar = '█' * filled + '░' * (bar_length - filled)
                
                # Add ML stats if enabled
                ml_info = ""
                if scanner.ml_reducer and scanner.ml_reducer.is_trained:
                    stats = scanner.ml_reducer.get_stats()
                    ml_info = f" | ML: {stats['training_samples']} samples"
                
                print(f"\r[{bar}] {progress:.1f}% | Found: {scanner.stats['total']} vulns{ml_info}", 
                      end="", flush=True)
                last_progress = int(progress)
            
            # Auto-save state periodically
            if args.save_state and scanner.completed_tasks % 50 == 0:
                scanner._save_state()
            
            time.sleep(0.5)
            
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        if args.save_state:
            scanner._save_state()
            print(f"[+] Scan state saved to {scanner.state_file}")
        
        scanner.stop_scan()
        
        # Show current results
        if scanner.stats['total'] > 0:
            print(f"\n[+] Partial results: {scanner.stats['total']} vulnerabilities found")
        else:
            print("\n[-] No vulnerabilities found before interruption")
            
    except Exception as e:
        logger.error(f"Scan failed: {e}", exc_info=True)
        scanner.stop_scan()
        sys.exit(1)

    # Generate report
    if scanner.stats['total'] > 0 or args.output:
        print("\n\n[+] Generating report...")
        try:
            reports = scanner.generate_report()
            
            # Show report locations
            for fmt, path in reports.items():
                if path and os.path.exists(path):
                    size = os.path.getsize(path) / 1024  # KB
                    print(f"[+] {fmt.upper()} report: {path} ({size:.1f} KB)")
            
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
    
    # Final summary
    print(f"\n{'='*60}")
    print(f"SCAN COMPLETE - {args.target if args.target else 'Resumed Scan'}")
    print(f"{'='*60}")
    print(f"Total vulnerabilities: {scanner.stats['total']}")
    print(f"  Critical: {scanner.stats.get('critical', 0)}")
    print(f"  High:     {scanner.stats.get('high', 0)}")
    print(f"  Medium:   {scanner.stats.get('medium', 0)}")
    print(f"  Low:      {scanner.stats.get('low', 0)}")
    print(f"  Info:     {scanner.stats.get('info', 0)}")
    print(f"Requests made: {scanner.stats.get('requests', 0)}")
    print(f"Cached responses: {scanner.stats.get('cached', 0)}")
    print(f"Duration: {scanner.get_duration()} seconds")
    
    if scanner.ml_reducer and scanner.ml_reducer.is_trained:
        ml_stats = scanner.ml_reducer.get_stats()
        print(f"\nML Statistics:")
        print(f"  Training samples: {ml_stats['training_samples']}")
        print(f"  Positive samples: {ml_stats.get('positive_samples', 0)}")
        print(f"  Negative samples: {ml_stats.get('negative_samples', 0)}")
    
    print(f"{'='*60}")

    # Stop blind XSS server
    if blind_xss_server:
        blind_xss_server.stop()
        print("[+] Blind XSS server stopped")

    sys.exit(0)

if __name__ == "__main__":
    # Determine mode based on arguments
    if len(sys.argv) > 1 and not sys.argv[1].startswith("-") and sys.argv[1] != "gui":
        main_cli()
    else:
        main_gui()