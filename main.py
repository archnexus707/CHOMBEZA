#!/usr/bin/env python3
import sys
import argparse
import time
import json
import logging
import os

# --- UI scaling (Windows HiDPI) ---
# Many Windows setups use 125–200% display scaling which can make PyQt UIs look huge.
# We keep the UI at a comfortable size by disabling auto-scaling and allowing an override.
os.environ.setdefault('QT_AUTO_SCREEN_SCALE_FACTOR', '0')
os.environ.setdefault('QT_SCALE_FACTOR', os.getenv('CHOMBEZA_QT_SCALE', '1'))
os.environ.setdefault('QT_FONT_DPI', '96')

from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import Qt  # FIXED: Missing import added
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
        # Must be set before QApplication is created (prevents Qt warning on Windows)
                # Prefer a smaller, consistent UI on Windows; can be overridden via CHOMBEZA_QT_SCALE env var.
        if hasattr(Qt, 'AA_DisableHighDpiScaling'):
            QApplication.setAttribute(Qt.AA_DisableHighDpiScaling, True)
        if hasattr(Qt, 'AA_UseHighDpiPixmaps'):
            QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
        app = QApplication(sys.argv)
        app.setApplicationName("CHOMBEZA Bug Bounty Pro")
        app.setApplicationVersion("2.0")
        
        
        window = MainWindow()
        window.show()
        
        # Clean exit
        exit_code = app.exec_()
        sys.exit(exit_code)
    except Exception as e:
        logger.critical(f"Failed to start GUI: {e}", exc_info=True)
        sys.exit(1)

def main_cli():
    """Command-line interface mode"""
    parser = argparse.ArgumentParser(
        description="CHOMBEZA - Advanced Bug Bounty Hunting Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py https://example.com --scan-type deep --threads 20
  python main.py https://example.com --blind-xss --output report
  python main.py https://example.com --scan-type quick --no-screenshot
        """
    )
    
    # Required arguments
    parser.add_argument("target", help="Target URL to scan (e.g., https://example.com)")
    
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
    
    # Vulnerability selection
    parser.add_argument("--vuln-types", nargs="+", 
                       choices=["xss", "sqli", "ssti", "lfi", "rce", "xxe", "ssrf",
                               "jwt", "cors", "idor", "graphql", "all"],
                       default=["all"], help="Vulnerability types to test")
    
    # Config file
    parser.add_argument("--config", help="Path to custom config.json")
    
    args = parser.parse_args()

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
        "user_agent": args.user_agent or config.get("user_agent", "CHOMBEZA/2.0")
    })

    # Initialize scanner
    try:
        scanner = Scanner(config_path if os.path.exists(config_path) else None)
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

    print(f"\n[+] Starting {args.scan_type} scan on {args.target}")
    print(f"[+] Threads: {args.threads} | Timeout: {args.timeout}s | Delay: {args.delay}ms")
    print("[+] Scanning... (Ctrl+C to stop)\n")

    # Start scan
    try:
        scanner.start_scan()
        
        # Monitor progress
        total_tasks = scanner.scan_queue.qsize()
        completed = 0
        last_progress = -1
        
        while scanner.running and scanner.scan_queue.qsize() > 0:
            current_size = scanner.scan_queue.qsize()
            completed = total_tasks - current_size if total_tasks > 0 else 0
            progress = (completed / total_tasks * 100) if total_tasks > 0 else 0
            
            # Update progress bar
            if int(progress) != last_progress:
                bar_length = 50
                filled = int(bar_length * progress / 100)
                bar = '█' * filled + '░' * (bar_length - filled)
                print(f"\r[{bar}] {progress:.1f}% | Found: {scanner.stats['total']} vulns", 
                      end="", flush=True)
                last_progress = int(progress)
            
            time.sleep(0.5)
            
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
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
    print(f"SCAN COMPLETE - {args.target}")
    print(f"{'='*60}")
    print(f"Total vulnerabilities: {scanner.stats['total']}")
    print(f"  Critical: {scanner.stats.get('critical', 0)}")
    print(f"  High:     {scanner.stats.get('high', 0)}")
    print(f"  Medium:   {scanner.stats.get('medium', 0)}")
    print(f"  Low:      {scanner.stats.get('low', 0)}")
    print(f"  Info:     {scanner.stats.get('info', 0)}")
    print(f"Duration: {scanner.get_duration()} seconds")
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