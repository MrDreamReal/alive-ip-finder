#!/usr/bin/env python3
"""
Advanced Red Team IP Scanner
Author: Security Professional
Description: Stealthy IP range scanner with evasion techniques
"""

import argparse
import asyncio
import ipaddress
import random
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
import os
from datetime import datetime

class StealthIPScanner:
    def __init__(self, max_workers=50, timeout=2, jitter=True, verbose=False):
        self.max_workers = max_workers
        self.timeout = timeout
        self.jitter = jitter
        self.verbose = verbose
        self.results = []
        self.scanned_count = 0
        self.live_count = 0
        
    def print_status(self, message):
        """Print status messages with timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] {message}")
        
    def random_delay(self):
        """Add random delay to avoid pattern detection"""
        if self.jitter:
            time.sleep(random.uniform(0.1, 0.5))
            
    def resolve_hostname(self, ip):
        """Attempt reverse DNS lookup for additional intelligence"""
        try:
            hostname = socket.gethostbyaddr(str(ip))[0]
            return hostname
        except:
            return "N/A"
    
    def custom_connect_scan(self, ip, port=80):
        """
        Custom TCP connect scan with evasion techniques
        Uses common ports to avoid suspicion
        """
        common_ports = [80, 443, 22, 53, 8080, 8000, 8443]
        target_port = random.choice(common_ports)
        
        try:
            # Create socket with timeout
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Attempt connection
            result = sock.connect_ex((str(ip), target_port))
            sock.close()
            
            if result == 0:
                return True, target_port
        except:
            pass
            
        return False, None
    
    def icmp_ping_scan(self, ip):
        """ICMP ping scan for host discovery"""
        try:
            # Use system ping command for better OS integration
            if os.name == 'nt':  # Windows
                response = os.system(f"ping -n 1 -w {self.timeout*1000} {ip} >nul 2>&1")
            else:  # Linux/Unix
                response = os.system(f"ping -c 1 -W {self.timeout} {ip} > /dev/null 2>&1")
            
            return response == 0
        except:
            return False
    
    def async_port_scan(self, ip, ports=[80, 443, 22]):
        """Asynchronous port scanning for multiple ports"""
        async def check_port(ip, port, timeout):
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(str(ip), port),
                    timeout=timeout
                )
                writer.close()
                await writer.wait_closed()
                return port, True
            except:
                return port, False
        
        async def scan_ports():
            tasks = [check_port(ip, port, self.timeout) for port in ports]
            results = await asyncio.gather(*tasks)
            return any(result[1] for result in results)
        
        try:
            return asyncio.run(scan_ports())
        except:
            return False
    
    def scan_single_ip(self, ip):
        """Comprehensive scan for a single IP using multiple techniques"""
        self.scanned_count += 1
        
        # Random delay between scans
        self.random_delay()
        
        # Method 1: ICMP Ping
        if self.icmp_ping_scan(ip):
            if self.verbose:
                self.print_status(f"LIVE (ICMP): {ip}")
            return str(ip), "ICMP"
        
        # Method 2: TCP Connect Scan
        tcp_result, port = self.custom_connect_scan(ip)
        if tcp_result:
            if self.verbose:
                self.print_status(f"LIVE (TCP/{port}): {ip}")
            return str(ip), f"TCP/{port}"
        
        # Method 3: Async Multi-port Scan
        if self.async_port_scan(ip):
            if self.verbose:
                self.print_status(f"LIVE (Multiple Ports): {ip}")
            return str(ip), "Multiple Ports"
            
        if self.verbose and self.scanned_count % 100 == 0:
            self.print_status(f"Scanned {self.scanned_count} IPs, found {self.live_count} live hosts")
            
        return None, None
    
    def generate_ips_from_range(self, ip_range):
        """Generate all IP addresses from a CIDR range"""
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
            return [ip for ip in network.hosts()]  # Exclude network and broadcast
        except ValueError as e:
            self.print_status(f"Error parsing range {ip_range}: {e}")
            return []
    
    def scan_ranges(self, ip_ranges):
        """Scan multiple IP ranges using thread pool"""
        all_ips = []
        
        # Generate all IPs from all ranges
        self.print_status("Generating IP addresses from ranges...")
        for ip_range in ip_ranges:
            ips = self.generate_ips_from_range(ip_range)
            all_ips.extend(ips)
            self.print_status(f"Range {ip_range}: {len(ips)} IPs")
        
        self.print_status(f"Total IPs to scan: {len(all_ips)}")
        
        # Shuffle IPs to avoid sequential scanning pattern
        random.shuffle(all_ips)
        
        # Scan using thread pool
        self.print_status("Starting comprehensive scan...")
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_ip = {
                executor.submit(self.scan_single_ip, ip): ip 
                for ip in all_ips
            }
            
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    result, method = future.result()
                    if result:
                        self.live_count += 1
                        self.results.append((result, method))
                        self.print_status(f"Found live host: {result} via {method}")
                except Exception as e:
                    if self.verbose:
                        self.print_status(f"Error scanning {ip}: {e}")
        
        end_time = time.time()
        self.print_status(f"Scan completed in {end_time - start_time:.2f} seconds")
        self.print_status(f"Total scanned: {self.scanned_count}, Live hosts: {self.live_count}")

def load_ip_ranges(filename):
    """Load IP ranges from file"""
    try:
        with open(filename, 'r') as f:
            ranges = [line.strip() for line in f if line.strip()]
        return ranges
    except FileNotFoundError:
        print(f"Error: File {filename} not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file: {e}")
        sys.exit(1)

def save_results(results, output_file):
    """Save results to output file"""
    try:
        with open(output_file, 'w') as f:
            for ip, method in results:
                f.write(f"{ip}\n")
        print(f"Results saved to {output_file}")
    except Exception as e:
        print(f"Error saving results: {e}")

def print_banner():
    """Print tool banner"""
    banner = """
╔══════════════════════════════════════════════════════════════╗
║                 Advanced Red Team IP Scanner                ║
║                      Stealth Host Discovery                 ║
╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(
        description="Advanced Red Team IP Scanner - Stealth Host Discovery",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument("-f", "--file", required=True, help="Input file with IP ranges (CIDR format)")
    parser.add_argument("-o", "--output", required=True, help="Output file for live IPs")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Maximum threads (default: 50)")
    parser.add_argument("-x", "--timeout", type=float, default=2, help="Timeout in seconds (default: 2)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--no-jitter", action="store_true", help="Disable random delays")
    
    args = parser.parse_args()
    
    # Validate input file exists
    if not os.path.exists(args.file):
        print(f"Error: Input file {args.file} does not exist")
        sys.exit(1)
    
    # Initialize scanner
    scanner = StealthIPScanner(
        max_workers=args.threads,
        timeout=args.timeout,
        jitter=not args.no_jitter,
        verbose=args.verbose
    )
    
    # Load IP ranges
    ip_ranges = load_ip_ranges(args.file)
    print(f"Loaded {len(ip_ranges)} IP ranges from {args.file}")
    
    # Start scanning
    scanner.scan_ranges(ip_ranges)
    
    # Save results
    save_results(scanner.results, args.output)
    
    # Print summary
    print("\n" + "="*50)
    print("SCAN SUMMARY")
    print("="*50)
    print(f"Total IP Ranges: {len(ip_ranges)}")
    print(f"Total IPs Scanned: {scanner.scanned_count}")
    print(f"Live Hosts Found: {scanner.live_count}")
    print(f"Success Rate: {(scanner.live_count/scanner.scanned_count*100):.2f}%" if scanner.scanned_count > 0 else "0%")
    print(f"Output File: {args.output}")
    print("="*50)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
        sys.exit(1)