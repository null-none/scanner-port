import socket
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


class PortScanner:
    def __init__(self, target_ip, timeout=1, max_threads=100):
        self.target_ip = target_ip
        self.timeout = timeout
        self.max_threads = max_threads
        self.open_ports = []
        self.scan_results = []

    def scan_port(self, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        port_result = {
            "port": port,
            "timestamp": datetime.now().isoformat(),
            "status": "closed",
        }
        try:
            result = sock.connect_ex((self.target_ip, port))
            if result == 0:
                port_result["status"] = "open"
                # Thread safety: Only append if not already present
                self.open_ports.append(port)
        finally:
            sock.close()
        return port_result

    def scan_ports(self, port_range=(1, 1024)):
        scan_start = datetime.now().isoformat()
        ports = list(range(port_range[0], port_range[1] + 1))
        results = []
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_port = {
                executor.submit(self.scan_port, port): port for port in ports
            }
            for future in as_completed(future_to_port):
                result = future.result()
                results.append(result)
                if result["status"] == "open":
                    self.open_ports.append(result["port"])
        scan_end = datetime.now().isoformat()
        # Sort by port number for clean output
        results.sort(key=lambda x: x["port"])
        self.scan_results = results
        return self.get_json_result(port_range, scan_start, scan_end)

    def get_json_result(self, port_range, scan_start, scan_end):
        result = {
            "target_ip": self.target_ip,
            "scan_start": scan_start,
            "scan_end": scan_end,
            "scanned_ports": [port for port in range(port_range[0], port_range[1] + 1)],
            "open_ports": sorted(set(self.open_ports)),
            "ports_detail": self.scan_results,
        }
        return result
