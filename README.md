# scanner-port
A fast, multithreaded TCP port scanner written in Python. Scan any range of ports on a given IP address, and get detailed results — including open ports, scan timestamps, and per-port status — in structured JSON format.

```bash
pip intstall scanner-port
```

```python
from scanner_port.utils import PortScanner

scanner = PortScanner("8.8.8.8", max_threads=100)
result = scanner.scan_ports((75, 85))
```

```python
import json
print(json.dumps(result, indent=2))

{
  "target_ip": "8.8.8.8",
  "scan_start": "2025-06-27T22:19:32.123456",
  "scan_end": "2025-06-27T22:19:33.789101",
  "scanned_ports": [75, 76, ..., 85],
  "open_ports": [80],
  "ports_detail": [
    {
      "port": 75,
      "timestamp": "2025-06-27T22:19:32.234567",
      "status": "closed"
    },
    {
      "port": 80,
      "timestamp": "2025-06-27T22:19:32.567890",
      "status": "open"
    }
    // ...
  ]
}
```

