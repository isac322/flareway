#!/usr/bin/env python3
"""
Flareway Documentation Portal Web Server.
Binds to 0.0.0.0:8080 so it is accessible from 10.222.0.7:8080 and 127.0.0.1:8080.
"""
import sys
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PORT = 8080
DOCS_DIR = Path(__file__).resolve().parent

class CustomHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(DOCS_DIR), **kwargs)

    def end_headers(self):
        self.send_header('Cache-Control', 'no-cache, must-revalidate')
        self.send_header('Access-Control-Allow-Origin', '*')
        super().end_headers()

    def log_message(self, format, *args):
        # Concise logging to stdout
        sys.stdout.write(f"[{self.log_date_time_string()}] {self.address_string()} {format % args}\n")
        sys.stdout.flush()

if __name__ == '__main__':
    server = ThreadingHTTPServer(('0.0.0.0', PORT), CustomHandler)
    print(f"Flareway Web Portal running on:")
    print(f"  - http://10.222.0.7:{PORT}/")
    print(f"  - http://127.0.0.1:{PORT}/")
    print(f"Serving directory: {DOCS_DIR}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server.")
        server.shutdown()
        server.server_close()
