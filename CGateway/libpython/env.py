#!/usr/bin/env python3.7

from libncgim import NCGIMHTTPServer
from http.server import SimpleHTTPRequestHandler
import os

class MyHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
#         self.end_headers();
#         self.send_response(code, message)
        
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        for k, v in os.environb.items():
            self.wfile.write(k)
            self.wfile.write(b": ")
            self.wfile.write(v)
            self.wfile.write(b"\n")
        
        self.wfile.write(b"cwd: ")
        self.wfile.write(os.getcwd().encode())

if __name__ == "__main__":
    server = NCGIMHTTPServer(MyHandler)
    server.serve_forever()