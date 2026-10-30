import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

PAGE = (b"<html><body><form method='POST' action='/login'>"
        b"User: <input name='username'><br>"
        b"Password: <input type='password' name='password'><br>"
        b"<button>Login</button></form></body></html>")

class Web(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Set-Cookie", "sessionid=abc123; Path=/; Secure; HttpOnly")
        self.end_headers()
        self.wfile.write(PAGE)
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.send_response(200); self.end_headers()
        self.wfile.write(b"received")
    def log_message(self, *a): pass

def run_ftp():
    auth = DummyAuthorizer()
    auth.add_user("testuser", "Test@1234", ".", perm="elr")
    FTPHandler.authorizer = auth
    FTPServer(("0.0.0.0", 21), FTPHandler).serve_forever()

threading.Thread(target=run_ftp, daemon=True).start()
print("HTTP :80 and FTP :21 running. Ctrl+C to stop.")
HTTPServer(("0.0.0.0", 80), Web).serve_forever()
