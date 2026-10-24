"""Bounded TCP relay from the internal IdP bridge to one configured SMTP service.

TLS and SMTP authentication remain end-to-end between Keycloak and the provider.
No protocol content, SMTP credentials, or recipient addresses are logged.
"""
import argparse
import ipaddress
import selectors
import socket
import socketserver
import threading
from pathlib import Path
import p7

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--smtp',type=Path,required=True)
a=p.parse_args()
c=p7.smtp_config(a.smtp)
network=ipaddress.ip_network('10.203.77.0/28')
slots=threading.BoundedSemaphore(10)


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        if ipaddress.ip_address(self.client_address[0]) not in network or not slots.acquire(blocking=False):
            return
        try:
            with socket.create_connection((c['host'],int(c['port'])),timeout=10) as upstream:
                self.request.settimeout(10)
                upstream.settimeout(10)
                with selectors.DefaultSelector() as selector:
                    selector.register(self.request,selectors.EVENT_READ,upstream)
                    selector.register(upstream,selectors.EVENT_READ,self.request)
                    while True:
                        ready=selector.select(timeout=30)
                        if not ready:
                            return
                        for key,_ in ready:
                            data=key.fileobj.recv(65536)
                            if not data:
                                return
                            key.data.sendall(data)
        except OSError:
            # The caller receives a bounded connection failure; no blind retry.
            pass
        finally:
            slots.release()


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address=True
    daemon_threads=True
    request_queue_size=10


with Server(('10.203.77.1',1587),Handler) as server:
    print('SMTP relay ready on the internal bridge; upstream restricted to configured submission service',flush=True)
    server.serve_forever()
