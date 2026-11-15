"""Traffic generators for the lab. They only target the local test server on 127.0.0.1."""

import http.client
import random
import socket
import ssl
import struct
import time

HOST, HOSTNAME = "127.0.0.1", "testsite.local"
PORT = 443  # run_lab.py sets this from --port


_CONTEXT = None


def _tls_context():
    global _CONTEXT
    if _CONTEXT is None:  # building a context loads the CA store (~40 ms), so build it once
        _CONTEXT = ssl.create_default_context()
        _CONTEXT.check_hostname = False
        _CONTEXT.verify_mode = ssl.CERT_NONE  # the lab certificate is self-signed
    return _CONTEXT


def _abort(sock):
    # Close with RST so thousands of test connections do not use up local ports in TIME_WAIT.
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    sock.close()


def _connection():
    return http.client.HTTPSConnection(HOST, PORT, context=_tls_context(), timeout=5)


def normal(seconds):
    """A few users browsing: short visits of 1 to 3 pages with pauses in between."""
    end, requests = time.time() + seconds, 0
    while time.time() < end:
        conn = _connection()
        for _ in range(random.randint(1, 3)):
            conn.request("GET", "/", headers={"Host": HOSTNAME})
            conn.getresponse().read()
            requests += 1
            time.sleep(random.uniform(0.2, 0.8))
        conn.close()
        time.sleep(random.uniform(0.5, 1.5))
    return {"requests": requests}


def handshake_flood(seconds):
    """A new TLS connection for every request."""
    end, connections = time.time() + seconds, 0
    while time.time() < end:
        conn = _connection()
        conn.request("GET", "/", headers={"Host": HOSTNAME, "Connection": "close"})
        conn.getresponse().read()
        conn.close()
        connections += 1
    return {"connections": connections}


def request_flood(seconds):
    """Many requests over one kept-alive TLS connection."""
    end, requests = time.time() + seconds, 0
    conn = _connection()
    while time.time() < end:
        conn.request("GET", "/", headers={"Host": HOSTNAME})
        conn.getresponse().read()
        requests += 1
    conn.close()
    return {"requests": requests}


def connection_flood(seconds, sources=1):
    """Open and drop TCP connections without TLS, from one or many loopback source addresses."""
    end, connections = time.time() + seconds, 0
    while time.time() < end:
        sock = socket.socket()
        if sources > 1:
            sock.bind((f"127.0.0.{2 + connections % sources}", 0))
        try:
            sock.connect((HOST, PORT))
        except OSError:
            pass
        _abort(sock)
        connections += 1
    return {"connections": connections, "sources": sources}


def distributed_flood(seconds):
    return connection_flood(seconds, sources=100)


def upload_flood(seconds, size=2_000_000):
    """Large POST bodies over one kept-alive TLS connection."""
    end, sent = time.time() + seconds, 0
    body = b"x" * size
    conn = _connection()
    while time.time() < end:
        conn.request("POST", "/upload", body=body, headers={"Host": HOSTNAME, "Content-Type": "application/octet-stream"})
        conn.getresponse().read()
        sent += size
    conn.close()
    return {"megabytes_sent": round(sent / 1e6, 1)}
