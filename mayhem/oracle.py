#!/usr/bin/env python3
"""Behavioral oracle for nginx-module-vts, driven by mayhem/test.sh.

Starts the normal-flags nginx (built by mayhem/build.sh) with the module compiled in, sends exact raw
HTTP requests and asserts the counters, the control API and the prometheus output the module reports.
Prints one PASS/FAIL line per assertion and a final `CTRFCOUNTS <passed> <failed>` line.
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

nginx = sys.argv[1]
tmp = tempfile.mkdtemp(prefix="vts-test-")
results = []


def check(name, ok, detail=""):
    results.append(bool(ok))
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else "  -> " + str(detail)), flush=True)


def finish(proc=None):
    if proc is not None and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(10)
        except Exception:
            proc.kill()
    print("CTRFCOUNTS %d %d" % (results.count(True), results.count(False)))
    shutil.rmtree(tmp, ignore_errors=True)
    sys.exit(0)


BODY = b"upstream-body-0123456789"
up = socket.socket()
up.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
up.bind(("127.0.0.1", 0))
up.listen(16)
up_port = up.getsockname()[1]


def serve_upstream():
    while True:
        try:
            c, _ = up.accept()
        except OSError:
            return
        try:
            c.settimeout(5)
            c.recv(65536)
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n"
                      b"Connection: close\r\n\r\n" % len(BODY) + BODY)
        except Exception:
            pass
        c.close()


threading.Thread(target=serve_upstream, daemon=True).start()

s = socket.socket()
s.bind(("127.0.0.1", 0))
port = s.getsockname()[1]
s.close()

os.makedirs(tmp + "/html")
os.makedirs(tmp + "/logs")
open(tmp + "/html/index.html", "w").write("<html>vts-oracle</html>\n")
conf = f"""
daemon off;
master_process off;
pid {tmp}/nginx.pid;
error_log {tmp}/logs/error.log info;
events {{ worker_connections 64; }}
http {{
    access_log off;
    client_body_temp_path {tmp}/cb;
    proxy_temp_path {tmp}/pt;
    vhost_traffic_status_zone shared:vts:1m;
    vhost_traffic_status_filter_by_set_key $http_user_agent agent::$server_name;
    upstream backend {{ server 127.0.0.1:{up_port}; }}
    server {{
        listen 127.0.0.1:{port};
        server_name example.com;
        root {tmp}/html;
        location /proxy/ {{ proxy_pass http://backend/; }}
        location /status {{
            vhost_traffic_status_display;
            vhost_traffic_status_bypass_stats on;
        }}
    }}
}}
"""
open(tmp + "/nginx.conf", "w").write(conf)
proc = subprocess.Popen([nginx, "-p", tmp + "/", "-c", tmp + "/nginx.conf"],
                        stdout=subprocess.DEVNULL, stderr=open(tmp + "/logs/stderr", "w"))


def raw(req):
    sk = socket.create_connection(("127.0.0.1", port), timeout=5)
    sk.sendall(req)
    data = b""
    while True:
        d = sk.recv(65536)
        if not d:
            break
        data += d
    sk.close()
    return data


ready = False
for _ in range(100):
    if proc.poll() is not None:
        break
    try:
        socket.create_connection(("127.0.0.1", port), timeout=1).close()
        ready = True
        break
    except OSError:
        time.sleep(0.1)
check("nginx with the vts module starts and listens", ready, open(tmp + "/logs/stderr").read())
if not ready:
    finish(proc)


def get(path, ua="oracle/1.0"):
    req = (f"GET {path} HTTP/1.1\r\nHost: example.com\r\nUser-Agent: {ua}\r\n"
           f"Connection: close\r\n\r\n").encode()
    return len(req), raw(req)


def body(resp):
    return resp.split(b"\r\n\r\n", 1)[1]


def status(resp):
    return int(resp.split(b" ", 2)[1])


def jbody(resp):
    try:
        return json.loads(body(resp))
    except Exception as e:
        check("body is valid JSON", False, f"{e}: {body(resp)[:200]}")
        return {}


in_total = out_total = 0


def traffic(path, want, ua="oracle/1.0"):
    global in_total, out_total
    n, resp = get(path, ua)
    in_total += n
    out_total += len(resp)
    check(f"GET {path} -> {want}", status(resp) == want, resp[:80])
    return resp


for _ in range(3):
    traffic("/", 200)
traffic("/missing", 404)
for _ in range(2):
    r = traffic("/proxy/data", 200)
    check("proxied body is the upstream body", body(r) == BODY, body(r))
traffic("/", 200, ua="other-agent/2")

# /status has bypass_stats: the display requests below are not counted themselves.
_, resp = get("/status/format/json")
check("status json is served as application/json",
      status(resp) == 200 and b"application/json" in resp.split(b"\r\n\r\n")[0].lower(), resp[:150])
j = jbody(resp)
sz = j.get("serverZones", {}).get("example.com", {})
check("server zone requestCounter == 7", sz.get("requestCounter") == 7, sz)
check("server zone inBytes == bytes the client sent", sz.get("inBytes") == in_total, (sz.get("inBytes"), in_total))
check("server zone outBytes == bytes the client received", sz.get("outBytes") == out_total,
      (sz.get("outBytes"), out_total))
rs = sz.get("responses", {})
check("responses: 2xx == 6, 4xx == 1, 5xx == 0",
      rs.get("2xx") == 6 and rs.get("4xx") == 1 and rs.get("5xx") == 0, rs)
agents = j.get("filterZones", {}).get("agent::example.com", {})
check("filter zone: oracle/1.0 agent counted 6 requests",
      agents.get("oracle/1.0", {}).get("requestCounter") == 6, agents)
check("filter zone: other-agent/2 counted 1 request",
      agents.get("other-agent/2", {}).get("requestCounter") == 1, agents)
ups = j.get("upstreamZones", {}).get("backend", [])
check("upstream zone counted the two proxied requests",
      len(ups) == 1 and ups[0].get("requestCounter") == 2 and ups[0].get("responses", {}).get("2xx") == 2, ups)

_, resp = get("/status/format/prometheus")
text = body(resp).decode("latin1")
check('prometheus: requests_total{host="example.com",code="2xx"} == 6',
      'nginx_vts_server_requests_total{host="example.com",code="2xx"} 6\n' in text, text[:400])
check('prometheus: requests_total{host="example.com",code="4xx"} == 1',
      'nginx_vts_server_requests_total{host="example.com",code="4xx"} 1\n' in text, text[:400])
check("prometheus: bytes_total direction=in equals the bytes the client sent",
      'nginx_vts_server_bytes_total{host="example.com",direction="in"} %d\n' % in_total in text, text[:400])

_, resp = get("/status/format/html")
check("html status page renders the monitor",
      status(resp) == 200 and b"text/html" in resp and b"nginx vhost traffic status monitor" in resp, resp[:150])

c = jbody(get("/status/control?cmd=status&group=server&zone=example.com")[1])
check("control status returns the server zone with its counters",
      c.get("example.com", {}).get("requestCounter") == 7, str(c)[:200])
c = jbody(get("/status/control?cmd=delete&group=server&zone=example.com")[1])
check("control delete removes exactly one zone",
      c.get("processingReturn") is True and c.get("processingCounts") == 1, c)
j = jbody(get("/status/format/json")[1])
check("deleted server zone is gone from the status", "example.com" not in j.get("serverZones", {}),
      j.get("serverZones"))

traffic("/", 200)
j = jbody(get("/status/format/json")[1])
sz = j.get("serverZones", {}).get("example.com", {})
check("the zone restarts counting from 1 after the delete", sz.get("requestCounter") == 1, sz)

finish(proc)
