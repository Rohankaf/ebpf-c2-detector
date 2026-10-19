import socket, threading

IPS = ["127.0.0.1", "127.0.0.2", "127.0.0.3", "127.0.0.4", "127.0.0.5"]
PORTS = range(9000, 9010)

def serve(ip, port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((ip, port))
    except OSError as e:
        print(f"skip {ip}:{port} - {e}", flush=True)
        return
    s.listen()
    while True:
        conn, _ = s.accept()
        conn.close()

# multi-port targets, all on 127.0.0.1 (for scan test)
for port in PORTS:
    threading.Thread(target=serve, args=("127.0.0.1", port), daemon=True).start()

# multi-IP targets, all on port 9000 (for multi-dest test)
# 127.0.0.1:9000 already covered above, so skip duplicate
for ip in IPS[1:]:
    threading.Thread(target=serve, args=(ip, 9000), daemon=True).start()

print(f"listening: {list(PORTS)} on 127.0.0.1, and {IPS} on port 9000", flush=True)
threading.Event().wait()
