import socket, threading

PORTS = range(9000, 9010)  # 10 ports: 9000-9009

def serve(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen()
    while True:
        conn, _ = s.accept()
        conn.close()  # just accept and close, no data needed for scan test

for p in PORTS:
    threading.Thread(target=serve, args=(p,), daemon=True).start()

print(f"listening on 127.0.0.1:{PORTS.start}-{PORTS.stop-1}", flush=True)
threading.Event().wait()  # block forever
