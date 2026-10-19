import socket, threading

IPS = ["127.0.0.1", "127.0.0.2", "127.0.0.3", "127.0.0.4", "127.0.0.5"]
PORT = 9000

def serve(ip):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ip, PORT))
    s.listen()
    while True:
        conn, _ = s.accept()
        conn.close()

for ip in IPS:
    threading.Thread(target=serve, args=(ip,), daemon=True).start()

print(f"listening on {IPS} : {PORT}", flush=True)
threading.Event().wait()
