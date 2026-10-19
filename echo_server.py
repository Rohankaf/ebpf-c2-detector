import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 9000))
s.listen()
print("server on 127.0.0.1:9000", flush=True)
while True:
    conn, _ = s.accept()
    conn.sendall(b"ok")
    conn.close()
