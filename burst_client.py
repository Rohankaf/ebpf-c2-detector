import socket, argparse, ctypes

ctypes.CDLL("libc.so.6").prctl(15, b"test_burst", 0, 0, 0)

p = argparse.ArgumentParser()
p.add_argument("--count", type=int, default=20)
p.add_argument("--port", type=int, default=9000)
a = p.parse_args()

for i in range(a.count):
    with socket.create_connection(("127.0.0.1", a.port)) as c:
        pass  # no sleep at all — rapid-fire
print(f"fired {a.count} connections", flush=True)
