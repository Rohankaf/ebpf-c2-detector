import socket, time, argparse, ctypes

ctypes.CDLL("libc.so.6").prctl(15, b"test_scanner", 0, 0, 0)

p = argparse.ArgumentParser()
p.add_argument("--start-port", type=int, default=9000)
p.add_argument("--end-port", type=int, default=9009)
p.add_argument("--delay", type=float, default=0.1)  # gap between attempts
a = p.parse_args()

for port in range(a.start_port, a.end_port + 1):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5) as c:
            pass
        print(f"port {port}: open", flush=True)
    except Exception as e:
        print(f"port {port}: {e}", flush=True)
    time.sleep(a.delay)
