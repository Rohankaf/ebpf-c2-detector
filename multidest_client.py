import socket, time, argparse, ctypes

ctypes.CDLL("libc.so.6").prctl(15, b"test_multidest", 0, 0, 0)

p = argparse.ArgumentParser()
p.add_argument("--ips", nargs="+",
               default=["127.0.0.1", "127.0.0.2", "127.0.0.3", "127.0.0.4", "127.0.0.5"])
p.add_argument("--port", type=int, default=9000)
p.add_argument("--delay", type=float, default=0.5)
a = p.parse_args()

for ip in a.ips:
    try:
        with socket.create_connection((ip, a.port), timeout=0.5) as c:
            pass
        print(f"{ip}: connected", flush=True)
    except Exception as e:
        print(f"{ip}: {e}", flush=True)
    time.sleep(a.delay)
