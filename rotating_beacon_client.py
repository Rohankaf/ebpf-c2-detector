import socket, time, argparse, ctypes, itertools, random

ctypes.CDLL("libc.so.6").prctl(15, b"test_rot_beacon", 0, 0, 0)

p = argparse.ArgumentParser()
p.add_argument("--interval", type=float, default=5)
p.add_argument("--jitter", type=float, default=0.1)
p.add_argument("--count", type=int, default=15)
p.add_argument("--ips", nargs="+",
               default=["127.0.0.1", "127.0.0.2", "127.0.0.3"])
p.add_argument("--port", type=int, default=9000)
a = p.parse_args()

ip_cycle = itertools.cycle(a.ips)  # rotate through destinations in order

for i in range(a.count):
    ip = next(ip_cycle)
    try:
        with socket.create_connection((ip, a.port), timeout=1) as c:
            pass
        print(f"beat {i+1}: connected to {ip}", flush=True)
    except Exception as e:
        print(f"beat {i+1}: {ip} - {e}", flush=True)

    wait = a.interval * (1 + random.uniform(-a.jitter, a.jitter))
    time.sleep(wait)
