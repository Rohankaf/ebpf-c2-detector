import socket, time, random, argparse, ctypes

# process ka naam telemetry mein "test_beacon" dikhe (sirf labeling)
ctypes.CDLL("libc.so.6").prctl(15, b"test_beacon", 0, 0, 0)

p = argparse.ArgumentParser()
p.add_argument("--interval", type=float, default=5)
p.add_argument("--jitter", type=float, default=0.0)   # 0.2 = ±20%
p.add_argument("--random", action="store_true")      # 1-10s random
p.add_argument("--count", type=int, default=12)
a = p.parse_args()

for i in range(a.count):
    with socket.create_connection(("127.0.0.1", 9000)) as c:
        c.recv(2)
    if a.random:
        wait = random.uniform(1, 10)
    else:
        wait = a.interval * (1 + random.uniform(-a.jitter, a.jitter))
    print(f"beat {i+1}, next in {wait:.2f}s", flush=True)
    time.sleep(wait)
