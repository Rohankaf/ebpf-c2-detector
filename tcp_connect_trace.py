#!/usr/bin/env python3
from bcc import BPF
import ctypes as ct
import socket, struct, json, datetime, sys

# ---- eBPF C program (runs INSIDE the kernel) ----
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

// ---- connect() attempt telemetry ----
struct connect_event_t {
    u32 pid;
    u32 saddr;
    u32 daddr;
    u16 dport;
    int retcode;
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(connect_events);
BPF_HASH(currsock, u32, struct sock *);

// ---- correlation map: socket pointer -> (pid, process name) ----
struct pid_info_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
};
BPF_HASH(sock_pid_map, u64, struct pid_info_t);

// ---- definitive success/failure telemetry ----
struct state_event_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    int oldstate;
    int newstate;
};
BPF_PERF_OUTPUT(state_events);

int trace_connect_entry(struct pt_regs *ctx, struct sock *sk) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    currsock.update(&pid, &sk);

    struct pid_info_t info = {};
    info.pid = pid;
    bpf_get_current_comm(&info.comm, sizeof(info.comm));
    u64 skaddr = (u64)sk;
    sock_pid_map.update(&skaddr, &info);

    return 0;
}

int trace_connect_return(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct sock **skpp = currsock.lookup(&pid);
    if (skpp == 0) {
        return 0;
    }

    struct sock *sk = *skpp;
    struct connect_event_t event = {};
    event.pid = pid;
    event.retcode = ret;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.saddr = sk->__sk_common.skc_rcv_saddr;
    event.daddr = sk->__sk_common.skc_daddr;
    event.dport = sk->__sk_common.skc_dport;

    connect_events.perf_submit(ctx, &event, sizeof(event));
    currsock.delete(&pid);
    return 0;
}

TRACEPOINT_PROBE(sock, inet_sock_set_state) {
    if (args->protocol != IPPROTO_TCP)
        return 0;

    u64 skaddr = (u64)args->skaddr;
    struct pid_info_t *infop = sock_pid_map.lookup(&skaddr);
    if (infop == 0)
        return 0;

    int is_success = (args->newstate == 1);   // TCP_ESTABLISHED
    int is_failure = (args->oldstate == 2 && args->newstate == 7);  // SYN_SENT -> CLOSE

    if (!is_success && !is_failure)
        return 0;

    struct state_event_t event = {};
    event.pid = infop->pid;
    __builtin_memcpy(&event.comm, infop->comm, sizeof(event.comm));
    event.oldstate = args->oldstate;
    event.newstate = args->newstate;

    if (args->family == 2) {  // AF_INET
        __builtin_memcpy(&event.saddr, args->saddr, 4);
        __builtin_memcpy(&event.daddr, args->daddr, 4);
    }
    event.sport = args->sport;
    event.dport = args->dport;

    state_events.perf_submit(args, &event, sizeof(event));

    if (args->newstate == 7) {
        sock_pid_map.delete(&skaddr);
    }
    return 0;
}
"""

# ---- Load into kernel and attach probes ----
b = BPF(text=bpf_text)
b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_entry")
b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_return")
# TRACEPOINT_PROBE auto-attaches itself, no manual attach call needed

print("Tracing TCP connect() calls + connection state changes... Ctrl+C to stop\n",
      file=sys.stderr)


class ConnectEvent(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint32),
        ("saddr", ct.c_uint32),
        ("daddr", ct.c_uint32),
        ("dport", ct.c_uint16),
        ("retcode", ct.c_int),
        ("comm", ct.c_char * 16),
    ]


class StateEvent(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint32),
        ("comm", ct.c_char * 16),
        ("saddr", ct.c_uint32),
        ("daddr", ct.c_uint32),
        ("sport", ct.c_uint16),
        ("dport", ct.c_uint16),
        ("oldstate", ct.c_int),
        ("newstate", ct.c_int),
    ]


def inet_ntoa(addr):
    return socket.inet_ntoa(struct.pack("I", addr))


# ---- Handles "connect" events: an attempt was INITIATED (may or may not
#      have ultimately succeeded — see handle_state_event for the outcome) ----
def handle_connect_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(ConnectEvent)).contents
    output = {
        "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
        "pid": event.pid,
        "process": event.comm.decode(errors="replace"),
        "source_ip": inet_ntoa(event.saddr),
        "destination_ip": inet_ntoa(event.daddr),
        "destination_port": socket.ntohs(event.dport),
        "protocol": "TCP",
        "event": "connect",
        "success": event.retcode == 0,
        "retcode": event.retcode,
    }
    print(json.dumps(output))


# ---- Handles "state_change" events: the DEFINITIVE outcome (established
#      or refused/failed) of a connection this tool already saw a
#      "connect" event for ----
def handle_state_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(StateEvent)).contents
    outcome = "established" if event.newstate == 1 else "refused_or_failed"
    output = {
        "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
        "pid": event.pid,
        "process": event.comm.decode(errors="replace"),
        "source_ip": inet_ntoa(event.saddr),
        "destination_ip": inet_ntoa(event.daddr),
        "source_port": event.sport,
        "destination_port": event.dport,
        "protocol": "TCP",
        "event": "state_change",
        "outcome": outcome,
        "success": event.newstate == 1,
    }
    print(json.dumps(output))


b["connect_events"].open_perf_buffer(handle_connect_event)
b["state_events"].open_perf_buffer(handle_state_event)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        break
