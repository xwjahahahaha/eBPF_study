#!/usr/bin/python3
from __future__ import print_function
from bcc import BPF
from bcc.utils import printb

REQ_WRITE = 1       # from include/linux/blk_types.h

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>
#include <linux/blk-mq.h>

BPF_HASH(start, u32);

TRACEPOINT_PROBE(block, block_rq_issue) {
    // stash start timestamp by request ptr
    u64 ts = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();
    // args from /sys/kernel/debug/tracing/events/block/block_rq_issue/format
    start.update(&pid, &ts);
    return 0;
}

TRACEPOINT_PROBE(block, block_rq_complete) {
    u64 *tsp, delta;
    u32 pid = bpf_get_current_pid_tgid();
    tsp = start.lookup(&pid);
    if (tsp != 0) {
        delta = bpf_ktime_get_ns() - *tsp;
        bpf_trace_printk("%d\\n", delta / 1000);
        start.delete(&pid);
    }
    return 0;
}
""")

# header
print("%-18s %8s" % ("TIME(s)", "LAT(ms)"))

# format output
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        ms = float(int(msg, 10)) / 1000

        printb(b"%-18.9f %8.2f" % (ts, ms))
    except KeyboardInterrupt:
        exit()