#!/usr/bin/python3
from __future__ import print_function
from bcc import BPF
from bcc.utils import printb

REQ_WRITE = 1       # from include/linux/blk_types.h

# load BPF program
b = BPF(text='''
#include <uapi/linux/ptrace.h>
#include <linux/blk-mq.h>

struct data_t {
    u64 len;            // 大小
    char rwbs[8];       // 类型
    u64 ts;              // 时间戳
};

BPF_HASH(start, u64, struct data_t);

TRACEPOINT_PROBE(block, block_rq_issue) {
    u64 key = 0;
    struct data_t data = {};
    data.ts = bpf_ktime_get_ns();
    // args from /sys/kernel/debug/tracing/events/block/block_rq_issue/format
    bpf_probe_read(&data.rwbs, sizeof(data.rwbs), (void *)args->rwbs);
    data.len = args->bytes;
    // 更新存储
    start.update(&key, &data);
    return 0;
}

TRACEPOINT_PROBE(block, block_rq_complete) {
    u64 delta, key = 0;
    struct data_t* datap;
    datap = start.lookup(&key);
    if (datap != NULL) {
        // 计算时间差
        delta = bpf_ktime_get_ns() - datap->ts;
        bpf_trace_printk("%d %x %d\\n", datap->len, datap->rwbs, delta / 1000);
        start.delete(&key);
    }
    return 0;
}
''')

# header
print("%-18s %-2s %-7s %8s" % ("TIME(s)", "T", "BYTES", "LAT(ms)"))

# format output
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        (bytes_s, bflags_s, us_s) = msg.split()

        if int(bflags_s, 16) & REQ_WRITE:
            type_s = b"W"
        elif bytes_s == "0":    # see blk_fill_rwbs() for logic
            type_s = b"M"
        else:
            type_s = b"R"
        ms = float(int(us_s, 10)) / 1000
        printb(b"%-18.9f %-2s %-7s %8.2f" % (ts, type_s, bytes_s, ms))
    except KeyboardInterrupt:
        exit()