#!/usr/bin/python3
from bcc import BPF

prog = '''
#include <uapi/linux/ptrace.h>

// 创建一个array用于计数
BPF_ARRAY(counts, u64, 1);

int do_sync(struct pt_regs *ctx) {
    u64 *now = 0;
    int index = 0;
    // +1
    counts.increment(index);
    now = counts.lookup(&index);
    if (now != NULL) {
        bpf_trace_printk("%d\\n", *now);
    }
    return 0;
}
'''

b = BPF(text=prog)
b.attach_kprobe(event=b.get_syscall_fnname("sync"), fn_name="do_sync")
while(1):
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    print("At time %.2f s: count sync is %s\n" % (ts, msg))