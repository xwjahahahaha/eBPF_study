#!/usr/bin/python3
from bcc import BPF

prog = '''
#include <uapi/linux/ptrace.h>

// 创建一个Hash映射数据结构
BPF_HASH(last);

int do_trace(struct pt_regs *ctx) {
    u64 ts, *tsp, delta, key = 0;
    
    // 读取当前hash中最新的数据
    tsp = last.lookup(&key);

    // 判断是否需要计算时间差
    if (tsp != NULL) {
        delta = bpf_ktime_get_ns() - *tsp;
        if (delta < 1000000000) {
            // 如果<1s,那么输出
            bpf_trace_printk("%d\\n", delta / 1000000);
        }
        // 删除掉原本的最新数据
        last.delete(&key);
    }
    
    // 更新hash,获取当前时间
    ts = bpf_ktime_get_ns();
    last.update(&key, &ts);
    return 0;
}
'''

b = BPF(text=prog)
b.attach_kprobe(event=b.get_syscall_fnname("sync"), fn_name="do_trace")
print("Tracing for quick sync's... Ctrl-C to end")
start = 0
while(1):
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    if start == 0 :
        start = ts
    ts = ts - start
    print("At time %.2f s: multiple syncs detected, last %s ms ago" % (ts, msg))