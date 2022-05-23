#!/usr/bin/python3

from multiprocessing import Event
from bcc import BPF

prog = '''
#include <linux/sched.h>

// 自定义输出类型
struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
};

// 创建perf输出通道,名为event
BPF_PERF_OUTPUT(events);

int hello(struct pt_regs *ctx) {
    // 创建对象,借助辅助函数填充数据
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // 发送到通道中(给用户态空间)
    events.perf_submit(ctx, &data, sizeof(data));
    
    return 0;
}
'''

b = BPF(text=prog)
b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="hello")
# header
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))

start = 0
# 该函数将处理从事件流中读取事件
def print_event(cpu, data, size):
    global start 
    # 将事件作为 Python 对象获取，从 C 声明中自动生成。
    event = b["events"].event(data)
    if start == 0:
        start = event.ts
    time_s = (float(event.ts - start)) / 1000000000
    print("%-18.9f %-16s %-6d %s" % (time_s, event.comm, event.pid, "Hello, perf_output!"))

# 设置回调函数
b["events"].open_perf_buffer(print_event)
while 1:
  	# 阻塞等待事件
    b.perf_buffer_poll()