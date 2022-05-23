#!/usr/bin/python3

from bcc import BPF

prog = '''
int hello(void *ctx)
{
    bpf_trace_printk("hello world\\n");
    return 0;
}
'''

b = BPF(text=prog)
# get_syscall_fnname: 根据输入的名称获取系统调用的全名, For example, given "clone" the helper would return "sys_clone" or "__x64_sys_clone".
b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="hello")

# header
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))

# 循环获取输出
while(1):
    try:
        # trace_fields 从trace_pipe中读取字段返回
        (task, pid, cpu, flags, timestamp, msg) =  b.trace_fields()
    except ValueError:
        continue
    print("%-18.9f %-16s %-6d %s" % (timestamp, task, pid, msg))

